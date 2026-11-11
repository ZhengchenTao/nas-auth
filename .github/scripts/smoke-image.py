#!/usr/bin/env python3
"""Boot the identical runtime image with two isolated, synthetic deployment configurations."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def request(name, path):
    # Run inside the container: works with both local and remote Docker daemons,
    # without publishing ports, installing curl, or accessing a real identity provider.
    wire = f"GET {path} HTTP/1.1\r\nHost: auth.example.test\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n"
    return docker("exec", name, "bash", "-c", 'exec 3<>/dev/tcp/127.0.0.1/8080; printf "%s" "$1" >&3; cat <&3', "smoke", wire)


def run(image, team):
    name = "nas-auth-smoke-" + uuid.uuid4().hex[:12]
    mount = "/auth" if team else ""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        os.chmod(root, 0o755)
        (root / "resources.json").write_text(json.dumps([
            dict(aud="library", resource_url="https://library.example.test", display_name="Library", scopes=["openid", "profile"]),
            dict(aud="site", resource_url="https://apps.example.test/tools/", display_name="Tools", forward_auth={})]))
        (root / "clients.json").write_text(json.dumps([dict(client_id="library-client", client_name="Library",
            redirect_uris=["https://library.example.test/callback"], default_resource="https://library.example.test", token_endpoint_auth_method="none")]))
        for file in root.iterdir():
            os.chmod(file, 0o644)
        settings = {"Auth__Issuer": "https://auth.example.test" + mount, "Auth__PathBase": mount,
            "Auth__Database": "Data Source=/app/data/auth.db", "Auth__ResourcesPath": "/app/config/resources.json",
            "Auth__ClientsPresetPath": "/app/config/clients.json", "Auth__Admin__Username": "admin",
            "Auth__Admin__Password": "synthetic-smoke-password", "ExternalProviders__UseConfiguredProviders": "true"}
        if team:
            for key, value in {"Id": "badge", "DisplayName": "Badge", "Enabled": "true",
                "LoginUrl": "https://login.example.test/start", "ValidationUrl": "https://adapter.example.test/validate",
                "ValidationToken": "synthetic-smoke-token"}.items():
                settings["ExternalProviders__TicketProviders__0__" + key] = value
            settings["ExternalProfiles__Providers__badge__Fields__department__Label"] = "Department"
        env = [item for k, v in settings.items() for item in ("-e", k + "=" + v)]
        try:
            docker("create", "--name", name, *env, image)
            docker("cp", str(root) + "/.", name + ":/app/config")
            docker("start", name)
            for attempt in range(40):
                try:
                    if "200 OK" in request(name, "/healthz"):
                        break
                except subprocess.CalledProcessError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("Runtime did not become ready")
            discovery = request(name, mount + "/.well-known/openid-configuration")
            assert "200 OK" in discovery and '"issuer":"https://auth.example.test' + mount + '"' in discovery
            login = request(name, mount + "/login")
            assert "200 OK" in login and "action='" + mount + "/login'" in login
            assert "302 Found" in request(name, mount + "/admin/apps/diagnostics")
            if team:
                assert "404 Not Found" in request(name, "/login")
                assert "302 Found" in request(name, "/auth/external/badge/start")
            print(("team" if team else "household") + ": runtime smoke passed")
        finally:
            subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    for team in (False, True):
        run(sys.argv[1], team)
