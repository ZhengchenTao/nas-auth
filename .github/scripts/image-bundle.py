#!/usr/bin/env python3
"""Transport an already-built image; never build source on the deployment host."""
import argparse
import gzip
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def checksum(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect(reference):
    return json.loads(docker("image", "inspect", reference))[0]


def archive_config(archive):
    # Read members without extracting paths. Docker save includes this compatibility
    # manifest with both the classic and containerd image stores.
    with tarfile.open(archive, "r:*") as tar:
        manifests = json.load(tar.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("Bundle must contain exactly one image")
        config = tar.extractfile(manifests[0]["Config"]).read()
        return "sha256:" + hashlib.sha256(config).hexdigest(), json.loads(config), manifests[0].get("RepoTags", [])


def saved_config(reference):
    with tempfile.TemporaryDirectory() as temporary:
        archive = pathlib.Path(temporary) / "image.tar"
        docker("save", "--output", str(archive), reference)
        digest, _, _ = archive_config(archive)
        return digest


def export(reference, output):
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", reference):
        raise ValueError("Export requires an immutable registry digest, not a tag")
    docker("pull", reference)
    image = inspect(reference)
    revision = image["Config"]["Labels"].get("org.opencontainers.image.revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Image has no full source revision")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "nas-auth.image.tar.gz"
    manifest = output / "manifest.json"
    if archive.exists() or manifest.exists():
        raise ValueError("Output already contains a bundle; use a new directory")
    transport_tag = "local/nas-auth-bundle:" + revision
    docker("tag", reference, transport_tag)
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        raw = pathlib.Path(temporary) / "image.tar"
        docker("save", "--output", str(raw), transport_tag)
        config_digest, _, tags = archive_config(raw)
        if tags != [transport_tag]:
            raise ValueError("Unexpected transport image tag")
        with open(raw, "rb") as source, gzip.open(archive, "wb", compresslevel=1) as target:
            shutil.copyfileobj(source, target)
    receipt = dict(schema=2, reference=reference, image_id=image["Id"], config_digest=config_digest, revision=revision,
                   archive=archive.name, archive_sha256=checksum(archive))
    manifest.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def verify(manifest):
    receipt = json.loads(manifest.read_text(encoding="utf-8"))
    if receipt.get("schema") != 2 or receipt.get("archive") != "nas-auth.image.tar.gz":
        raise ValueError("Unsupported bundle manifest")
    if not re.fullmatch(r"[0-9a-f]{40}", receipt.get("revision", "")):
        raise ValueError("Invalid source revision")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt.get("image_id", "")):
        raise ValueError("Invalid image ID")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt.get("config_digest", "")):
        raise ValueError("Invalid image configuration digest")
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", receipt.get("reference", "")):
        raise ValueError("Invalid registry digest")
    archive = manifest.parent / receipt["archive"]
    if checksum(archive) != receipt.get("archive_sha256"):
        raise ValueError("Archive checksum mismatch; refusing to load")
    digest, config, tags = archive_config(archive)
    if digest != receipt["config_digest"] or config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != receipt["revision"]:
        raise ValueError("Archived configuration does not match the manifest")
    if tags != ["local/nas-auth-bundle:" + receipt["revision"]]:
        raise ValueError("Archive contains an unexpected image tag")
    return receipt, archive


def load(manifest):
    receipt, archive = verify(manifest)
    docker("load", "--input", str(archive))
    transport_tag = "local/nas-auth-bundle:" + receipt["revision"]
    image = inspect(transport_tag)
    if image["Config"]["Labels"].get("org.opencontainers.image.revision") != receipt["revision"] or saved_config(transport_tag) != receipt["config_digest"]:
        raise ValueError("Loaded image does not match the release manifest")
    tag = "local/nas-auth:" + receipt["revision"]
    docker("tag", transport_tag, tag)
    return dict(receipt, loaded_image_id=image["Id"], deployment_image=tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    exporting = commands.add_parser("export")
    exporting.add_argument("--image", required=True)
    exporting.add_argument("--output", type=pathlib.Path, required=True)
    for command in ("verify", "import"):
        sub = commands.add_parser(command)
        sub.add_argument("manifest", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "export":
        result = export(args.image, args.output)
    elif args.command == "import":
        result = load(args.manifest)
    else:
        result, _ = verify(args.manifest)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
