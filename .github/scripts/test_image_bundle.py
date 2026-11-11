import importlib.util
import io
import json
import pathlib
import tempfile
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bundle", pathlib.Path(__file__).with_name("image-bundle.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def fixture(self, root):
        revision = "b" * 40
        archive = root / "nas-auth.image.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, value in {"manifest.json": [{"Config": "config.json", "RepoTags": ["local/nas-auth-bundle:" + revision]}],
                "config.json": {"config": {"Labels": {"org.opencontainers.image.revision": revision}}}}.items():
                data = json.dumps(value).encode()
                info = tarfile.TarInfo(name); info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        receipt = dict(schema=2, archive=archive.name, archive_sha256=bundle.checksum(archive),
            image_id="sha256:" + "a" * 64, revision=revision, config_digest=bundle.archive_config(archive)[0],
            reference="registry.example.test/auth@sha256:" + "c" * 64)
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps(receipt))
        return manifest, receipt

    def test_rejects_mutable_reference_before_docker(self):
        with patch.object(bundle, "docker") as docker:
            with self.assertRaises(ValueError):
                bundle.export("registry.example.test/auth:latest", pathlib.Path("unused"))
            docker.assert_not_called()

    def test_import_checks_archive_before_load_and_checks_revision_before_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest, receipt = self.fixture(root)
            archive = root / receipt["archive"]
            receipt["archive_sha256"] = "bad"
            manifest.write_text(json.dumps(receipt))
            with patch.object(bundle, "docker") as docker:
                with self.assertRaises(ValueError):
                    bundle.load(manifest)
                docker.assert_not_called()
            receipt["archive_sha256"] = bundle.checksum(archive)
            manifest.write_text(json.dumps(receipt))
            with patch.object(bundle, "docker") as docker, patch.object(bundle, "inspect", return_value={
                "Id": receipt["image_id"], "Config": {"Labels": {"org.opencontainers.image.revision": "d" * 40}}}):
                with self.assertRaises(ValueError):
                    bundle.load(manifest)
                self.assertEqual([call.args[0] for call in docker.call_args_list], ["load"])

    def test_import_accepts_different_engine_id_only_when_config_digest_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, receipt = self.fixture(pathlib.Path(directory))
            loaded_id = "sha256:" + "d" * 64
            with patch.object(bundle, "docker") as docker, patch.object(bundle, "inspect", return_value={
                "Id": loaded_id, "Config": {"Labels": {"org.opencontainers.image.revision": receipt["revision"]}}}), \
                patch.object(bundle, "saved_config", return_value=receipt["config_digest"]):
                self.assertEqual(bundle.load(manifest)["loaded_image_id"], loaded_id)
                self.assertEqual([call.args[0] for call in docker.call_args_list], ["load", "tag"])
            with patch.object(bundle, "docker") as docker, patch.object(bundle, "inspect", return_value={
                "Id": loaded_id, "Config": {"Labels": {"org.opencontainers.image.revision": receipt["revision"]}}}), \
                patch.object(bundle, "saved_config", return_value="sha256:" + "e" * 64):
                with self.assertRaises(ValueError):bundle.load(manifest)
                self.assertEqual([call.args[0] for call in docker.call_args_list], ["load"])

    def test_manifest_cannot_select_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps(dict(schema=2, archive="../outside.tar.gz")))
            with self.assertRaises(ValueError):
                bundle.verify(path)


if __name__ == "__main__":
    unittest.main()
