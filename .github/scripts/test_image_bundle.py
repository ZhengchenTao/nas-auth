import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bundle", pathlib.Path(__file__).with_name("image-bundle.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def test_rejects_mutable_reference_before_docker(self):
        with patch.object(bundle, "docker") as docker:
            with self.assertRaises(ValueError):
                bundle.export("registry.example.test/auth:latest", pathlib.Path("unused"))
            docker.assert_not_called()

    def test_import_checks_archive_before_load_and_checks_revision_before_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / "nas-auth.image.tar.gz"
            archive.write_bytes(b"synthetic archive")
            receipt = dict(schema=1, archive=archive.name, archive_sha256="bad",
                image_id="sha256:" + "a" * 64, revision="b" * 40,
                reference="registry.example.test/auth@sha256:" + "c" * 64)
            manifest = root / "manifest.json"
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

    def test_manifest_cannot_select_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps(dict(schema=1, archive="../outside.tar.gz")))
            with self.assertRaises(ValueError):
                bundle.verify(path)


if __name__ == "__main__":
    unittest.main()
