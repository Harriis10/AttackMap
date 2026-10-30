"""Focused path/ZIP refusal checks. No package stages, builds or GUI are created."""
import hashlib
import io
import json
import stat
import unittest
import zipfile

import package_portable as portable


class PortableRefusalTests(unittest.TestCase):
    def archive(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("AttackMap-Windows/", b"")
            for name, content in entries:
                archive.writestr(name, content)
        output.seek(0)
        return output

    def expected(self, content=b"checked bytes"):
        return {"files": {"payload.bin": {"size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}}, "directories": []}

    def test_windows_ambiguous_paths_are_refused(self):
        for path in ("", "/root", "C:relative", "C:/absolute", "a\\b", "a//b", "a/../b", "./a", "x.",
                     " x", "x ", "con", "AUX.json", "folder/LPT1.dll", "COM¹", "file:stream", "x\x00y", "x?y"):
            with self.subTest(path=path), self.assertRaises(portable.PackageError):
                portable.safe_relative(path)
        for path in ("engine/_internal/python313.dll", "GraphExplorer.Web/vendor/file-2.0.js", "CTETE-ME.txt"):
            self.assertEqual(path, portable.safe_relative(path))

    def test_case_colliding_inventory_and_duplicate_json_are_refused(self):
        with self.assertRaises(portable.PackageError):
            portable.hashes({"a.dll": "a" * 64, "A.dll": "b" * 64})
        with self.assertRaises(portable.PackageError):
            json.loads('{"passed":false,"passed":true}', object_pairs_hook=portable.unique_object)

    def test_zip_reads_actual_member_bytes(self):
        observed = portable.zip_inventory(self.archive([("AttackMap-Windows/payload.bin", b"checked bytes")]), self.expected())
        self.assertEqual(1, observed["files_verified"])
        self.assertEqual(13, observed["bytes_verified"])

    def test_zip_equal_length_tamper_is_refused(self):
        with self.assertRaises(portable.PackageError):
            portable.zip_inventory(self.archive([("AttackMap-Windows/payload.bin", b"changed bytes")]), self.expected())

    def test_zip_traversal_and_external_members_are_refused(self):
        for name in ("AttackMap-Windows/../escaped", "outside/payload.bin", "AttackMap-Windows/C:stream", "AttackMap-Windows/a\\b"):
            with self.subTest(name=name), self.assertRaises(portable.PackageError):
                portable.zip_inventory(self.archive([(name, b"checked bytes")]), self.expected())

    def test_zip_missing_unexpected_and_case_colliding_members_are_refused(self):
        variants = [[], [("AttackMap-Windows/unexpected.bin", b"checked bytes")],
                    [("AttackMap-Windows/payload.bin", b"checked bytes"), ("AttackMap-Windows/PAYLOAD.bin", b"checked bytes")]]
        for entries in variants:
            with self.subTest(entries=entries), self.assertRaises(portable.PackageError):
                portable.zip_inventory(self.archive(entries), self.expected())

    def test_zip_symbolic_link_is_refused(self):
        item = zipfile.ZipInfo("AttackMap-Windows/payload.bin")
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(portable.PackageError):
            portable.zip_inventory(self.archive([(item, b"checked bytes")]), self.expected())


if __name__ == "__main__":
    unittest.main(verbosity=2)
