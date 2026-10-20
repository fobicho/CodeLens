import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import extractor

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_MKDTEMP = tempfile.mkdtemp


class ExtractorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=str(REPOSITORY_ROOT))
        self.work_dir = Path(self.temp_dir.name)
        self.archive_path = self.work_dir / "sample.zip"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_zip(self, members):
        with zipfile.ZipFile(self.archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in members:
                archive.writestr(name, content)

    def extract_with_controlled_temp_dir(self, expected_error):
        extract_dir = self.work_dir / "extracted"
        with mock.patch.object(extractor.tempfile, "mkdtemp", return_value=str(extract_dir)):
            with self.assertRaises(expected_error):
                extractor.extract(str(self.archive_path), "sample.zip")
        self.assertFalse(extract_dir.exists(), "failed extraction should clean its temp directory")

    def extract_archive(self):
        with mock.patch.object(
                extractor.tempfile, "mkdtemp",
                side_effect=lambda prefix: ORIGINAL_MKDTEMP(prefix=prefix, dir=str(self.work_dir))):
            return extractor.extract(str(self.archive_path), "sample.zip")

    def test_extracts_source_files_and_skips_ignored_directories(self):
        self.write_zip([
            ("project/app.py", "print('hello')\n"),
            ("project/node_modules/pkg/index.js", "ignored()\n"),
        ])

        root = self.extract_archive()
        try:
            files, truncated = extractor.collect_sources(root)
            self.assertEqual(files, [("project/app.py", "print('hello')\n")])
            self.assertFalse(truncated)
        finally:
            extractor.cleanup(root)

    def test_rejects_path_traversal_and_cleans_temp_directory(self):
        self.write_zip([("../outside.py", "should not be written")])

        self.extract_with_controlled_temp_dir(ValueError)
        self.assertFalse((self.work_dir / "outside.py").exists())

    def test_rejects_expanded_size_over_limit_and_cleans_temp_directory(self):
        self.write_zip([("large.py", "12345")])

        with mock.patch.object(extractor, "MAX_EXTRACTED_BYTES", 4):
            self.extract_with_controlled_temp_dir(ValueError)

    def test_rejects_too_many_archive_members_and_cleans_temp_directory(self):
        self.write_zip([("one.py", "1"), ("two.py", "2")])

        with mock.patch.object(extractor, "MAX_ARCHIVE_MEMBERS", 1):
            self.extract_with_controlled_temp_dir(ValueError)

    def test_invalid_zip_cleans_temp_directory(self):
        self.archive_path.write_bytes(b"not a zip")

        self.extract_with_controlled_temp_dir(zipfile.BadZipFile)


if __name__ == "__main__":
    unittest.main()
