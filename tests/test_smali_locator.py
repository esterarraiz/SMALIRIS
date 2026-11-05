from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcc_analyzer.smali_locator import SmaliLocator


class SmaliLocatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.decompiled_dir = Path(self.temporary_directory.name)

        self.main_class = (
            self.decompiled_dir
            / "smali"
            / "owasp"
            / "sat"
            / "agoat"
            / "AccessControl1ViewActivity.smali"
        )
        self.main_class.parent.mkdir(parents=True)
        self.main_class.write_text(
            ".class public Lowasp/sat/agoat/AccessControl1ViewActivity;\n",
            encoding="utf-8",
        )

        self.secondary_class = (
            self.decompiled_dir
            / "smali_classes2"
            / "owasp"
            / "sat"
            / "agoat"
            / "DownloadInvoiceService.smali"
        )
        self.secondary_class.parent.mkdir(parents=True)
        self.secondary_class.write_text(
            ".class public Lowasp/sat/agoat/DownloadInvoiceService;\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_locates_fully_qualified_class_in_main_dex(self) -> None:
        locator = SmaliLocator(self.decompiled_dir)

        result = locator.locate(
            "owasp.sat.agoat.AccessControl1ViewActivity"
        )

        self.assertEqual(result, self.main_class)

    def test_locates_class_in_secondary_dex(self) -> None:
        locator = SmaliLocator(self.decompiled_dir)

        result = locator.locate("owasp.sat.agoat.DownloadInvoiceService")

        self.assertEqual(result, self.secondary_class)

    def test_accepts_relative_name_with_package(self) -> None:
        locator = SmaliLocator(self.decompiled_dir)

        result = locator.locate(
            ".AccessControl1ViewActivity",
            package_name="owasp.sat.agoat",
        )

        self.assertEqual(result, self.main_class)

    def test_accepts_smali_descriptor(self) -> None:
        locator = SmaliLocator(self.decompiled_dir)

        result = locator.locate(
            "Lowasp/sat/agoat/DownloadInvoiceService;"
        )

        self.assertEqual(result, self.secondary_class)

    def test_returns_none_for_missing_class(self) -> None:
        locator = SmaliLocator(self.decompiled_dir)

        result = locator.locate("owasp.sat.agoat.MissingActivity")

        self.assertIsNone(result)

    def test_rejects_relative_name_without_package(self) -> None:
        locator = SmaliLocator(self.decompiled_dir)

        with self.assertRaises(ValueError):
            locator.locate(".AccessControl1ViewActivity")

    def test_smali_roots_are_sorted_by_dex_number(self) -> None:
        (self.decompiled_dir / "smali_classes10").mkdir()
        locator = SmaliLocator(self.decompiled_dir)

        names = [path.name for path in locator.smali_roots()]

        self.assertEqual(names, ["smali", "smali_classes2", "smali_classes10"])


if __name__ == "__main__":
    unittest.main()
