from __future__ import annotations

import unittest

from tcc_analyzer.report_schema import load_report_schema, validate_report


class ReportSchemaTests(unittest.TestCase):
    def test_published_schema_is_the_v2_contract(self) -> None:
        schema = load_report_schema()

        self.assertEqual(schema["properties"]["schema_version"]["const"], "2.0")
        self.assertIn("reproducibility", schema["required"])
        self.assertIn("ipc_transitions", schema["properties"]["data_flow_analysis"]["required"])

    def test_rejects_report_missing_required_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "campo obrigatório ausente"):
            validate_report({"schema_version": "2.0"})


if __name__ == "__main__":
    unittest.main()
