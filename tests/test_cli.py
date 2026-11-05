from __future__ import annotations

import unittest

from main import build_parser


class CliTests(unittest.TestCase):
    def test_default_call_depth_is_seven(self) -> None:
        args = build_parser().parse_args(["app.apk"])

        self.assertEqual(args.max_call_depth, 7)


if __name__ == "__main__":
    unittest.main()
