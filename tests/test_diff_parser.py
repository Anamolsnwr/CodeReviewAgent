"""Tests for diff parsing and changed-line mapping."""

import unittest
from codereview.github.diff_parser import parse_patch_changed_lines, is_line_in_diff


class TestDiffParser(unittest.TestCase):

    def test_parse_simple_patch(self):
        patch = (
            "@@ -10,6 +10,8 @@ def calculate(x, y):\n"
            "     print(x)\n"
            "+    if y == 0:\n"
            "+        raise ValueError('y cannot be 0')\n"
            "     return x / y\n"
        )
        changed_lines, line_to_pos = parse_patch_changed_lines(patch)

        self.assertIn(11, changed_lines)
        self.assertIn(12, changed_lines)
        self.assertEqual(len(changed_lines), 2)
        self.assertIn(11, line_to_pos)
        self.assertIn(12, line_to_pos)
        self.assertTrue(line_to_pos[11] < line_to_pos[12])

    def test_parse_multiple_hunks(self):
        patch = (
            "@@ -1,3 +1,4 @@\n"
            " import os\n"
            "+import sys\n"
            " \n"
            "@@ -20,3 +21,4 @@\n"
            " def hello():\n"
            "+    return 'world'\n"
        )
        changed_lines, line_to_pos = parse_patch_changed_lines(patch)
        self.assertEqual(changed_lines, [2, 22])
        self.assertIn(2, line_to_pos)
        self.assertIn(22, line_to_pos)

    def test_parse_empty_or_none_patch(self):
        changed_lines, line_to_pos = parse_patch_changed_lines("")
        self.assertEqual(changed_lines, [])
        self.assertEqual(line_to_pos, {})

        changed_lines, line_to_pos = parse_patch_changed_lines(None)
        self.assertEqual(changed_lines, [])
        self.assertEqual(line_to_pos, {})

    def test_is_line_in_diff(self):
        changed = [10, 11, 25]
        self.assertTrue(is_line_in_diff(10, changed))
        self.assertTrue(is_line_in_diff(12, changed, context_buffer=2))
        self.assertFalse(is_line_in_diff(50, changed, context_buffer=2))


if __name__ == "__main__":
    unittest.main()
