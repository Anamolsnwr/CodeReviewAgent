"""Diff parsing utilities for mapping changed lines and diff positions."""

import re
from typing import Dict, List, Set, Tuple


HUNK_HEADER_REGEX = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_patch_changed_lines(patch: str) -> Tuple[List[int], Dict[int, int]]:
    """Parses a unified diff patch string and returns:

    1. changed_lines: List of line numbers in the new/head file that were added or modified.
    2. line_to_diff_position: Mapping from head line number to diff position (1-based index in diff).
    """
    if not patch:
        return [], {}

    changed_lines: List[int] = []
    line_to_diff_position: Dict[int, int] = {}

    current_new_line = 0
    diff_position = 0

    for line in patch.splitlines():
        diff_position += 1

        if line.startswith("@@"):
            match = HUNK_HEADER_REGEX.match(line)
            if match:
                # Group 3 is the new file starting line
                current_new_line = int(match.group(3))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            changed_lines.append(current_new_line)
            line_to_diff_position[current_new_line] = diff_position
            current_new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            # Deletion does not advance head file line number
            pass
        else:
            # Context line
            line_to_diff_position[current_new_line] = diff_position
            current_new_line += 1

    return changed_lines, line_to_diff_position


def is_line_in_diff(line_number: int, changed_lines: List[int], context_buffer: int = 3) -> bool:
    """Checks whether a given line number falls within or directly adjacent to changed lines in the diff."""
    if not changed_lines:
        return False
    for cl in changed_lines:
        if abs(cl - line_number) <= context_buffer:
            return True
    return False
