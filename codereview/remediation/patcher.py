"""Patcher utility for generating diffs, applying fixes safely with backups, and rolling back."""

import difflib
import os
import shutil
import time
from typing import Optional, Tuple
from codereview.models import FixProposal, FixStatus
from codereview.utils.security import validate_safe_path


def create_unified_diff(original_text: str, modified_text: str, filename: str) -> str:
    """Generates a clean unified diff string."""
    orig_lines = original_text.splitlines(keepends=True)
    mod_lines = modified_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    )
    return "".join(diff)


def apply_patch_to_string(
    file_content: str,
    original_snippet: str,
    replacement_snippet: str,
) -> Tuple[bool, str, str]:
    """Replaces original_snippet with replacement_snippet in file_content.

    Validates that original_snippet exists uniquely to prevent ambiguous or out-of-range patching.
    """
    if not original_snippet:
        return False, file_content, "Original snippet cannot be empty."

    occurrences = file_content.count(original_snippet)
    if occurrences == 0:
        # Try line-trimmed match
        trimmed_orig = original_snippet.strip()
        trimmed_count = file_content.count(trimmed_orig)
        if trimmed_count == 1:
            new_content = file_content.replace(trimmed_orig, replacement_snippet.strip(), 1)
            return True, new_content, ""
        elif trimmed_count > 1:
            return False, file_content, f"Ambiguous patch target: code snippet occurs {trimmed_count} times."
        else:
            return False, file_content, "Target code snippet not found in file content (stale patch)."

    if occurrences > 1:
        return False, file_content, f"Ambiguous patch target: code snippet occurs {occurrences} times."

    new_content = file_content.replace(original_snippet, replacement_snippet, 1)
    return True, new_content, ""


def create_backup(file_path: str, backup_dir: Optional[str] = None) -> str:
    """Creates a timestamped backup of the file before applying changes."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    dir_name = backup_dir or os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    timestamp = int(time.time())
    backup_path = os.path.join(dir_name, f"{base_name}.{timestamp}.bak")

    shutil.copy2(file_path, backup_path)
    return backup_path


def apply_fix_to_file(
    file_path: str,
    proposal: FixProposal,
    user_confirmed: bool = False,
    backup_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """Applies a verified fix proposal to disk after explicit user confirmation and backup."""
    if not user_confirmed:
        return False, "Explicit user confirmation is required before applying fix."

    if not os.path.isfile(file_path):
        return False, f"File not found: {file_path}"

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        current_content = f.read()

    # Apply patch to content
    success, new_content, err_msg = apply_patch_to_string(
        current_content,
        proposal.original_code,
        proposal.replacement_code,
    )

    if not success:
        return False, f"Patch application failed: {err_msg}"

    # Create backup
    try:
        backup_file = create_backup(file_path, backup_dir=backup_dir)
        proposal.backup_path = backup_file
    except Exception as e:
        return False, f"Failed to create backup: {e}"

    # Write patched content
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        proposal.status = FixStatus.APPLIED
        return True, "Fix applied successfully."
    except Exception as e:
        # Attempt recovery if write fails
        if proposal.backup_path and os.path.exists(proposal.backup_path):
            shutil.copy2(proposal.backup_path, file_path)
        return False, f"Failed writing patched file: {e}"


def rollback_fix(proposal: FixProposal) -> Tuple[bool, str]:
    """Rolls back an applied fix by restoring the backup file."""
    if not proposal.backup_path or not os.path.exists(proposal.backup_path):
        return False, "No backup file found to rollback."

    if not os.path.isfile(proposal.file_path):
        return False, f"Target file does not exist: {proposal.file_path}"

    try:
        shutil.copy2(proposal.backup_path, proposal.file_path)
        proposal.status = FixStatus.ROLLED_BACK
        return True, "Fix rolled back successfully."
    except Exception as e:
        return False, f"Rollback failed: {e}"
