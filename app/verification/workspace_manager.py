"""
Isolated Workspace Manager for Safe Patch Application and Testing.
Ensures the active workspace baseline is preserved and never modified during evaluation.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import tempfile
from typing import List, Optional, Tuple

from app.core.errors import PatchIntegrityError


def apply_unified_diff(original_text: str, patch_text: str) -> str:
    """
    Apply a unified diff string to original text deterministically in pure Python.
    Handles standard unified diff format and AI-generated relaxed diffs without external dependencies.
    Preserves original context lines, blank lines, and whitespace indentation.
    """
    lines = original_text.splitlines(keepends=True)
    patch_lines = patch_text.splitlines(keepends=False)

    # Locate hunk headers
    hunk_indices = [idx for idx, l in enumerate(patch_lines) if l.startswith("@@")]
    if not hunk_indices:
        raise PatchIntegrityError("No diff hunks found in patch")

    out_lines = list(lines)

    for h_idx, hunk_pos in enumerate(hunk_indices):
        header = patch_lines[hunk_pos]
        next_hunk_pos = hunk_indices[h_idx + 1] if h_idx + 1 < len(hunk_indices) else len(patch_lines)
        raw_hunk = patch_lines[hunk_pos + 1 : next_hunk_pos]

        m = re.search(r"-(\d+)", header)
        hint_line = int(m.group(1)) if m else 1

        # Break hunk into operations:
        # Each item is ('context', text), ('delete', text), ('add', text)
        ops: List[Tuple[str, str]] = []
        for line in raw_hunk:
            if line.startswith("-"):
                ops.append(("delete", line[1:]))
            elif line.startswith("+"):
                ops.append(("add", line[1:]))
            elif line.startswith(" "):
                ops.append(("context", line[1:]))
            elif line == "":
                ops.append(("context", ""))

        if not ops:
            continue

        orig_seq = [text for op, text in ops if op in ("context", "delete")]
        if not orig_seq:
            # Pure addition hunk
            insert_idx = min(len(out_lines), max(0, hint_line - 1))
            added = [text + "\n" for op, text in ops if op == "add"]
            out_lines[insert_idx:insert_idx] = added
            continue

        def find_match():
            for strip_mode in (False, True):
                search_order = []
                hint_idx = max(0, min(len(out_lines) - 1, hint_line - 1))
                search_order.append(hint_idx)
                for radius in range(1, len(out_lines)):
                    if hint_idx - radius >= 0:
                        search_order.append(hint_idx - radius)
                    if hint_idx + radius < len(out_lines):
                        search_order.append(hint_idx + radius)

                for cand in search_order:
                    match_map = {}
                    o_idx = cand
                    matched = True
                    for s_i, exp in enumerate(orig_seq):
                        exp_cmp = exp.strip() if strip_mode else exp.rstrip("\r\n")
                        while o_idx < len(out_lines):
                            act = out_lines[o_idx]
                            act_cmp = act.strip() if strip_mode else act.rstrip("\r\n")
                            if act_cmp == exp_cmp:
                                match_map[s_i] = o_idx
                                o_idx += 1
                                break
                            elif act_cmp == "" and exp_cmp != "":
                                o_idx += 1
                            else:
                                matched = False
                                break
                        else:
                            matched = False
                        if not matched:
                            break
                    if matched and len(match_map) == len(orig_seq):
                        return match_map
            return None

        match_map = find_match()
        if not match_map:
            raise PatchIntegrityError(f"Hunk at line {hint_line} failed to apply: context mismatch")

        edits = []
        seq_i = 0
        op_i = 0
        while op_i < len(ops):
            op, text = ops[op_i]
            if op == "context":
                seq_i += 1
                op_i += 1
            else:
                del_out_indices = []
                add_lines = []
                while op_i < len(ops) and ops[op_i][0] in ("delete", "add"):
                    cur_op, cur_text = ops[op_i]
                    if cur_op == "delete":
                        del_out_indices.append(match_map[seq_i])
                        seq_i += 1
                    elif cur_op == "add":
                        add_lines.append(cur_text)
                    op_i += 1

                if del_out_indices:
                    start_rep = min(del_out_indices)
                    end_rep = max(del_out_indices) + 1
                    orig_del_first = out_lines[start_rep]
                    orig_indent = len(orig_del_first) - len(orig_del_first.lstrip(" "))
                    # Find corresponding diff deleted line
                    del_ops = [ops[k][1] for k in range(op_i - len(add_lines) - len(del_out_indices), op_i) if ops[k][0] == "delete"]
                    diff_del_first = del_ops[0] if del_ops else ""
                    diff_indent = len(diff_del_first) - len(diff_del_first.lstrip(" "))
                    indent_delta = orig_indent - diff_indent
                else:
                    prev_out_idx = match_map[seq_i - 1] if seq_i > 0 else 0
                    start_rep = prev_out_idx + 1
                    end_rep = start_rep
                    indent_delta = 0

                adjusted_adds = []
                for al in add_lines:
                    if indent_delta > 0:
                        adjusted_adds.append(" " * indent_delta + al + "\n")
                    elif indent_delta < 0 and al.startswith(" " * abs(indent_delta)):
                        adjusted_adds.append(al[abs(indent_delta):] + "\n")
                    else:
                        adjusted_adds.append(al + "\n")

                edits.append((start_rep, end_rep, adjusted_adds))

        # Apply edits in reverse order so line numbers remain valid
        edits.sort(key=lambda x: x[0], reverse=True)
        for s_idx, e_idx, new_l in edits:
            out_lines[s_idx:e_idx] = new_l

    return "".join(out_lines)


class IsolatedWorkspace:
    """
    Creates an isolated copy of target files in a temporary directory,
    applies the patch, and validates AST syntax without touching the repository.
    """

    def __init__(self, workspace_root: str) -> None:
        self.workspace_root = os.path.abspath(workspace_root)
        self.temp_dir: Optional[str] = None
        self.applied_files: List[str] = []

    def create(self) -> IsolatedWorkspace:
        """Create a fresh isolated directory."""
        self.temp_dir = tempfile.mkdtemp(prefix="zda_isolated_ws_")
        return self

    def apply_patch(self, patch_content: str, target_rel_path: str) -> str:
        """
        Copy the source file to isolated workspace, apply the patch, and verify Python syntax.
        Returns the absolute path to the patched file in the isolated workspace.
        """
        if not self.temp_dir:
            self.create()

        if os.path.isabs(target_rel_path):
            src_abs = os.path.abspath(target_rel_path)
            dest_abs = os.path.join(self.temp_dir, os.path.basename(target_rel_path))
        else:
            src_abs = os.path.abspath(os.path.join(self.workspace_root, target_rel_path))
            dest_abs = os.path.join(self.temp_dir, target_rel_path)

        dest_abs = os.path.abspath(dest_abs)
        temp_dir_abs = os.path.abspath(self.temp_dir)
        if not (dest_abs == temp_dir_abs or dest_abs.startswith(temp_dir_abs + os.sep)):
            raise PatchIntegrityError(f"Target path escapes isolated workspace: {target_rel_path}")

        if not os.path.exists(src_abs):
            raise PatchIntegrityError(f"Target source file not found: {target_rel_path}")

        os.makedirs(os.path.dirname(dest_abs), exist_ok=True)

        # Copy sibling files from source directory (e.g. database or helper files) to isolated workspace
        src_parent = os.path.dirname(src_abs)
        dest_parent = os.path.dirname(dest_abs)
        if os.path.exists(src_parent):
            for item in os.listdir(src_parent):
                s_item = os.path.join(src_parent, item)
                d_item = os.path.join(dest_parent, item)
                if os.path.isfile(s_item) and item != os.path.basename(src_abs) and not os.path.exists(d_item):
                    try:
                        shutil.copyfile(s_item, d_item)
                    except Exception:
                        pass
                elif os.path.isdir(s_item) and item not in (".git", "__pycache__", "node_modules", ".pytest_cache") and not os.path.exists(d_item):
                    try:
                        shutil.copytree(s_item, d_item)
                    except Exception:
                        pass

        with open(src_abs, "r", encoding="utf-8") as f:
            original_code = f.read()

        patched_code = apply_unified_diff(original_code, patch_content)

        # Validate syntax
        try:
            ast.parse(patched_code, filename=dest_abs)
        except SyntaxError as e:
            raise PatchIntegrityError(f"Patched code introduced a Python syntax error: {e}") from e

        with open(dest_abs, "w", encoding="utf-8") as f:
            f.write(patched_code)

        self.applied_files.append(dest_abs)
        return dest_abs

    def cleanup(self) -> None:
        """Discard the isolated workspace and all temporary artifacts."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass
            self.temp_dir = None
            self.applied_files = []

    def __enter__(self) -> IsolatedWorkspace:
        return self.create()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()
