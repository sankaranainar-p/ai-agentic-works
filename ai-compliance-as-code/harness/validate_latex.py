"""
harness/validate_latex.py — Pure-Python LaTeX Syntax and Booktabs Table Validator.

Validates LaTeX documents and table snippets without requiring an external pdflatex binary:
  1. Balanced environments: \\begin{env} matches \\end{env} with strict LIFO nesting.
  2. Proper column alignment: In tabular environments, verifies that data lines have
     column counts matching the tabular column specification (accounting for \\multicolumn).
  3. Valid booktabs line rules: Ensures \\toprule, \\midrule, and \\bottomrule are used
     in proper sequence.
  4. Escaped special characters:
     - Unescaped underscores '_' outside of math mode ($...$) and label/input commands
     - Unescaped percent signs '%' intended as symbols rather than comments (e.g., "50%")
     - Unescaped ampersands '&' outside of tabular environments
     - Delimiter and brace matching ($...$ and {...})

Usage:
  python -m harness.validate_latex paper/artifacts/
  python -m harness.validate_latex paper/artifacts/table1_complementarity.tex
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# Helpers: Column Specifier Parsing & Cell Splitting
# ---------------------------------------------------------------------------

def find_unescaped_comment_index(line: str) -> int:
    """Find index of the first unescaped '%' that starts a LaTeX comment, or -1 if none."""
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "%":
            return i
    return -1


def parse_tabular_column_count(spec: str) -> int:
    """Parse a LaTeX tabular column specification and return the expected column count.

    Examples:
      - 'lcccccc' -> 7
      - 'lccccc' -> 6
      - 'ccccccc' -> 7
      - '*{3}{c}l' -> 4
      - 'p{3cm}cc' -> 3
    """
    clean = re.sub(r"\s+", "", spec)
    clean = re.sub(r"[@!|]\{[^{}]*\}", "", clean)
    clean = clean.replace("|", "")

    # Expand *{N}{cols} constructs
    while True:
        m = re.search(r"\*\{(\d+)\}\{([^{}]+)\}", clean)
        if not m:
            break
        count = int(m.group(1))
        repeated = m.group(2) * count
        clean = clean[:m.start()] + repeated + clean[m.end():]

    # Replace p{...}, m{...}, b{...} with single column placeholders
    clean = re.sub(r"[pmb]\{[^{}]*\}", "c", clean)

    # Valid LaTeX column characters: l, c, r, X, s, p, m, b
    cols = re.findall(r"[lcrXspmb]", clean)
    return len(cols)


def split_cells_by_ampersand(row_text: str) -> List[str]:
    """Split a table row by top-level unescaped ampersands '&' at brace depth 0."""
    cells: List[str] = []
    current_chars: List[str] = []
    depth = 0
    in_math = False
    escaped = False

    for ch in row_text:
        if escaped:
            current_chars.append(ch)
            escaped = False
            continue

        if ch == "\\":
            current_chars.append(ch)
            escaped = True
            continue

        if ch == "$" and not escaped:
            in_math = not in_math
            current_chars.append(ch)
            continue

        if ch == "{" and not in_math:
            depth += 1
            current_chars.append(ch)
            continue

        if ch == "}" and not in_math:
            depth = max(0, depth - 1)
            current_chars.append(ch)
            continue

        if ch == "&" and depth == 0 and not in_math:
            cells.append("".join(current_chars).strip())
            current_chars = []
            continue

        current_chars.append(ch)

    if current_chars or cells:
        cells.append("".join(current_chars).strip())

    return cells


def compute_row_column_span(cell: str) -> int:
    """Return the number of columns spanned by a single cell (handles \\multicolumn{K})."""
    cell_clean = cell.strip()
    m = re.match(r"^\\multicolumn\s*\{(\d+)\}", cell_clean)
    if m:
        return int(m.group(1))
    return 1


# ---------------------------------------------------------------------------
# Core Validator
# ---------------------------------------------------------------------------

class LaTeXValidator:
    """Validates LaTeX content for environments, columns, booktabs, and escaping."""

    def __init__(self, content: str, filename: str = "<string>") -> None:
        self.content = content
        self.filename = filename
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate(self) -> List[str]:
        """Run all validation checks and return a list of error strings."""
        self.errors = []
        self.warnings = []

        lines = self.content.splitlines()

        # 1. Environment and brace balance check
        self._check_environments_and_braces(lines)

        # 2. Tabular column alignment & booktabs rule order check
        self._check_tabular_blocks(lines)

        # 3. Special character escaping check
        self._check_escaped_characters(lines)

        return self.errors

    def _check_environments_and_braces(self, lines: List[str]) -> None:
        env_stack: List[Tuple[str, int]] = []
        total_open_braces = 0
        total_close_braces = 0

        for line_idx, line in enumerate(lines, start=1):
            comment_idx = find_unescaped_comment_index(line)
            code_part = line[:comment_idx] if comment_idx != -1 else line

            # Check \begin{...}
            for match in re.finditer(r"\\begin\{([a-zA-Z0-9*]+)\}", code_part):
                env_name = match.group(1)
                env_stack.append((env_name, line_idx))

            # Check \end{...}
            for match in re.finditer(r"\\end\{([a-zA-Z0-9*]+)\}", code_part):
                env_name = match.group(1)
                if not env_stack:
                    self.errors.append(
                        f"[{self.filename}:{line_idx}] Unexpected \\end{{{env_name}}} with no active \\begin."
                    )
                else:
                    expected_name, start_line = env_stack.pop()
                    if expected_name != env_name:
                        self.errors.append(
                            f"[{self.filename}:{line_idx}] Mismatched environment: expected \\end{{{expected_name}}} "
                            f"(opened at line {start_line}), but found \\end{{{env_name}}}."
                        )

            # Brace counting (ignoring \{ and \})
            escaped_b = False
            for ch in code_part:
                if escaped_b:
                    escaped_b = False
                    continue
                if ch == "\\":
                    escaped_b = True
                    continue
                if ch == "{":
                    total_open_braces += 1
                elif ch == "}":
                    total_close_braces += 1

            # Math delimiter parity per line ($ ... $)
            dollar_count = 0
            escaped_d = False
            for ch in code_part:
                if escaped_d:
                    escaped_d = False
                    continue
                if ch == "\\":
                    escaped_d = True
                    continue
                if ch == "$":
                    dollar_count += 1
            if dollar_count % 2 != 0:
                self.errors.append(
                    f"[{self.filename}:{line_idx}] Unbalanced math delimiter '$' on line ({dollar_count} unescaped '$')."
                )

        # Check any unclosed environments
        while env_stack:
            unclosed_env, start_line = env_stack.pop()
            self.errors.append(
                f"[{self.filename}:{start_line}] Unclosed environment: \\begin{{{unclosed_env}}} has no matching \\end."
            )

        if total_open_braces != total_close_braces:
            self.errors.append(
                f"[{self.filename}] Unbalanced curly braces: found {total_open_braces} '{{' and {total_close_braces} '}}'."
            )

    def _check_tabular_blocks(self, lines: List[str]) -> None:
        in_tabular = False
        tabular_start_line = 0
        expected_cols = 0
        rule_history: List[Tuple[str, int]] = []

        for line_idx, line in enumerate(lines, start=1):
            strip_line = line.strip()

            # Detect \begin{tabular}{...}
            m_begin = re.search(r"\\begin\{tabular\}\{([^{}]+)\}", strip_line)
            if m_begin:
                in_tabular = True
                tabular_start_line = line_idx
                spec = m_begin.group(1)
                expected_cols = parse_tabular_column_count(spec)
                rule_history = []
                if expected_cols == 0:
                    self.errors.append(
                        f"[{self.filename}:{line_idx}] Could not parse valid columns from tabular spec '{spec}'."
                    )
                continue

            if "\\end{tabular}" in strip_line:
                if in_tabular:
                    rule_names = [r[0] for r in rule_history]
                    if any(r in rule_names for r in ["toprule", "midrule", "bottomrule"]):
                        if "toprule" not in rule_names:
                            self.errors.append(
                                f"[{self.filename}:{tabular_start_line}] Booktabs tabular missing \\toprule."
                            )
                        if "bottomrule" not in rule_names:
                            self.errors.append(
                                f"[{self.filename}:{line_idx}] Booktabs tabular missing \\bottomrule."
                            )
                        if "toprule" in rule_names and "bottomrule" in rule_names:
                            top_idx = rule_names.index("toprule")
                            bot_idx = rule_names.index("bottomrule")
                            if top_idx > bot_idx:
                                self.errors.append(
                                    f"[{self.filename}:{line_idx}] \\bottomrule appeared before \\toprule."
                                )

                in_tabular = False
                continue

            if not in_tabular:
                continue

            # Inside tabular:
            if "\\toprule" in strip_line:
                rule_history.append(("toprule", line_idx))
                continue
            if "\\midrule" in strip_line:
                rule_history.append(("midrule", line_idx))
                continue
            if "\\bottomrule" in strip_line:
                rule_history.append(("bottomrule", line_idx))
                continue
            if "\\hline" in strip_line:
                self.warnings.append(
                    f"[{self.filename}:{line_idx}] Obsolete \\hline found in tabular; prefer booktabs \\midrule/\\toprule."
                )
                continue

            # Strip pure comments or empty lines
            if not strip_line or strip_line.startswith("%"):
                continue

            # Check if this line is a data row ending with \\
            if strip_line.endswith(r"\\") or r"\\" in strip_line:
                comment_idx = find_unescaped_comment_index(strip_line)
                row_content = strip_line[:comment_idx] if comment_idx != -1 else strip_line

                last_slash = row_content.rfind(r"\\")
                if last_slash != -1:
                    row_content = row_content[:last_slash].strip()

                if not row_content:
                    continue

                cells = split_cells_by_ampersand(row_content)
                total_span = sum(compute_row_column_span(c) for c in cells)

                if total_span != expected_cols:
                    self.errors.append(
                        f"[{self.filename}:{line_idx}] Column count mismatch in tabular. "
                        f"Expected {expected_cols} columns, but row spans {total_span} columns "
                        f"(found {len(cells)} cells, {len(cells)-1} '&' delimiters). Row: '{row_content[:60]}'."
                    )

    def _check_escaped_characters(self, lines: List[str]) -> None:
        in_tabular = False

        for line_idx, line in enumerate(lines, start=1):
            strip_line = line.strip()

            if "\\begin{tabular}" in strip_line:
                in_tabular = True
            elif "\\end{tabular}" in strip_line:
                in_tabular = False

            if strip_line.startswith("%"):
                continue

            comment_start = find_unescaped_comment_index(line)
            code_text = line[:comment_start] if comment_start != -1 else line

            # Check 1: Unescaped percent symbol in code (e.g., "50%" or "12.3%")
            bad_percent = re.search(r"(\d+(?:\.\d+)?)(?<!\\)%", line)
            if bad_percent and (comment_start == -1 or bad_percent.start() <= comment_start):
                match_start = bad_percent.start(0) + len(bad_percent.group(1))
                if match_start == 0 or line[match_start - 1] != "\\":
                    self.errors.append(
                        f"[{self.filename}:{line_idx}] Unescaped percent sign in '{bad_percent.group(0)}'. "
                        f"In LaTeX, '%' starts a comment; write '\\%' instead."
                    )

            # Check 2: Unescaped underscore outside math mode ($...$) and safe commands (\label, \input, etc.)
            in_math = False
            escaped_u = False
            non_math_chars: List[str] = []

            for ch in code_text:
                if escaped_u:
                    escaped_u = False
                    if not in_math:
                        non_math_chars.append("\\" + ch)
                    continue
                if ch == "\\":
                    escaped_u = True
                    continue
                if ch == "$":
                    in_math = not in_math
                    continue
                if not in_math:
                    non_math_chars.append(ch)

            non_math_str = "".join(non_math_chars)
            # Exclude commands where raw underscores are valid LaTeX identifier syntax
            safe_text = re.sub(r"\\(label|ref|pageref|cite|input|include|usepackage|documentclass|begin|end|url)\{[^{}]*\}", "", non_math_str)

            for m in re.finditer(r"(?<!\\)_", safe_text):
                snippet = safe_text[max(0, m.start() - 10):min(len(safe_text), m.end() + 10)]
                self.errors.append(
                    f"[{self.filename}:{line_idx}] Unescaped underscore '_' outside math mode: '...{snippet}...'. "
                    f"Use '\\_' or place in math mode."
                )

            # Check 3: Unescaped '&' outside tabular
            if not in_tabular:
                escaped_a = False
                for ch in code_text:
                    if escaped_a:
                        escaped_a = False
                        continue
                    if ch == "\\":
                        escaped_a = True
                        continue
                    if ch == "&":
                        self.errors.append(
                            f"[{self.filename}:{line_idx}] Unescaped '&' outside tabular environment. "
                            f"Use '\\&' for literal ampersands."
                        )
                        break


# ---------------------------------------------------------------------------
# Public Functions & CLI
# ---------------------------------------------------------------------------

def validate_latex_content(content: str, filename: str = "<string>") -> List[str]:
    """Validate LaTeX string content and return list of error strings."""
    validator = LaTeXValidator(content, filename=filename)
    return validator.validate()


def validate_latex_file(path: Path) -> List[str]:
    """Validate a single LaTeX file and return list of error strings."""
    if not path.is_file():
        return [f"File not found: {path}"]
    content = path.read_text(encoding="utf-8")
    return validate_latex_content(content, filename=path.name)


def validate_latex_dir(dir_path: Path) -> Dict[Path, List[str]]:
    """Validate all .tex files in directory (and subdirectories) and return mapping of path to errors."""
    results: Dict[Path, List[str]] = {}
    for p in sorted(dir_path.rglob("*.tex")):
        errors = validate_latex_file(p)
        results[p] = errors
    return results


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pure-Python LaTeX Booktabs & Syntax Validator (No pdflatex required).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["paper/artifacts"],
        help="Files or directories containing .tex files to validate.",
    )

    args = parser.parse_args(argv)
    targets = [Path(p) for p in args.paths]

    total_files = 0
    total_errors = 0
    results: Dict[Path, List[str]] = {}

    for t in targets:
        if t.is_dir():
            dir_res = validate_latex_dir(t)
            results.update(dir_res)
        elif t.is_file():
            results[t] = validate_latex_file(t)
        else:
            print(f"Error: Target path does not exist: {t}", file=sys.stderr)
            return 1

    total_files = len(results)
    print(f"\nValidating {total_files} LaTeX artifact(s)...")

    for path, errors in results.items():
        if not errors:
            print(f"  [PASS] {path}")
        else:
            print(f"  [FAIL] {path} ({len(errors)} error(s)):")
            for err in errors:
                print(f"         - {err}")
            total_errors += len(errors)

    if total_errors == 0:
        print(f"\nAll {total_files} LaTeX file(s) passed validation successfully.\n")
        return 0
    else:
        print(f"\nValidation failed with {total_errors} total error(s) across {total_files} file(s).\n", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
