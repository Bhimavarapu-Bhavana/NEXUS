from pathlib import Path
import ast

from app.security.sensitive_data import redact_text


def detect_python_errors(workspace_path: str) -> str:
    """
    Safely detect Python syntax errors in an authorized workspace.
    Does not execute the Python files.
    """

    root = Path(workspace_path)

    if not root.exists():
        return "Workspace does not exist."

    if not root.is_dir():
        return "Workspace path is not a directory."

    ignored = {
        ".env",
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
    }

    errors = []
    checked = 0

    for file in root.rglob("*.py"):
        if any(part in ignored for part in file.parts):
            continue

        checked += 1

        try:
            source = file.read_text(
                encoding="utf-8",
                errors="replace"
            )

            ast.parse(source)

        except SyntaxError as error:
            relative_path = file.relative_to(root)

            errors.append(
                f"FILE: {relative_path}\n"
                f"ERROR: SyntaxError\n"
                f"LINE: {error.lineno}\n"
                f"COLUMN: {error.offset}\n"
                f"MESSAGE: {error.msg}"
            )

        except Exception as error:
            relative_path = file.relative_to(root)

            errors.append(
                f"FILE: {relative_path}\n"
                f"ERROR: Could not analyze file\n"
                f"MESSAGE: {error}"
            )

    if not errors:
        return (
            f"Python files checked: {checked}\n"
            "No Python syntax errors detected."
        )

    return redact_text(
        f"Python files checked: {checked}\n\n"
        "Detected errors:\n\n"
        + "\n\n".join(errors)
    )