from pathlib import Path
from collections.abc import Iterable

from app.security.sensitive_data import redact_text


def inspect_python_logic(workspace_path: str, file_names: Iterable[str] | None = None) -> str:
    """
    Inspect Python source files inside the authorized workspace.

    This tool only reads source code.
    It does not execute or modify files.
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

    requested = {str(name).replace("\\", "/").strip() for name in (file_names or []) if str(name).strip()}
    results = []

    files = [root / name for name in requested] if requested else list(root.rglob("*.py"))
    for file in files:

        if not file.is_file() or file.suffix.lower() != ".py":
            continue

        if any(part in ignored for part in file.parts):
            continue

        try:
            file.relative_to(root)
        except ValueError:
            continue

        try:
            content = file.read_text(
                encoding="utf-8",
                errors="replace"
            )

            relative_path = file.relative_to(root)

            results.append(
                f"\n--- FILE: {relative_path} ---\n"
                f"{content[:8000]}"
            )

        except Exception as error:
            results.append(
                f"\n--- FILE: {file} ---\n"
                f"Could not read file: {error}"
            )

    if not results:
        return "No Python files found."

    return redact_text(
        f"Python files discovered: {len(results)}\n"
        + "\n".join(results)
    )