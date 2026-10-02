from pathlib import Path

from app.security.sensitive_data import redact_text


def inspect_python_files(workspace_path: str) -> str:
    """
    Safely inspect Python source files in an authorized workspace.
    """

    root = Path(workspace_path)

    if not root.exists():
        return "Workspace does not exist."

    results = []

    ignored = {
        ".env",
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
    }

    for file in root.rglob("*.py"):
        if any(part in ignored for part in file.parts):
            continue

        try:
            content = file.read_text(
                encoding="utf-8",
                errors="replace"
            )

            relative_path = file.relative_to(root)

            results.append(
                f"\n--- FILE: {relative_path} ---\n"
                f"{content[:5000]}"
            )

        except Exception as error:
            results.append(
                f"\n--- FILE: {file} ---\n"
                f"Could not read file: {error}"
            )

    if not results:
        return "No Python files found."

    return redact_text("\n".join(results))