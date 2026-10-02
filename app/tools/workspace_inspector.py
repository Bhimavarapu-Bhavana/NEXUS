from pathlib import Path

from app.security.sensitive_data import redact_text


def inspect_workspace(workspace_path: str) -> str:
    """
    Inspect an authorized workspace and return a safe summary.
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

    files = []
    directories = []

    for item in root.rglob("*"):
        if any(part in ignored for part in item.parts):
            continue

        if item.is_dir():
            directories.append(str(item.relative_to(root)))

        elif item.is_file():
            files.append(str(item.relative_to(root)))

    result = [
        f"Workspace: {root}",
        f"Directories found: {len(directories)}",
        f"Files found: {len(files)}",
        "",
        "Files:"
    ]

    result.extend(files[:50])

    if len(files) > 50:
        result.append(f"... and {len(files) - 50} more files.")

    return redact_text("\n".join(result))