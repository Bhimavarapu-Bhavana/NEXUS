from pathlib import Path


def fix_python_logic(
    workspace_path: str,
    file_name: str,
    old_code: str,
    new_code: str,
    *,
    execution_context: dict[str, object] | None = None,
) -> str:
    """
    Safely apply an approved code change to a Python file.

    Security:
    - Only works inside the authorized workspace.
    - Only modifies .py files.
    - Requires the exact old code to exist.
    - Changes only the first matching occurrence.
    - Does not execute the modified code.
    """

    if not isinstance(execution_context, dict) or not execution_context.get("approval_id") or not execution_context.get("checkpoint_id") or not execution_context.get("proposal_hash"):
        return "Execution blocked: fixer requires an authoritative approved execution context."

    root = Path(workspace_path).resolve()
    file = (root / file_name).resolve()

    # Security check: prevent access outside workspace
    try:
        file.relative_to(root)
    except ValueError:
        return "Security error: requested file is outside the authorized workspace."

    # Only allow Python files
    if file.suffix != ".py":
        return "Security error: only Python files can be modified."

    if any(part.lower() in {".env", ".git", ".venv", "__pycache__", "node_modules"} for part in file.relative_to(root).parts):
        return "Security error: requested file is inside a restricted directory."

    if not file.exists():
        return f"File does not exist: {file_name}"

    if not file.is_file():
        return f"Not a valid file: {file_name}"

    try:
        content = file.read_text(
            encoding="utf-8",
            errors="replace"
        )

        # Make sure the expected code exists
        if old_code not in content:
            return (
                "Expected code was not found.\n"
                "No changes were made."
            )

        # Prevent accidental no-op
        if old_code == new_code:
            return "Old and new code are identical. No changes made."

        # Apply only the first exact replacement
        updated_content = content.replace(
            old_code,
            new_code,
            1
        )

        file.write_text(
            updated_content,
            encoding="utf-8"
        )

        return (
            "Fix applied successfully.\n\n"
            f"File: {file_name}\n"
            f"Changed:\n{old_code}\n\n"
            f"To:\n{new_code}"
        )

    except Exception as error:
        return f"Fix failed: {error}"