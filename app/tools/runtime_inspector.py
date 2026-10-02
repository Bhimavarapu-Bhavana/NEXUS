from pathlib import Path
import subprocess
import sys

from app.security.sensitive_data import redact_text
from app.agent.runtime_containment import execute_contained_python


IGNORED_DIRECTORIES = {
    ".env",
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
}


def run_python_file(
    workspace_path: str,
    file_name: str,
    timeout_seconds: int = 10,
) -> str:
    """
    Safely run an authorized Python file and capture its output.

    Security:
    - Only runs Python files.
    - File must remain inside the authorized workspace.
    - Uses the current Python interpreter.
    - Has a strict timeout.
    - Captures stdout and stderr.
    - Does not allow the LLM to construct arbitrary commands.
    """

    root = Path(workspace_path).resolve()
    file = (root / file_name).resolve()

    # Security: prevent access outside workspace
    try:
        file.relative_to(root)
    except ValueError:
        return (
            "Security error: requested file is "
            "outside the authorized workspace."
        )

    # Only Python files
    if file.suffix.lower() != ".py":
        return (
            "Security error: runtime inspector "
            "only runs Python files."
        )

    # Prevent execution of ignored directories
    if any(
        part in IGNORED_DIRECTORIES
        for part in file.relative_to(root).parts
    ):
        return (
            "Security error: requested file is "
            "inside a restricted directory."
        )

    if not file.exists():
        return f"File does not exist: {file_name}"

    if not file.is_file():
        return f"Not a valid file: {file_name}"

    try:
        contained = execute_contained_python(file, workspace_root=root, timeout_seconds=timeout_seconds)
        if contained.get("status") == "RUNTIME_CONTAINMENT_UNAVAILABLE":
            return redact_text(f"FILE: {file_name}\nSTATUS: RUNTIME_CONTAINMENT_UNAVAILABLE\nERROR: {contained.get('error', '')}")
        if contained.get("status") in {"RUNTIME_CAPABILITY_BLOCKED", "TIMEOUT"}:
            return redact_text(f"FILE: {file_name}\nSTATUS: {contained.get('status')}\nERROR: {contained.get('error', contained.get('stderr', ''))}")

        stdout = str(contained.get("stdout", "")).strip()
        stderr = str(contained.get("stderr", "")).strip()
        return_code = int(contained.get("returncode", 0) or 0)

        output = [
            f"FILE: {file_name}",
            f"EXIT CODE: {return_code}",
            "",
            "STDOUT:",
            stdout if stdout else "(no output)",
            "",
            "STDERR:",
            stderr if stderr else "(no errors)",
        ]

        if return_code == 0:
            output.extend(
                [
                    "",
                    "STATUS: SUCCESS",
                ]
            )
        else:
            output.extend(
                [
                    "",
                    "STATUS: RUNTIME ERROR",
                ]
            )

        return redact_text("\n".join(output))

    except subprocess.TimeoutExpired:
        return (
            f"FILE: {file_name}\n"
            f"STATUS: TIMEOUT\n"
            f"Execution exceeded {timeout_seconds} seconds."
        )

    except Exception as error:
        return (
            f"FILE: {file_name}\n"
            "STATUS: EXECUTION FAILED\n"
            f"ERROR: {error}"
        )