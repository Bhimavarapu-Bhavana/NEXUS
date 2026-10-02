from pathlib import Path


def verify_demo_calculation(workspace_path: str) -> str:
    """
    Verify the controlled demo calculation after a proposed fix.
    """

    root = Path(workspace_path)
    file = root / "workspace" / "demo_error.py"

    if not file.exists():
        return "Demo file does not exist."

    try:
        content = file.read_text(
            encoding="utf-8",
            errors="replace"
        )

        if "total = price * quantity" in content:
            return (
                "Verification successful.\n"
                "The calculation now uses multiplication.\n"
                "Expected result: 200."
            )

        if "total = price + quantity" in content:
            return (
                "Verification failed.\n"
                "The logical error is still present.\n"
                "The calculation still uses addition."
            )

        return "Verification inconclusive."

    except Exception as error:
        return f"Verification error: {error}"