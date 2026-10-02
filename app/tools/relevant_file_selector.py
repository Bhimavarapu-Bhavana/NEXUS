from pathlib import Path

from app.security.sensitive_data import redact_text


IGNORED_DIRECTORIES = {
    ".env",
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
}


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".html",
    ".css",
    ".json",
    ".md",
    ".txt",
}


def select_relevant_files(
    workspace_path: str,
    user_request: str,
    max_files: int = 10,
) -> str:
    """
    Find files that are potentially relevant to the user's request.

    This is a read-only tool.

    Selection is based on:
    - filename similarity
    - path similarity
    - words appearing in the request

    It does not execute or modify files.
    """

    root = Path(workspace_path).resolve()

    if not root.exists():
        return "Workspace does not exist."

    if not root.is_dir():
        return "Workspace path is not a directory."

    request_words = {
        word.lower()
        for word in user_request.replace("_", " ").replace("-", " ").split()
        if len(word) >= 3
    }

    candidates = []

    for file in root.rglob("*"):

        if not file.is_file():
            continue

        if any(part in IGNORED_DIRECTORIES for part in file.parts):
            continue

        if file.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        relative_path = file.relative_to(root)

        path_text = str(relative_path).lower()

        filename_text = file.stem.lower().replace("_", " ").replace("-", " ")

        score = 0

        # Filename relevance
        for word in request_words:
            if word in filename_text:
                score += 5

        # Path relevance
        for word in request_words:
            if word in path_text:
                score += 2

        # Common project source files receive a small baseline score
        if file.suffix.lower() in {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".java",
            ".c",
            ".cpp",
        }:
            score += 1

        candidates.append((score, str(relative_path)))

    if not candidates:
        return "No supported project files found."

    candidates.sort(
        key=lambda item: (-item[0], item[1].lower())
    )

    selected = candidates[:max_files]

    result = [
        f"Relevant files selected: {len(selected)}",
        "",
    ]

    for score, path in selected:
        result.append(
            f"FILE: {path} | RELEVANCE SCORE: {score}"
        )

    return redact_text("\n".join(result))