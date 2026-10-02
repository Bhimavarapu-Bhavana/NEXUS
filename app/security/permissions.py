from pathlib import Path


# NEXUS only operates inside an authorized workspace root.
# The default remains the project workspace, but tools may validate against the
# actual workspace supplied at runtime (including temp or test workspaces).
AUTHORIZED_WORKSPACE = Path("workspace").resolve()


def is_authorized_path(path: str, workspace_root: str | Path | None = None) -> bool:
    """
    Check whether a requested path is inside the provided workspace root.
    When no workspace root is supplied, fall back to the default authorized workspace.
    """

    requested = Path(path).resolve()
    root = Path(workspace_root).resolve() if workspace_root is not None else AUTHORIZED_WORKSPACE

    try:
        requested.relative_to(root)
        return True
    except ValueError:
        return False


def get_authorized_workspace() -> str:
    """
    Return the authorized workspace path.
    """

    return str(AUTHORIZED_WORKSPACE)