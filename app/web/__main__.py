"""Launch the local NEXUS Web Control Surface.

Usage:
    python -m app.web [--host 127.0.0.1] [--port 8770] [--workspace PATH] [--db PATH]

The service always binds to localhost only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local NEXUS Web Control Surface.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8770, type=int)
    parser.add_argument("--workspace", default="workspace")
    parser.add_argument("--db", default=None, help="Path to the single unified NEXUS SQLite store.")
    args = parser.parse_args(argv)

    from app.control_plane import ControlPlane, run_server

    if args.host not in {"127.0.0.1", "localhost"}:
        print(f"Refusing to bind to {args.host}; NEXUS is local-only.", file=sys.stderr)
        return 2

    workspace = Path(args.workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    control = ControlPlane(workspace_root=workspace, db_path=Path(args.db) if args.db else None)
    return run_server(host=args.host, port=int(args.port), control=control)


if __name__ == "__main__":
    raise SystemExit(main())