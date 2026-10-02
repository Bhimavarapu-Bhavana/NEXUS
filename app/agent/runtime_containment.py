from __future__ import annotations

import ast
import ctypes
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from app.security.sensitive_data import redact_text
from app.security.permissions import is_authorized_path

DENIED_IMPORTS = {
    "socket", "ssl", "urllib", "urllib.request", "http", "http.client", "https", "ftplib", "telnetlib",
    "requests", "httpx", "aiohttp", "subprocess", "multiprocessing", "ctypes", "win32api", "win32con",
}
DENIED_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "spawn", "create_subprocess_exec", "create_subprocess_shell", "open", "input", "getattr", "setattr", "vars", "globals", "locals", "breakpoint", "help", "dir"}
MAX_OUTPUT_CHARS = 12000


def _module_name(node: ast.ImportFrom) -> str:
    return str(node.module or "")


def validate_runtime_source(path: Path) -> tuple[bool, str]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        return False, f"Runtime source could not be validated: {redact_text(exc)}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in DENIED_IMPORTS or alias.name.split(".")[0] in DENIED_IMPORTS:
                    return False, f"Runtime capability denied for import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and (_module_name(node) in DENIED_IMPORTS or _module_name(node).split(".")[0] in DENIED_IMPORTS):
            return False, f"Runtime capability denied for import: {_module_name(node)}"
        elif isinstance(node, ast.Call):
            function = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if function in DENIED_CALLS:
                return False, f"Runtime capability denied for call: {function}"
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            return False, "Runtime capability denied for attribute or subscript-based escape access"
    return True, "validated"


def _windows_job_available() -> bool:
    return os.name == "nt" and hasattr(ctypes, "windll")


def _assign_kill_on_close(job: Any, process: subprocess.Popen[str]) -> bool:
    if not _windows_job_available():
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        job_handle = kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            return False
        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", ctypes.c_ulong), ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_ulong), ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_ulong), ("SchedulingClass", ctypes.c_ulong)]
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [("ReadOperationCount", ctypes.c_ulonglong), ("WriteOperationCount", ctypes.c_ulonglong), ("OtherOperationCount", ctypes.c_ulonglong), ("ReadTransferCount", ctypes.c_ulonglong), ("WriteTransferCount", ctypes.c_ulonglong), ("OtherTransferCount", ctypes.c_ulonglong)]
        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000
        if not kernel32.SetInformationJobObject(job_handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(job_handle)
            return False
        if not kernel32.AssignProcessToJobObject(job_handle, int(process._handle)):
            kernel32.CloseHandle(job_handle)
            return False
        job.value = job_handle
        return True
    except Exception:
        return False


def _terminate_tree(process: subprocess.Popen[str], job: Any) -> None:
    if job.value and _windows_job_available():
        try:
            ctypes.windll.kernel32.TerminateJobObject(job.value, 1)
            ctypes.windll.kernel32.CloseHandle(job.value)
            return
        except Exception:
            pass
    try:
        process.kill()
    except OSError:
        pass


def execute_contained_python(path: Path, *, workspace_root: Path, timeout_seconds: int = 10) -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "RUNTIME_CONTAINMENT_UNAVAILABLE", "error": "Required Windows process containment is unavailable."}
    resolved_path = path.resolve()
    resolved_root = workspace_root.resolve()
    if not is_authorized_path(str(resolved_path), resolved_root) or not resolved_path.is_file():
        return {"status": "RUNTIME_CAPABILITY_BLOCKED", "error": "Runtime source is outside the authorized workspace."}
    valid, reason = validate_runtime_source(resolved_path)
    if not valid:
        return {"status": "RUNTIME_CAPABILITY_BLOCKED", "error": reason}
    environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP") if key in os.environ}
    environment["PATH"] = os.environ.get("PATH", "")
    environment["PYTHONNOUSERSITE"] = "1"
    environment["NEXUS_RUNTIME_NETWORK_POLICY"] = "DENY"
    process: subprocess.Popen[str] | None = None
    job = type("JobHandle", (), {"value": None})()
    try:
        process = subprocess.Popen([sys.executable, str(resolved_path)], cwd=str(resolved_root), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, env=environment, creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if not _assign_kill_on_close(job, process):
            _terminate_tree(process, job)
            return {"status": "RUNTIME_CONTAINMENT_UNAVAILABLE", "error": "Windows Job Object containment could not be established."}
        try:
            stdout, stderr = process.communicate(timeout=max(1, int(timeout_seconds)))
        except subprocess.TimeoutExpired:
            _terminate_tree(process, job)
            process.wait(timeout=5)
            return {"status": "TIMEOUT", "stdout": "", "stderr": "Runtime process tree terminated after timeout."}
        status = "SUCCESS" if process.returncode == 0 else "RUNTIME ERROR"
        return {"status": status, "returncode": process.returncode, "stdout": stdout[:MAX_OUTPUT_CHARS], "stderr": stderr[:MAX_OUTPUT_CHARS], "network_policy": "DENY", "containment": "WINDOWS_JOB_OBJECT"}
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None:
            _terminate_tree(process, job)
        return {"status": "RUNTIME_CONTAINMENT_UNAVAILABLE", "error": redact_text(exc)}
    finally:
        if job.value and _windows_job_available():
            try:
                ctypes.windll.kernel32.CloseHandle(job.value)
            except Exception:
                pass
