"""
worker.py — spawned as a subprocess by main.py.

This simulates an external tool (image processor, converter, etc.)
that a web server might call to handle user input.

It enumerates /proc/self/fd/ to discover what file descriptors
it inherited from the parent process, then attempts to read them.

In the VULNERABLE case:  parent called subprocess with close_fds=False
                          → this worker finds and reads secrets.txt fd.

In the SAFE case:         parent called subprocess with close_fds=True
                          → only stdin/stdout/stderr survive; nothing leaks.
"""

import os
import stat
import sys
import json

FD_DIR = "/proc/self/fd"

findings = []

try:
    fd_names = os.listdir(FD_DIR)
except PermissionError as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)

for fd_name in sorted(fd_names, key=lambda x: int(x)):
    try:
        fd_num = int(fd_name)
    except ValueError:
        continue

    # Skip the fd we opened to list the directory itself
    # and skip stdin / stdout / stderr.
    if fd_num <= 2:
        continue

    fd_path = os.path.join(FD_DIR, fd_name)

    try:
        resolved = os.readlink(fd_path)
    except OSError:
        continue

    entry = {
        "fd":       fd_num,
        "resolved": resolved,
        "readable": False,
        "content":  None,
        "error":    None,
    }

    # Only attempt to read regular files — sockets/pipes/etc. would block
    try:
        fd_stat = os.fstat(fd_num)
        if not stat.S_ISREG(fd_stat.st_mode):
            entry["error"] = f"skipped (not a regular file: {stat.filemode(fd_stat.st_mode)})"
            findings.append(entry)
            continue
    except OSError as exc:
        entry["error"] = str(exc)
        findings.append(entry)
        continue

    # Attempt to read through the inherited descriptor
    try:
        # Re-open via /proc/self/fd/<n> so we don't need the original path
        with open(fd_path, "r", errors="replace") as fh:
            entry["content"]  = fh.read(1024)
            entry["readable"] = True
    except Exception as exc:
        entry["error"] = str(exc)

    findings.append(entry)

print(json.dumps(findings))
