"""
JOCKY Framework — Module 7: In-Memory Execution via memfd_create

Loads a compiled binary into an anonymous in-memory file (memfd) and
executes it via fexecve. No file ever touches disk.

This is the Linux analogue of Windows reflective DLL injection / process
hollowing. It satisfies the problem statement's "file-less execution"
requirement.
"""

import ctypes
import os
import sys
from pathlib import Path


# x86_64 Linux syscall numbers
SYS_write   = 1
SYS_close   = 3
SYS_fexecve = 431

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def _syscall(num: int, *args) -> int:
    """Raw syscall — every integer arg forced to c_long."""
    c_args = [ctypes.c_long(num)]
    for a in args:
        if isinstance(a, int):
            c_args.append(ctypes.c_long(a))
        else:
            c_args.append(a)
    ret = int(libc.syscall(*c_args))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"syscall {num} failed: {os.strerror(err)}")
    return ret


def write_all(fd: int, data: bytes):
    """Write all bytes to fd, handling partial writes."""
    offset = 0
    total = len(data)
    while offset < total:
        chunk = data[offset:offset + 65536]
        buf = ctypes.create_string_buffer(chunk, len(chunk))
        ptr = ctypes.cast(buf, ctypes.c_void_p)
        written = _syscall(SYS_write, fd, ptr, len(chunk))
        if written <= 0:
            raise OSError(f"write returned {written}")
        offset += written


def execute_from_memory(binary_path: str, verbose: bool = True):
    """Load binary into memory and execute via fexecve — nothing on disk."""
    bin_path = Path(binary_path)
    if not bin_path.exists():
        raise FileNotFoundError(f"binary not found: {binary_path}")

    data = bin_path.read_bytes()

    if verbose:
        print(f"[memfd] Loading {bin_path.name} ({len(data)} bytes) into RAM")
        print(f"[memfd] Original inode on disk: {bin_path.stat().st_ino}")

    # Create anonymous in-memory file (uses os.memfd_create — stdlib, safe)
    fd = os.memfd_create("jocky_payload", flags=os.MFD_CLOEXEC)
    if verbose:
        print(f"[memfd] Created anonymous fd: {fd}")

    write_all(fd, data)
    if verbose:
        print(f"[memfd] Wrote {len(data)} bytes to fd")

    # Proof: the fd points to a deleted memfd — nothing on disk
    if verbose:
        try:
            link = os.readlink(f"/proc/self/fd/{fd}")
            print(f"[memfd] fd -> {link}")
        except Exception as e:
            print(f"[memfd] (readlink failed: {e})")

    # Fork and execute via fexecve(fd)
    pid = os.fork()
    if pid == 0:
        try:
            argv_b = [str(bin_path).encode(), None]
            argv_c = (ctypes.c_char_p * len(argv_b))(*argv_b)
            envp_c = (ctypes.c_char_p * 1)(None)

            # Primary: try fexecve (fd-based execution)
            ret = int(libc.syscall(
                ctypes.c_long(SYS_fexecve),
                ctypes.c_long(fd),
                ctypes.cast(argv_c, ctypes.c_void_p),
                ctypes.cast(envp_c, ctypes.c_void_p),
            ))
            err = ctypes.get_errno()

            # Fallback: exec via /proc/self/fd/N (what glibc fexecve does internally)
            fd_path = f"/proc/self/fd/{fd}".encode()
            ret = int(libc.syscall(
                ctypes.c_long(59),  # SYS_execve
                ctypes.cast(ctypes.c_char_p(fd_path), ctypes.c_void_p),
                ctypes.cast(argv_c, ctypes.c_void_p),
                ctypes.cast(envp_c, ctypes.c_void_p),
            ))
            err = ctypes.get_errno()
            print(f"[memfd-child] execve fallback returned {ret}: {os.strerror(err)}",
                  file=sys.stderr)
            os._exit(127)
        except Exception as e:
            print(f"[memfd-child] exception: {e}", file=sys.stderr)
            os._exit(127)

    else:
        _, status = os.waitpid(pid, 0)
        try:
            _syscall(SYS_close, fd)
        except Exception:
            pass
        if verbose:
            code = os.waitstatus_to_exitcode(status)
            print(f"[memfd] Child {pid} exited with code {code}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 memfd_exec.py <binary>")
        sys.exit(1)
    execute_from_memory(sys.argv[1])
