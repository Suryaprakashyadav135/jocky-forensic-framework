"""
JOCKY Framework — Module 8: Direct Syscalls (Linux x86-64)

Invokes Linux syscalls directly via the `syscall` instruction, bypassing
libc entirely. Demonstrates the "direct system calls" technique from the
problem statement.

Why this matters for detection evasion:
  - AV/EDR on Linux often hooks libc (open, read, write, execve)
  - Calling syscall() directly from user code skips those hooks
  - Common in modern Linux malware and rootkits

Technique:
  1. mmap() a small RWX page
  2. Write a tiny `syscall; ret` stub into it (or use the `syscall` instruction
     via ctypes with a handcrafted function pointer)
  3. Call it with the desired syscall number and args in the right registers

For simplicity, we use a well-known technique: mmap an executable page,
populate it with the raw bytes of `syscall; ret`, and call it via ctypes.
"""

import ctypes
import mmap
import os
import sys


# x86-64 syscall numbers (subset)
SYS_read    = 0
SYS_write   = 1
SYS_close   = 3
SYS_mmap    = 9
SYS_munmap  = 11
SYS_getpid  = 39
SYS_getuid  = 102
SYS_exit    = 60
SYS_uname   = 63


# The raw x86-64 instructions for a bare syscall stub:
#   0F 05        syscall
#   C3           ret

# Full 6-arg syscall stub:
#   mov rax, rdi        ; syscall number from first arg
#   mov rdi, rsi        ; arg1
#   mov rsi, rdx        ; arg2
#   mov rdx, rcx        ; arg3
#   mov r10, r8         ; arg4
#   mov r8,  r9         ; arg5
#   (arg6 not supported in this demo stub)
#   syscall
#   ret
SYSCALL_STUB = bytes([
    0x48, 0x89, 0xF8,   # mov rax, rdi
    0x48, 0x89, 0xF7,   # mov rdi, rsi
    0x48, 0x89, 0xD6,   # mov rsi, rdx
    0x48, 0x89, 0xCA,   # mov rdx, rcx
    0x4D, 0x89, 0xC2,   # mov r10, r8
    0x4D, 0x89, 0xC8,   # mov r8,  r9
    0x0F, 0x05,         # syscall
    0xC3,               # ret
])

class DirectSyscall:
    """Execute Linux syscalls by calling raw `syscall; ret` from mmap'd RWX memory."""

    def __init__(self):
        # Allocate RWX memory via Python's mmap (uses mmap syscall under the hood)
        self._page = mmap.mmap(
            -1, 4096,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        )
        # Write the syscall;ret stub
        self._page.write(SYSCALL_STUB)
        # Get the buffer address
        self._addr = ctypes.addressof(ctypes.c_char.from_buffer(self._page))

        # Create a ctypes function pointer that takes 6 args
        # Syscall convention on Linux x86-64:
        #   rax = syscall number
        #   rdi, rsi, rdx, r10, r8, r9 = args 1..6
        PROTOTYPE = ctypes.CFUNCTYPE(
            ctypes.c_long,      # return
            ctypes.c_long,      # syscall number
            ctypes.c_long, ctypes.c_long, ctypes.c_long,
            ctypes.c_long, ctypes.c_long, ctypes.c_long,
        )
        self._syscall = PROTOTYPE(self._addr)

    def call(self, num: int, a1: int = 0, a2: int = 0, a3: int = 0,
             a4: int = 0, a5: int = 0, a6: int = 0) -> int:
        """Invoke a raw syscall."""
        ret = self._syscall(num, a1, a2, a3, a4, a5, a6)
        # Negative returns indicate -errno
        if ret < 0 and ret > -4096:
            err = -ret
            raise OSError(err, f"syscall {num} failed: {os.strerror(err)}")
        return ret


# ---------- Demo ----------
def demo():
    print("=" * 70)
    print("JOCKY Direct Syscall Demo — bypassing libc")
    print("=" * 70)

    ds = DirectSyscall()
    print(f"[*] RWX stub mapped at: 0x{ds._addr:x}")
    print(f"[*] Stub bytes: {SYSCALL_STUB.hex()}")
    print()

    # syscall: getpid
    pid = ds.call(SYS_getpid)
    print(f"[syscall] getpid()  = {pid}")
    print(f"[verify]  os.getpid() = {os.getpid()}")
    assert pid == os.getpid(), "getpid mismatch!"
    print("  ✓ direct syscall matches libc wrapper")
    print()

    # syscall: getuid
    uid = ds.call(SYS_getuid)
    print(f"[syscall] getuid()  = {uid}")
    print(f"[verify]  os.getuid() = {os.getuid()}")
    assert uid == os.getuid(), "getuid mismatch!"
    print("  ✓ direct syscall matches libc wrapper")
    print()

    # syscall: write to stdout (fd=1)
    msg = b"[syscall] write() via raw syscall -- this message bypassed libc\n"
    buf = ctypes.create_string_buffer(msg, len(msg))
    ptr = ctypes.addressof(buf)
    written = ds.call(SYS_write, 1, ptr, len(msg))
    print(f"  ✓ wrote {written} bytes directly to fd 1")
    print()

    print("[OK] All syscalls executed via raw `syscall;ret` — libc bypassed")


if __name__ == "__main__":
    demo()
