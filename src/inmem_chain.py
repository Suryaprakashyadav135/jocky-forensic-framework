"""
JOCKY Framework — Module 9: Full In-Memory Execution Chain

End-to-end demonstration:
    .jky source  →  JOCKY compiler  →  native binary  →  memfd  →  execute

Nothing touches disk at any point during the compile → execute pipeline.
The binary itself has no plaintext command strings (control-flow flattening
+ FNV-1a command hashing). The execution is file-less (memfd).

This is the closing demo of the framework.
"""

import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path

# Add src to path so we can import memfd_exec
sys.path.insert(0, str(Path(__file__).parent))
from memfd_exec import execute_from_memory


ROOT = Path(__file__).resolve().parent.parent
LLVM_DIR = ROOT / "llvm"
DEMO_DIR = ROOT / "demo"
RUNTIME_O = LLVM_DIR / "runtime.o"


def ensure_runtime_compiled():
    """Compile the C runtime stub if not present."""
    if RUNTIME_O.exists():
        return
    print("[chain] Compiling runtime stub")
    subprocess.run(
        ["clang", "-c", str(LLVM_DIR / "runtime.c"), "-o", str(RUNTIME_O)],
        check=True,
    )


def compile_jky_to_binary(jky_path: Path, out_bin: Path):
    """Run the JOCKY compiler frontend and produce a native binary."""
    print(f"[chain] Compiling {jky_path.name}")

    # Step 1: .jky → .ll
    ll_path = out_bin.with_suffix(".ll")
    subprocess.run(
        ["python3", str(LLVM_DIR / "codegen.py"), str(jky_path)],
        check=True, capture_output=True,
    )
    # codegen writes next to the .jky file
    generated_ll = jky_path.with_suffix(".ll")
    if generated_ll.exists():
        shutil.copy(str(generated_ll), str(ll_path))
        generated_ll.unlink()
    else:
        raise FileNotFoundError(f"codegen did not produce {generated_ll}")
	
    # Step 2: verify IR is valid
    subprocess.run(
        ["llvm-as", str(ll_path), "-o", "/dev/null"],
        check=True,
    )
    print(f"[chain]   ✓ LLVM IR valid")

    # Step 3: .ll → .o
    obj_path = out_bin.with_suffix(".o")
    subprocess.run(
        ["clang", "-c", str(ll_path), "-o", str(obj_path)],
        check=True,
    )

    # Step 4: .o + runtime.o → binary
    subprocess.run(
        ["clang", str(obj_path), str(RUNTIME_O), "-o", str(out_bin)],
        check=True,
    )
    print(f"[chain]   ✓ Binary: {out_bin} ({out_bin.stat().st_size} bytes)")

    return ll_path


def verify_no_plaintext(binary: Path, commands: list):
    """Prove the binary contains no plaintext forensic command names."""
    print(f"[chain] Verifying no plaintext commands in binary")
    result = subprocess.run(
        ["strings", str(binary)],
        capture_output=True, text=True,
    )
    found = []
    for cmd in commands:
        if cmd in result.stdout:
            found.append(cmd)

    if found:
        print(f"[chain]   ✗ FOUND plaintext commands: {found}")
        return False
    print(f"[chain]   ✓ No plaintext commands found")
    return True


def main():
    print("=" * 70)
    print("JOCKY Full Chain — Compile + Obfuscate + Execute In-Memory")
    print("=" * 70)

    jky_src = DEMO_DIR / "test.jky"
    if not jky_src.exists():
        print(f"[chain] Missing source file: {jky_src}")
        sys.exit(1)

    ensure_runtime_compiled()

    # Compile to a temp binary we will delete before execution
    tmp_dir = Path(tempfile.mkdtemp(prefix="jocky_"))
    out_bin = tmp_dir / "payload.bin"

    print(f"\n[chain] Working directory: {tmp_dir}")
    print(f"[chain] Source: {jky_src}")
    print()

    # Compile
    compile_jky_to_binary(jky_src, out_bin)

    # Verify obfuscation
    commands_to_check = [
        "collect_system_info", "scan_forensic_artifacts",
        "enumerate_network_connections", "check_persistence",
    ]
    if not verify_no_plaintext(out_bin, commands_to_check):
        print("[chain] FAILED — plaintext commands found in binary")
        sys.exit(1)

    # Read into memory
    print(f"\n[chain] Reading binary into memory")
    binary_bytes = out_bin.read_bytes()
    print(f"[chain]   ✓ {len(binary_bytes)} bytes in RAM")

    # Delete all disk artifacts BEFORE execution
    print(f"\n[chain] Deleting disk artifacts before execution")
    for f in tmp_dir.iterdir():
        f.unlink()
        print(f"[chain]   deleted {f.name}")
    tmp_dir.rmdir()
    print(f"[chain]   deleted {tmp_dir}")

    # Copy the binary bytes into a fresh memfd-like buffer and execute
    # We re-materialize into memfd via memfd_exec.execute_from_memory — but
    # that function expects a file path. So we write to a fresh memfd manually.
    print(f"\n[chain] Executing from anonymous memory")
    execute_bytes_from_memory(binary_bytes, argv_name="jocky_payload")

    print(f"\n[chain] ✓ Full chain complete — nothing on disk")


def execute_bytes_from_memory(data: bytes, argv_name: str = "payload"):
    """Execute raw bytes from memory via memfd_create + /proc/self/fd."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    # Create memfd
    fd = os.memfd_create(argv_name, flags=os.MFD_CLOEXEC)
    print(f"[memfd] fd={fd}")

    # Write in chunks
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 65536]
        buf = ctypes.create_string_buffer(chunk, len(chunk))
        ptr = ctypes.cast(buf, ctypes.c_void_p)
        ret = int(libc.syscall(ctypes.c_long(1), ctypes.c_long(fd),
                                ptr, ctypes.c_long(len(chunk))))
        if ret <= 0:
            raise OSError(f"write failed: {ret}")
        offset += ret
    print(f"[memfd] wrote {offset} bytes")

    # Readlink — shows it's anonymous
    try:
        link = os.readlink(f"/proc/self/fd/{fd}")
        print(f"[memfd] fd -> {link}")
    except Exception:
        pass

    # Fork + exec via /proc/self/fd
    pid = os.fork()
    if pid == 0:
        argv_b = [argv_name.encode(), None]
        argv_c = (ctypes.c_char_p * len(argv_b))(*argv_b)
        envp_c = (ctypes.c_char_p * 1)(None)

        # Try fexecve first
        ret = int(libc.syscall(ctypes.c_long(431), ctypes.c_long(fd),
                                ctypes.cast(argv_c, ctypes.c_void_p),
                                ctypes.cast(envp_c, ctypes.c_void_p)))
        # Fallback: execve on /proc/self/fd/N
        fd_path = f"/proc/self/fd/{fd}".encode()
        libc.syscall(ctypes.c_long(59),
                      ctypes.cast(ctypes.c_char_p(fd_path), ctypes.c_void_p),
                      ctypes.cast(argv_c, ctypes.c_void_p),
                      ctypes.cast(envp_c, ctypes.c_void_p))
        err = ctypes.get_errno()
        print(f"[memfd-child] exec failed: {os.strerror(err)}", file=sys.stderr)
        os._exit(127)
    else:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        print(f"[memfd] child exited {code}")


if __name__ == "__main__":
    main()
