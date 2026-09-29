"""
JOCKY Framework --- Module: Dynamic Symbol Table Augmentation

Adds randomized dummy symbols to the ELF dynamic symbol table of a
compiled binary. The dummy symbols are never looked up, never called,
and never referenced by any relocation --- they exist purely to change
the byte pattern of the .dynsym section on every build.

This alters the "import table" fingerprint that static scanners
use to identify binaries.

Uses objcopy under the hood (part of binutils, available on all Linux).

Usage:
    python3 dynsym_inject.py <binary> [num_symbols]

Default num_symbols: 5
"""

import os
import random
import string
import subprocess
import sys
from pathlib import Path


# Symbol names that look like legitimate runtime scaffolding
LEGITIMATE_PREFIXES = [
    "_ITM_",
    "__cxa_",
    "__gmon_",
    "_dl_",
    "_edata",
    "_end",
    "__bss_start",
    "__data_start",
    "__dso_handle",
    "_Jv_RegisterClasses",
    "_fini",
    "_init",
    "_start",
]

# Legitimate-looking suffix patterns
SUFFIX_CHARS = string.ascii_lowercase + string.digits


def random_symbol_name() -> str:
    """Generate a symbol name that blends with legitimate runtime symbols."""
    prefix = random.choice(LEGITIMATE_PREFIXES)
    suffix = "".join(random.choices(SUFFIX_CHARS, k=random.randint(4, 10)))
    return f"{prefix}{suffix}"


def inject_dummy_symbols(binary_path: str, num: int = 5, verbose: bool = True) -> dict:
    """
    Inject `num` dummy symbols into the .dynsym table.

    Returns a dict with details of what was added.
    """
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(binary_path)

    symbols = []
    objcopy_args = ["objcopy"]

    for i in range(num):
        name = random_symbol_name()
        # Place it at a plausible .text address (all offsets valid; never called)
        offset = random.randint(0x1000, 0x1f00)
        objcopy_args.append(f"--add-symbol={name}=.text:0x{offset:x}")
        symbols.append({"name": name, "offset": f"0x{offset:x}"})

    objcopy_args.append(str(path))

    if verbose:
        print(f"[dynsym] Injecting {num} dummy symbols into {path.name}")
        for s in symbols:
            print(f"  + {s['name']} -> .text:{s['offset']}")

    result = subprocess.run(
        objcopy_args,
        capture_output=True, text=True, check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(f"objcopy failed: {result.stderr}")

    if verbose:
        print(f"[dynsym] Injection complete")

    return {
        "binary": str(path),
        "symbols_added": len(symbols),
        "symbols": symbols,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 dynsym_inject.py <binary> [num_symbols]")
        sys.exit(1)

    binary = sys.argv[1]
    num = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    result = inject_dummy_symbols(binary, num, verbose=True)
    print()
    print("=== Result ===")
    for k, v in result.items():
        if k != "symbols":
            print(f"  {k}: {v}")
