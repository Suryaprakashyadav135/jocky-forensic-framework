"""
JOCKY Framework --- Module: ELF Entry Point Mutation

Reads a compiled ELF binary (PIE, x86-64) and mutates its entry point
to point at a newly-written jump stub in the executable segment's tail
padding.

Effect:
  - Original: e_entry = 0x1150 (points at _start in .text)
  - After:    e_entry = <cave> (points at our stub)
  - The stub is a 5-byte relative jump (E9 <rel32>) to the real _start

Every build produces a different e_entry value (the cave address is
randomized within the available padding), defeating entry-point-hash
signatures.

Usage:
  python3 elf_mutate.py <input_binary> [output_binary]
"""

import os
import random
import struct
import sys
from pathlib import Path

# ELF64 constants
ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_DYN = 3
EM_X86_64 = 62

# ELF64 header layout (64 bytes total)
# Offset  Size  Field
# 0x00    16    e_ident
# 0x10    2     e_type
# 0x12    2     e_machine
# 0x14    4     e_version
# 0x18    8     e_entry       ← we modify this
# 0x20    8     e_phoff
# 0x28    8     e_shoff
# 0x30    4     e_flags
# 0x34    2     e_ehsize
# 0x36    2     e_phentsize
# 0x38    2     e_phnum
# 0x3a    2     e_shentsize
# 0x3c    2     e_shnum
# 0x3e    2     e_shstrndx

ELF_HEADER_ENTRY_OFFSET = 0x18
ELF_HEADER_SIZE = 64


def read_elf_header(data: bytes) -> dict:
    """Parse the ELF64 header. Raise on invalid format."""
    if data[:4] != ELF_MAGIC:
        raise ValueError("Not an ELF file")
    if data[4] != ELFCLASS64:
        raise ValueError("Not ELF64")
    if data[5] != ELFDATA2LSB:
        raise ValueError("Not little-endian")

    e_type = struct.unpack_from("<H", data, 0x10)[0]
    e_machine = struct.unpack_from("<H", data, 0x12)[0]
    e_entry = struct.unpack_from("<Q", data, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]

    return {
        "e_type": e_type,
        "e_machine": e_machine,
        "e_entry": e_entry,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
    }


def parse_program_headers(data: bytes, header: dict) -> list:
    """
    Parse program headers. Return list of dicts.
    ELF64 program header:
      p_type   (4)
      p_flags  (4)
      p_offset (8)
      p_vaddr  (8)
      p_paddr  (8)
      p_filesz (8)
      p_memsz  (8)
      p_align  (8)
    """
    headers = []
    for i in range(header["e_phnum"]):
        off = header["e_phoff"] + i * header["e_phentsize"]
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        headers.append({
            "type": p_type,
            "flags": p_flags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "paddr": p_paddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
        })
    return headers


def find_executable_load_segment(phdrs: list) -> dict:
    """Find the LOAD segment with execute flag (PF_X = 0x1)."""
    for ph in phdrs:
        if ph["type"] == 1 and (ph["flags"] & 0x1):  # PT_LOAD + PF_X
            return ph
    return None


def find_code_cave(data: bytes, exec_seg: dict, phdrs: list,
                    size_needed: int = 16) -> dict:
    """
    Find space in the executable segment for our jump stub.

    Strategy:
      1. Prefer trailing nulls inside the current segment.
      2. If none, extend the segment up to the next page boundary and
         use that gap. This requires updating p_filesz / p_memsz.
    """
    seg_start = exec_seg["offset"]
    seg_end = seg_start + exec_seg["filesz"]

    # --- Attempt 1: trailing nulls inside the segment ---
    i = seg_end - 1
    trailing_nulls = 0
    while i >= seg_start and data[i] == 0x00:
        trailing_nulls += 1
        i -= 1

    if trailing_nulls >= size_needed:
        cave_file_offset = seg_end - trailing_nulls
        cave_vaddr = exec_seg["vaddr"] + (cave_file_offset - seg_start)
        return {
            "file_offset": cave_file_offset,
            "vaddr": cave_vaddr,
            "size": trailing_nulls,
            "extended": False,
        }

    # --- Attempt 2: extend segment to the next page boundary ---
    # Compute how much padding exists between seg_end and the next page.
    PAGE = 0x1000
    next_page = ((seg_end + PAGE - 1) // PAGE) * PAGE

    # But we must not extend into another LOAD segment.
    # Find the next segment that starts after exec_seg.
    min_next_start = next_page
    for ph in phdrs:
        if ph is exec_seg:
            continue
        if ph["type"] != 1:  # PT_LOAD
            continue
        if ph["offset"] > seg_end and ph["offset"] < min_next_start:
            min_next_start = ph["offset"]

    available = min_next_start - seg_end
    if available < size_needed:
        return None

    # Cave is right after the current segment end
    cave_file_offset = seg_end
    cave_vaddr = exec_seg["vaddr"] + (cave_file_offset - seg_start)

    return {
        "file_offset": cave_file_offset,
        "vaddr": cave_vaddr,
        "size": available,
        "extended": True,
        "new_filesz": exec_seg["filesz"] + available,
    }

def build_jump_stub(cave_vaddr: int, target_vaddr: int) -> bytes:
    """
    Build a 5-byte relative jump: E9 <rel32>
    rel32 = target - (cave_vaddr + 5)
    """
    rel = target_vaddr - (cave_vaddr + 5)
    if not (-2**31 <= rel < 2**31):
        raise ValueError(f"Jump displacement out of range: {rel}")
    return b"\xe9" + struct.pack("<i", rel)


def mutate_entry_point(binary_path: str, output_path: str = None,
                        verbose: bool = True) -> dict:
    """
    Mutate the entry point of an ELF binary.

    Returns a dict with mutation details.
    """
    input_path = Path(binary_path)
    if not input_path.exists():
        raise FileNotFoundError(binary_path)

    if output_path is None:
        output_path = str(input_path)
    output_path = Path(output_path)

    data = bytearray(input_path.read_bytes())

    # Parse
    header = read_elf_header(data)
    if header["e_type"] != ET_DYN:
        raise ValueError(f"Expected ET_DYN (PIE), got {header['e_type']}")
    if header["e_machine"] != EM_X86_64:
        raise ValueError(f"Expected x86-64, got {header['e_machine']}")

    original_entry = header["e_entry"]

    if verbose:
        print(f"[elf-mut] Input: {input_path}")
        print(f"[elf-mut] Original e_entry: {hex(original_entry)}")

    # Locate executable segment
    phdrs = parse_program_headers(data, header)
    exec_seg = find_executable_load_segment(phdrs)
    if exec_seg is None:
        raise ValueError("No executable LOAD segment found")

    if verbose:
        print(f"[elf-mut] Exec segment: vaddr={hex(exec_seg['vaddr'])}, "
              f"offset={hex(exec_seg['offset'])}, filesz={hex(exec_seg['filesz'])}")

    # Find code cave
    cave = find_code_cave(data, exec_seg, phdrs, size_needed=16)
    if cave is None:
        raise ValueError("No suitable code cave found in exec segment")

    # If we had to extend the segment, update its p_filesz and p_memsz
    if cave.get("extended"):
        # Find the program header index for exec_seg
        ph_index = phdrs.index(exec_seg)
        ph_file_offset = header["e_phoff"] + ph_index * header["e_phentsize"]
        # p_filesz is at offset +0x20 in the program header
        # p_memsz is at offset +0x28
        new_filesz = cave["new_filesz"]
        new_memsz = cave["new_filesz"]  # assume same as filesz for text
        struct.pack_into("<Q", data, ph_file_offset + 0x20, new_filesz)
        struct.pack_into("<Q", data, ph_file_offset + 0x28, new_memsz)
        if verbose:
            print(f"[elf-mut] Extended exec segment to filesz={hex(new_filesz)}")
    if verbose:
        print(f"[elf-mut] Code cave: file_off={hex(cave['file_offset'])}, "
              f"vaddr={hex(cave['vaddr'])}, size={cave['size']}")

    # Randomize the cave offset a bit within the available space
    # (Leave room for 5-byte stub; jitter within the cave.)
    max_jitter = max(0, cave["size"] - 16)
    jitter = random.randint(0, max_jitter) if max_jitter > 0 else 0
    stub_file_offset = cave["file_offset"] + jitter
    stub_vaddr = cave["vaddr"] + jitter

    # Build the jump stub
    stub = build_jump_stub(stub_vaddr, original_entry)

    if verbose:
        print(f"[elf-mut] Stub at vaddr={hex(stub_vaddr)}, "
              f"jump to {hex(original_entry)}")
        print(f"[elf-mut] Stub bytes: {stub.hex()}")

    # Write stub into the file at the cave offset
    data[stub_file_offset:stub_file_offset + len(stub)] = stub

    # Patch e_entry in the ELF header
    struct.pack_into("<Q", data, ELF_HEADER_ENTRY_OFFSET, stub_vaddr)

    # Write output
    output_path.write_bytes(bytes(data))

    # Make executable
    os.chmod(output_path, 0o755)

    if verbose:
        print(f"[elf-mut] New e_entry: {hex(stub_vaddr)}")
        print(f"[elf-mut] Output: {output_path}")

    return {
        "original_entry": original_entry,
        "new_entry": stub_vaddr,
        "stub_file_offset": stub_file_offset,
        "stub_bytes": stub.hex(),
        "output": str(output_path),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 elf_mutate.py <input_binary> [output_binary]")
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None

    result = mutate_entry_point(inp, out, verbose=True)
    print()
    print("=== Mutation result ===")
    for k, v in result.items():
        print(f"  {k}: {v}")
