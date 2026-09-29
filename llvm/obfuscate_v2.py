"""
JOCKY Obfuscation Pass --- applied to LLVM IR after codegen.

Applies classic O-LLVM style transformations that are safe on the
IR produced by codegen_v2.py:

  1. Bogus Control Flow Around Calls
     Split each block containing a call. Insert a conditional branch
     with an always-false predicate. One branch goes to a "bogus"
     block that does dead work and rejoins. The other branch goes to
     the continuation block with the original call.

     Every created block has exactly one terminator.
     Every created block has a predecessor.

  2. Dead Instruction Injection
     Add unused arithmetic chains after loads/allocas. These
     instructions never execute in a meaningful way but appear in
     the IR, changing bytecode signatures.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import llvmlite.ir as ir


def _opname(instr):
    """Return the opcode string (e.g. 'call', 'load', 'br', 'ret')."""
    if hasattr(instr, "opname"):
        return instr.opname
    return type(instr).__name__.lower()


# ---------------------------------------------------------------
# Transformation 1: Bogus Control Flow Around Calls
# ---------------------------------------------------------------

def insert_bogus_around_calls(func: ir.Function) -> int:
    """
    Split each block containing a call. Insert a conditional branch
    with an always-false predicate. One branch goes to a "bogus"
    block that does dead work and rejoins. The other branch goes to
    the continuation block with the original call.
    """
    inserted = 0
    i64 = ir.IntType(64)

    for block in list(func.blocks):
        if any(tag in block.name for tag in
               ("bogus_", "dispatcher", "cont_")):
            continue

        # Find the first call in this block
        first_call = None
        for instr in block.instructions:
            if _opname(instr) == "call":
                first_call = instr
                break

        if first_call is None:
            continue

        # Skip if we've already obfuscated this block
        if getattr(block, "_jocky_done", False):
            continue

        try:

            # --- 1. Detach all instructions from first_call onward ---
            idx = block.instructions.index(first_call)
            detached = list(block.instructions[idx:])

            # Remove each from the original block
            for d in detached:
                d.parent = None
            # --- 2. Create the new blocks (empty) ---
            bogus_block = func.append_basic_block(
                name=f"bogus_{inserted}_{random.randint(100, 999)}")
            cont_block = func.append_basic_block(
                name=f"cont_{inserted}_{random.randint(100, 999)}")

            # --- 3. In the original block, insert the always-false
            #        condition and cbranch. The block now has no
            #        terminator (we detached it), so this is safe. ---
            b1 = ir.IRBuilder(block)
            zero = ir.Constant(i64, 0)
            one = ir.Constant(i64, 1)
            cond = b1.icmp_unsigned("==", zero, one,
                                    name=f"bogus_cond_{inserted}")
            b1.cbranch(cond, bogus_block, cont_block)

            # --- 4. Attach the detached instructions to cont_block ---
            for d in detached:
                cont_block.instructions.append(d)

            # --- 5. Build the bogus_block: dead work, then jump to
            #        cont_block ---
            bb = ir.IRBuilder(bogus_block)
            a = bb.alloca(i64, name=f"bogus_a_{inserted}")
            bb.store(ir.Constant(i64, random.randint(1, 2**30)), a)
            v = bb.load(a)
            w = bb.add(v, ir.Constant(i64, random.randint(1, 1000)),
                       name=f"bogus_w_{inserted}")
            x = bb.mul(w, ir.Constant(i64, 2),
                       name=f"bogus_x_{inserted}")
            bb.branch(cont_block)

            block._jocky_done = True
            inserted += 1
        except Exception as e:
            import traceback
            print(f"  [obf-error] {type(e).__name__}: {e!r}",
                  file=sys.stderr)
            traceback.print_exc()
            continue

    return inserted
# ---------------------------------------------------------------
# Transformation 2: Dead Instruction Injection
# ---------------------------------------------------------------

def inject_dead_instructions(func: ir.Function) -> int:
    """
    For each block, after the first 'load' or 'alloca', insert a
    short chain of unused arithmetic. These instructions appear in
    the binary but their results are never used.
    """
    injected = 0
    i64 = ir.IntType(64)

    for block in func.blocks:
        if any(tag in block.name for tag in ("bogus", "dispatcher")):
            continue

        # Find first load or alloca
        anchor = None
        for instr in block.instructions:
            if _opname(instr) in ("load", "alloca"):
                anchor = instr
                break

        if anchor is None:
            continue

        try:
            builder = ir.IRBuilder(anchor)
            for i in range(random.randint(1, 3)):
                v = ir.Constant(i64, random.randint(1, 10000))
                _ = builder.mul(v, ir.Constant(i64, 3),
                                name=f"dead_mul_{injected}_{i}")
            injected += 1
        except Exception:
            continue

    return injected


# ---------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------

def obfuscate_module(module: ir.Module, verbose: bool = False):
    """Apply obfuscation to every function except runtime shims."""
    totals = {"bogus_around_calls": 0, "dead_instructions": 0}

    for func in module.functions:
        if len(func.blocks) == 0:
            continue

        # Skip the C runtime shim
        if func.name == "jocky_cmd":
            continue

        try:
            b = insert_bogus_around_calls(func)
            d = inject_dead_instructions(func)
            totals["bogus_around_calls"] += b
            totals["dead_instructions"] += d

            if verbose and (b + d) > 0:
                print(f"  [obf] {func.name}: bogus_calls={b}, dead={d}",
                      file=sys.stderr)
        except Exception as e:
            if verbose:
                print(f"  [obf] {func.name}: ERROR {e}", file=sys.stderr)

    return totals
