"""
JOCKY Language — V5.2 Compiler with Full Type System

Types:
    TInt     — i64
    TString  — pointer to JkyString (opaque i8* in IR)
    TArray   — pointer to JkyArray (opaque i8* in IR)

Runtime ABI:
    JkyString*  jky_read_file(const char*)
    JkyString*  jky_exec_cmd(const char*)
    JkyArray*   jky_list_dir(const char*)
    int64_t     jky_len_str(JkyString*)
    int64_t     jky_len_arr(JkyArray*)
    JkyString*  jky_index(JkyArray*, int64_t)
    JkyString*  jky_concat(JkyString*, JkyString*)
    void        jky_emit(const char*, JkyString*)

All types are erased to i8* in IR. The compiler tracks them.
Control-flow flattening (dispatcher pattern) is preserved.
"""

import sys
import random
import string as _string
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import llvmlite.ir as ir

sys.path.insert(0, str(Path(__file__).parent))
from parser import (
    Program, VarDecl, FnDecl, Command, Block, If, For, Return,
    Assign, ExprStmt, BinOp, IntLit, StrLit, Ident, Call, Index,
    While, Break, Continue,
)

# ============ Type System ============
class JType:
    """Base type marker."""
    pass

class TInt(JType):
    def __repr__(self): return "int"

class TString(JType):
    def __repr__(self): return "string"

class TArray(JType):
    def __repr__(self): return "array"

class TUnknown(JType):
    def __repr__(self): return "unknown"

T_INT = TInt()
T_STRING = TString()
T_ARRAY = TArray()
T_UNKNOWN = TUnknown()


# ============ AST Scan (for preallocation) ============
def scan(node, vars_out: set, counters: dict):
    """Collect var names + count flattened blocks."""
    if isinstance(node, Ident):
        vars_out.add(node.name)
    elif isinstance(node, VarDecl):
        vars_out.add(node.name)
        scan(node.value, vars_out, counters)
    elif isinstance(node, Assign):
        vars_out.add(node.target)
        scan(node.value, vars_out, counters)
    elif isinstance(node, FnDecl):
        vars_out.update(node.params)
        scan(node.body, vars_out, counters)
    elif isinstance(node, Block):
        if node.statements:
            counters["blocks"] += 1
        for s in node.statements:
            scan(s, vars_out, counters)
    elif isinstance(node, If):
        scan(node.condition, vars_out, counters)
        scan(node.then_block, vars_out, counters)
        if node.else_block:
            scan(node.else_block, vars_out, counters)
    elif isinstance(node, For):
        vars_out.add(node.var)
        scan(node.start, vars_out, counters)
        scan(node.end, vars_out, counters)
        scan(node.body, vars_out, counters)
    elif isinstance(node, Return):
        if node.value:
            scan(node.value, vars_out, counters)
    elif isinstance(node, ExprStmt):
        scan(node.expr, vars_out, counters)
    elif isinstance(node, BinOp):
        scan(node.left, vars_out, counters)
        scan(node.right, vars_out, counters)
    elif isinstance(node, Call):
        for a in node.args:
            scan(a, vars_out, counters)
    elif isinstance(node, Index):
        scan(node.target, vars_out, counters)
        scan(node.index, vars_out, counters)


# ============ Codegen ============
class CodeGenV2:
    def __init__(self, program: Program):
        self.program = program
        self.module = ir.Module(name="jocky_module")
        self.module.triple = "x86_64-pc-linux-gnu"
        # Loop context for break/continue
        self.loop_stack = []

        i64 = ir.IntType(64)
        i8p = ir.IntType(8).as_pointer()
        void = ir.VoidType()

        # Runtime function signatures
        # Runtime function names — overridable via JKY_SYMBOL_PREFIX
        import os as _os
        pfx = _os.environ.get("JKY_SYMBOL_PREFIX", "")
        _suffix = {
            # Original 12
            "jky_read_file": "a", "jky_list_dir": "b",
            "jky_exec_cmd": "c", "jky_len_str": "d",
            "jky_len_arr": "e", "jky_index": "f",
            "jky_concat": "g", "jky_emit": "h",
            "jky_make_str": "i", "jky_int_to_str": "j",
            "jocky_cmd": "k", "jky_decode_str": "l",
            # Tier 1 primitives (22 new)
            "jky_file_exists": "m",
            "jky_file_size": "n",
            "jky_file_mtime": "o",
            "jky_read_file_lines": "p",
            "jky_read_bytes": "q",
            "jky_readlink": "r",
            "jky_substr": "s",
            "jky_split": "t",
            "jky_find": "u",
            "jky_trim": "v",
            "jky_lower": "w",
            "jky_upper": "x",
            "jky_to_int": "y",
            "jky_replace": "z",
            "jky_starts_with": "A",
            "jky_ends_with": "B",
            "jky_append": "C",
            "jky_contains": "D",
            "jky_getenv": "E",
            "jky_getpid": "F",
            "jky_getuid": "G",
            "jky_getcwd": "H",
            # Tier 2 (maps, regex, io)
            "jky_map_new": "I",
            "jky_map_set": "J",
            "jky_map_get": "K",
            "jky_map_has": "L",
            "jky_map_size": "M",
            "jky_map_key_at": "N",
            "jky_map_val_at": "O",
            "jky_build_string": "P",
            "jky_match": "Q",
            "jky_regex_test": "R",
            "jky_write_file": "S",
            "jky_append_file": "T",
            "jky_sleep": "U",
            "jky_json_escape": "V",
            # Tier 3
            "jky_sort": "W",
            "jky_reverse": "X",
            "jky_slice": "Y",
            "jky_unique": "Z",
            "jky_join": "1",
            "jky_base64_encode": "2",
            "jky_base64_decode": "3",
            "jky_hex_encode": "4",
            "jky_hex_decode": "5",
            "jky_sha256_file": "6",
            "jky_str_eq": "9",
            "jky_sha256_string": "7",
            "jky_str_len_bytes": "8",
        }
        def rn(base):
            return f"{pfx}_{_suffix[base]}" if pfx else base

        self.rt = {
            "make_str":  ir.Function(self.module, ir.FunctionType(i8p, [i8p]), name=rn("jky_make_str")),
            "decode_str": ir.Function(self.module, ir.FunctionType(i8p, [i8p, i64, i64]), name=rn("jky_decode_str")),            "read_file": ir.Function(self.module, ir.FunctionType(i8p, [i8p]), name=rn("jky_read_file")),
            # Tier 1 primitives
            "file_exists": ir.Function(self.module,
                ir.FunctionType(i64, [i8p]), name=rn("jky_file_exists")),
            "file_size": ir.Function(self.module,
                ir.FunctionType(i64, [i8p]), name=rn("jky_file_size")),
            "file_mtime": ir.Function(self.module,
                ir.FunctionType(i64, [i8p]), name=rn("jky_file_mtime")),
            "read_file_lines": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_read_file_lines")),
            "read_bytes": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i64, i64]),
                name=rn("jky_read_bytes")),
            "readlink": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_readlink")),
            "substr": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i64, i64]),
                name=rn("jky_substr")),
            "split": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p]), name=rn("jky_split")),
            "find": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]), name=rn("jky_find")),
            "trim": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_trim")),
            "lower": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_lower")),
            "upper": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_upper")),
            "to_int": ir.Function(self.module,
                ir.FunctionType(i64, [i8p]), name=rn("jky_to_int")),
            "replace": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p, i8p]),
                name=rn("jky_replace")),
            "starts_with": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]),
                name=rn("jky_starts_with")),
            "ends_with": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]),
                name=rn("jky_ends_with")),
            "append": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p]), name=rn("jky_append")),
            "contains": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]), name=rn("jky_contains")),
            "getenv": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_getenv")),
            "getpid": ir.Function(self.module,
                ir.FunctionType(i64, []), name=rn("jky_getpid")),
            "getuid": ir.Function(self.module,
                ir.FunctionType(i64, []), name=rn("jky_getuid")),
            "getcwd": ir.Function(self.module,
                ir.FunctionType(i8p, []), name=rn("jky_getcwd")), 
            # Tier 2
            "map_new": ir.Function(self.module,
                ir.FunctionType(i8p, []), name=rn("jky_map_new")),
            "map_set": ir.Function(self.module,
                ir.FunctionType(void, [i8p, i8p, i8p]),
                name=rn("jky_map_set")),
            "map_get": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p]), name=rn("jky_map_get")),
            "map_has": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]), name=rn("jky_map_has")),
            "map_size": ir.Function(self.module,
                ir.FunctionType(i64, [i8p]), name=rn("jky_map_size")),
            "map_key_at": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i64]), name=rn("jky_map_key_at")),
            "map_val_at": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i64]), name=rn("jky_map_val_at")),
            "build_string": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p]),
                name=rn("jky_build_string")),
            "match": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p]), name=rn("jky_match")),
            "regex_test": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]),
                name=rn("jky_regex_test")),
            "write_file": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]),
                name=rn("jky_write_file")),
            "append_file": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]),
                name=rn("jky_append_file")),
            "sleep": ir.Function(self.module,
                ir.FunctionType(void, [i64]), name=rn("jky_sleep")),
            "json_escape": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_json_escape")),
            # Tier 3 signatures
            "sort": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_sort")),
            "reverse": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_reverse")),
            "slice": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i64, i64]), name=rn("jky_slice")),
            "unique": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_unique")),
            "join": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p, i8p]), name=rn("jky_join")),
            "base64_encode": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_base64_encode")),
            "base64_decode": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_base64_decode")),
            "hex_encode": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_hex_encode")),
            "hex_decode": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_hex_decode")),
            "sha256_file": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_sha256_file")),
            "sha256_string": ir.Function(self.module,
                ir.FunctionType(i8p, [i8p]), name=rn("jky_sha256_string")),
            "str_eq": ir.Function(self.module,
                ir.FunctionType(i64, [i8p, i8p]), name=rn("jky_str_eq")),           
	    "str_len_bytes": ir.Function(self.module,
                ir.FunctionType(i64, [i8p]), name=rn("jky_str_len_bytes")),
	    "exec_cmd":  ir.Function(self.module, ir.FunctionType(i8p, [i8p]), name=rn("jky_exec_cmd")),
            "list_dir":  ir.Function(self.module, ir.FunctionType(i8p, [i8p]), name=rn("jky_list_dir")),
            "len_str":   ir.Function(self.module, ir.FunctionType(i64, [i8p]), name=rn("jky_len_str")),
            "len_arr":   ir.Function(self.module, ir.FunctionType(i64, [i8p]), name=rn("jky_len_arr")),
            "index":     ir.Function(self.module, ir.FunctionType(i8p, [i8p, i64]), name=rn("jky_index")),
            "concat":    ir.Function(self.module, ir.FunctionType(i8p, [i8p, i8p]), name=rn("jky_concat")),
            "emit":      ir.Function(self.module, ir.FunctionType(void, [i8p, i8p]), name=rn("jky_emit")),
            "int_to_str": ir.Function(self.module, ir.FunctionType(i8p, [i64]), name=rn("jky_int_to_str")),
            "cmd":       ir.Function(self.module, ir.FunctionType(i64, [i64, i64, i64.as_pointer()]), name=rn("jocky_cmd")),
        }
        self.functions: Dict[str, ir.Function] = {}
        self.entry_builder: Optional[ir.IRBuilder] = None
        # name -> (alloca, JType)
        self.symbols: Dict[str, Tuple[ir.AllocaInstr, JType]] = {}
        self.state_slots: List[ir.AllocaInstr] = []
        self.state_idx = 0
        self.cmd_arg_slots: List[ir.AllocaInstr] = []
        self.cmd_idx = 0
        self.name_map: Dict[str, str] = {}

        # Global string literals cache (i8* -> alloca)
        self.string_literals: Dict[str, ir.GlobalVariable] = {}

    # ---------- Literal helper ----------

    def _make_string_literal(self, value: str) -> ir.Constant:
        """Create a global constant for an XOR-encoded string literal.

        The plaintext never appears in the binary's .rodata. The bytes
        stored are `plaintext XOR key`. The runtime decodes on first use.
        """
        key = value
        if key not in self.string_literals:
            import random as _rnd
            # Pick a random non-zero single-byte XOR key
            xk = _rnd.randint(1, 255)
            # Encode: every byte XOR'd with xk
            plain = value.encode("utf-8")
            encoded = bytes([b ^ xk for b in plain])
            data = encoded + b"\x00"

            arr_type = ir.ArrayType(ir.IntType(8), len(data))
            gv = ir.GlobalVariable(
                self.module, arr_type,
                name=f"str_{len(self.string_literals)}")
            gv.global_constant = True
            gv.initializer = ir.Constant(arr_type, bytearray(data))
            gv.linkage = "internal"

            # Remember the key and length alongside the global
            self.string_literals[key] = (gv, xk, len(plain))

        gv, _xk, _len = self.string_literals[key]
        zero = ir.Constant(ir.IntType(32), 0)
        return gv.gep([zero, zero])
    # ---------- Preallocate ----------
    def _preallocate(self, func: ir.Function, root_node,
                     params: List[str] = None):
        i64 = ir.IntType(64)
        i8p = ir.IntType(8).as_pointer()

        vars_needed: set = set()
        counters = {"blocks": 0}
        scan(root_node, vars_needed, counters)

        entry = func.append_basic_block("entry")
        eb = ir.IRBuilder(entry)
        self.entry_builder = eb
        self.symbols = {}

        # Every variable gets an i8* slot (universal repr)
        for name in sorted(vars_needed):
            self.symbols[name] = (eb.alloca(i8p, name=f"{name}_slot"), T_UNKNOWN)

        # State slots for flattened blocks
        n_states = counters["blocks"] + 8
        self.state_slots = [eb.alloca(i64, name=f"st_{i}") for i in range(n_states)]
        self.state_idx = 0

        # Command arg buffers
        arr_type = ir.ArrayType(i64, 16)
        self.cmd_arg_slots = [eb.alloca(arr_type, name=f"ca_{i}") for i in range(16)]
        self.cmd_idx = 0

        # Store params
        if params:
            for i, pname in enumerate(params):
                slot, _ = self.symbols[pname]
                # Param arrives as i64 — bitcast to i8* for universal storage
                p_val = func.args[i]
                cast = eb.inttoptr(p_val, i8p, name=f"{pname}_cast")
                eb.store(cast, slot)

        body_entry = func.append_basic_block("body_entry")
        eb.branch(body_entry)
        return ir.IRBuilder(body_entry)

    def _next_state(self) -> ir.AllocaInstr:
        s = self.state_slots[self.state_idx]
        self.state_idx += 1
        return s

    def _next_cmd_buf(self) -> ir.AllocaInstr:
        s = self.cmd_arg_slots[self.cmd_idx]
        self.cmd_idx += 1
        return s

    # ---------- Symbol access ----------
    def _get_slot(self, name: str) -> ir.AllocaInstr:
        if name not in self.symbols:
            self.symbols[name] = (
                self.entry_builder.alloca(ir.IntType(8).as_pointer(),
                                           name=f"{name}_slot"),
                T_UNKNOWN,
            )
        return self.symbols[name][0]

    def _get_type(self, name: str) -> JType:
        if name in self.symbols:
            return self.symbols[name][1]
        return T_UNKNOWN

    def _set_type(self, name: str, t: JType):
        slot = self._get_slot(name)
        self.symbols[name] = (slot, t)

    # ---------- Top-level ----------
    def generate(self) -> ir.Module:
        # Randomize function names
        for d in self.program.declarations:
            if isinstance(d, FnDecl):
                self.name_map[d.name] = "f_" + "".join(
                    random.choices(_string.ascii_lowercase + _string.digits, k=12))

        for d in self.program.declarations:
            if isinstance(d, FnDecl):
                self._declare_fn(d)
        for d in self.program.declarations:
            if isinstance(d, FnDecl):
                self._generate_fn(d)
        self._generate_main()


        # Obfuscation hook disabled --- see llvm/obfuscate_v2.py prototype
        return self.module

    def _declare_fn(self, fn: FnDecl):
        i64 = ir.IntType(64)
        actual = self.name_map.get(fn.name, fn.name)
        func = ir.Function(self.module, fn_type, name=actual)
        for i, p in enumerate(fn.params):
            func.args[i].name = p
        self.functions[fn.name] = func

    def _generate_fn(self, fn: FnDecl):
        func = self.functions[fn.name]
        builder = self._preallocate(func, fn, params=fn.params)
        self._compile_block_flattened(builder, fn.body)
        if not builder.block.is_terminated:
            builder.ret(ir.Constant(ir.IntType(64), 0))

    def _generate_main(self):
        i64 = ir.IntType(64)
        main = ir.Function(self.module, ir.FunctionType(i64, []), name="main")
        top_stmts = [d for d in self.program.declarations
                     if not isinstance(d, FnDecl)]
        top_block = Block(statements=top_stmts)
        builder = self._preallocate(main, top_block)
        self._compile_block_flattened(builder, top_block)
        if not builder.block.is_terminated:
            builder.ret(ir.Constant(i64, 0))

    # ---------- Flattened block ----------
    def _compile_block_flattened(self, builder, block: Block):
        i64 = ir.IntType(64)
        if not block.statements:
            return

        state = self._next_state()
        builder.store(ir.Constant(i64, 0), state)

        n = len(block.statements)
        func = builder.function
        dispatcher = func.append_basic_block("dispatcher")
        stmt_blocks = [func.append_basic_block(f"s{i}") for i in range(n)]
        exit_b = func.append_basic_block("exit")

        builder.branch(dispatcher)
        builder.position_at_end(dispatcher)
        sv = builder.load(state, name="sv")
        for i in range(n):
            cmp = builder.icmp_unsigned("==", sv, ir.Constant(i64, i))
            nxt = func.append_basic_block(f"c{i+1}")
            builder.cbranch(cmp, stmt_blocks[i], nxt)
            builder.position_at_end(nxt)
            sv = builder.load(state, name=f"sv{i+1}")
        cmp_exit = builder.icmp_unsigned("==", sv, ir.Constant(i64, n))
        builder.cbranch(cmp_exit, exit_b, dispatcher)

        for i, stmt in enumerate(block.statements):
            builder.position_at_end(stmt_blocks[i])
            self._compile_stmt(builder, stmt)
            if not builder.block.is_terminated:
                builder.store(ir.Constant(i64, i + 1), state)
                builder.branch(dispatcher)

        builder.position_at_end(exit_b)

    # ---------- Statements ----------
    def _compile_stmt(self, builder, stmt):
        if isinstance(stmt, VarDecl):
            val, typ = self._compile_expr(builder, stmt.value)
            slot = self._get_slot(stmt.name)
            builder.store(self._to_i8p(builder, val), slot)
            self._set_type(stmt.name, typ)
        elif isinstance(stmt, Assign):
            val, typ = self._compile_expr(builder, stmt.value)
            slot = self._get_slot(stmt.target)
            builder.store(self._to_i8p(builder, val), slot)
            self._set_type(stmt.target, typ)
        elif isinstance(stmt, Command):
            self._compile_command(builder, stmt)
        elif isinstance(stmt, If):
            self._compile_if(builder, stmt)
        elif isinstance(stmt, For):
            self._compile_for(builder, stmt)
        elif isinstance(stmt, Return):
            if stmt.value is None:
                builder.ret(ir.Constant(ir.IntType(64), 0))
            else:
                val, _ = self._compile_expr(builder, stmt.value)
                builder.ret(self._to_i64(builder, val))
        elif isinstance(stmt, ExprStmt):
            self._compile_expr(builder, stmt.expr)
        elif isinstance(stmt, While):
            self._compile_while(builder, stmt)
        elif isinstance(stmt, Break):
            self._compile_break(builder)
        elif isinstance(stmt, Continue):
            self._compile_continue(builder)

    def _compile_command(self, builder, cmd: Command):
        i64 = ir.IntType(64)
        buf = self._next_cmd_buf()
        hashes = [self._str_hash(a) for a in cmd.args]
        for i, h in enumerate(hashes):
            idx = ir.Constant(ir.IntType(32), i)
            ep = builder.gep(buf, [ir.Constant(ir.IntType(32), 0), idx])
            builder.store(ir.Constant(i64, h), ep)
        ptr = builder.bitcast(buf, i64.as_pointer())
        builder.call(self.rt["cmd"], [
            ir.Constant(i64, self._str_hash(cmd.name)),
            ir.Constant(i64, len(hashes)),
            ptr,
        ])

    def _compile_if(self, builder, node: If):
        i64 = ir.IntType(64)
        cond, ctyp = self._compile_expr(builder, node.condition)
        if ctyp == T_STRING:
            # truthiness: string length > 0
            clen = builder.call(self.rt["len_str"], [self._to_i8p(builder, cond)])
            cond_bool = builder.icmp_unsigned("!=", clen, ir.Constant(i64, 0))
        else:
            cv = self._to_i64(builder, cond)
            cond_bool = builder.icmp_unsigned("!=", cv, ir.Constant(i64, 0))

        func = builder.function
        tb = func.append_basic_block("if_then")
        eb = func.append_basic_block("if_else")
        ab = func.append_basic_block("if_after")
        builder.cbranch(cond_bool, tb, eb)

        builder.position_at_end(tb)
        self._compile_block_flattened(builder, node.then_block)
        if not builder.block.is_terminated:
            builder.branch(ab)

        builder.position_at_end(eb)
        if node.else_block:
            self._compile_block_flattened(builder, node.else_block)
        if not builder.block.is_terminated:
            builder.branch(ab)

        builder.position_at_end(ab)

    def _compile_for(self, builder, node: For):
        i64 = ir.IntType(64)
        start_v, _ = self._compile_expr(builder, node.start)
        end_v, _   = self._compile_expr(builder, node.end)

        slot = self._get_slot(node.var)
        builder.store(self._to_i8p(builder, start_v), slot)
        self._set_type(node.var, T_INT)

        func = builder.function
        cond_b = func.append_basic_block("for_cond")
        body_b = func.append_basic_block("for_body")
        after_b = func.append_basic_block("for_after")
        builder.branch(cond_b)

        builder.position_at_end(cond_b)
        cur_raw = builder.load(slot)
        cur = self._to_i64(builder, cur_raw)
        endi = self._to_i64(builder, end_v)
        cmp = builder.icmp_signed("<", cur, endi)
        builder.cbranch(cmp, body_b, after_b)

        builder.position_at_end(body_b)
        self._compile_block_flattened(builder, node.body)
        if not builder.block.is_terminated:
            cur2_raw = builder.load(slot)
            cur2 = self._to_i64(builder, cur2_raw)
            nxt = builder.add(cur2, ir.Constant(i64, 1))
            builder.store(self._to_i8p(builder, nxt), slot)
            builder.branch(cond_b)

        builder.position_at_end(after_b)

    def _compile_while(self, builder, node):
        """
        Compile a while loop.

        Important: this runs INSIDE the flattened dispatcher. The current
        block (builder.block) has already been positioned by the flattener
        but does NOT yet have its state-store + dispatcher branch. We must
        not call builder.branch() here --- that would terminate the block
        before the flattener can emit its own terminator.

        Instead: we create the loop blocks, let the flattener emit the
        state-store + branch to dispatcher as normal, and connect the
        dispatcher's next statement to the while_cond block.

        Actually simpler: we run the loop entirely inside this one block
        position, inlined. The flattener will continue after the loop.
        """
        i64 = ir.IntType(64)
        func = builder.function

        # We're currently positioned inside a flattened statement block.
        # Create the loop's own sub-blocks.
        cond_b = func.append_basic_block("while_cond")
        body_b = func.append_basic_block("while_body")
        after_b = func.append_basic_block("while_after")

        # Emit the loop's control flow INTO the current block.
        # Terminate the current block with a jump to while_cond.
        builder.branch(cond_b)

        # --- Condition block ---
        builder.position_at_end(cond_b)
        cond, ctyp = self._compile_expr(builder, node.condition)
        if ctyp == T_STRING:
            clen = builder.call(self.rt["len_str"],
                                [self._to_i8p(builder, cond)])
            cond_bool = builder.icmp_unsigned("!=", clen, ir.Constant(i64, 0))
        else:
            cv = self._to_i64(builder, cond)
            cond_bool = builder.icmp_unsigned("!=", cv, ir.Constant(i64, 0))
        builder.cbranch(cond_bool, body_b, after_b)

        # --- Body block: compile each statement directly (no re-flatten) ---
        builder.position_at_end(body_b)
        self.loop_stack.append({
            "continue_target": cond_b,
            "break_target": after_b,
        })
        for stmt in node.body.statements:
            self._compile_stmt(builder, stmt)
            if builder.block.is_terminated:
                break
        self.loop_stack.pop()
        if not builder.block.is_terminated:
            builder.branch(cond_b)

        # --- After block: continue compiling the flattened statement from here ---
        builder.position_at_end(after_b)
        # Do NOT call builder.branch() --- the flattener will emit
        # the state-store and dispatcher branch after this method returns.
    def _compile_break(self, builder):
        if not self.loop_stack:
            raise RuntimeError("break outside of loop")
        target = self.loop_stack[-1]["break_target"]
        builder.branch(target)
        new_b = builder.function.append_basic_block("after_break")
        builder.position_at_end(new_b)

    def _compile_continue(self, builder):
        if not self.loop_stack:
            raise RuntimeError("continue outside of loop")
        target = self.loop_stack[-1]["continue_target"]
        builder.branch(target)
        new_b = builder.function.append_basic_block("after_continue")
        builder.position_at_end(new_b)

    # ---------- Expressions ----------
    def _compile_expr(self, builder, expr) -> Tuple[ir.Value, JType]:
        i64 = ir.IntType(64)
        i8p = ir.IntType(8).as_pointer()

        if isinstance(expr, IntLit):
            return ir.Constant(i64, expr.value), T_INT

        if isinstance(expr, StrLit):
            # Encoded global + key + length → runtime decoder → JkyString
            ptr = self._make_string_literal(expr.value)
            gv_tuple = self.string_literals[expr.value]
            _gv, xk, plain_len = gv_tuple
            decoded = builder.call(
                self.rt["decode_str"],
                [ptr,
                 ir.Constant(i64, xk),
                 ir.Constant(i64, plain_len)],
            )
            return decoded, T_STRING
        if isinstance(expr, Ident):
            slot = self._get_slot(expr.name)
            raw = builder.load(slot, name=f"{expr.name}_v")
            typ = self._get_type(expr.name)
            if typ == T_INT:
                return self._to_i64(builder, raw), T_INT
            return raw, typ

        if isinstance(expr, BinOp):
            op = expr.op
            l_raw, l_t = self._compile_expr(builder, expr.left)
            r_raw, r_t = self._compile_expr(builder, expr.right)

            # String concatenation
            if op == "+" and (l_t == T_STRING or r_t == T_STRING):
                ls = self._as_jkystring(builder, l_raw, l_t)
                rs = self._as_jkystring(builder, r_raw, r_t)
                result = builder.call(self.rt["concat"], [ls, rs])
                return result, T_STRING

            # String comparison (== and !=)
            if op in ("==", "!=") and (l_t == T_STRING or r_t == T_STRING):
                ls = self._as_jkystring(builder, l_raw, l_t)
                rs = self._as_jkystring(builder, r_raw, r_t)
                eq_result = builder.call(self.rt["str_eq"], [ls, rs])
                if op == "==":
                    return eq_result, T_INT
                # != inverts the result
                one = ir.Constant(i64, 1)
                return builder.xor(eq_result, one), T_INT

            # Integer ops
            L = self._to_i64(builder, l_raw)
            R = self._to_i64(builder, r_raw)

            if op == "+": return builder.add(L, R), T_INT
            if op == "-": return builder.sub(L, R), T_INT
            if op == "*": return builder.mul(L, R), T_INT
            if op == "/": return builder.sdiv(L, R), T_INT
            if op == "%": return builder.srem(L, R), T_INT
            if op == "==": return builder.zext(builder.icmp_unsigned("==", L, R), i64), T_INT
            if op == "!=": return builder.zext(builder.icmp_unsigned("!=", L, R), i64), T_INT
            if op == "<": return builder.zext(builder.icmp_signed("<", L, R), i64), T_INT
            if op == ">": return builder.zext(builder.icmp_signed(">", L, R), i64), T_INT
            if op == "<=": return builder.zext(builder.icmp_signed("<=", L, R), i64), T_INT
            if op == ">=": return builder.zext(builder.icmp_signed(">=", L, R), i64), T_INT

            raise NotImplementedError(f"op {op}")
        if isinstance(expr, Index):
            arr_raw, arr_t = self._compile_expr(builder, expr.target)
            idx_raw, _     = self._compile_expr(builder, expr.index)
            arr_ptr = self._as_jkyarray(builder, arr_raw, arr_t)
            idx_i   = self._to_i64(builder, idx_raw)
            result = builder.call(self.rt["index"], [arr_ptr, idx_i])
            return result, T_STRING

        if isinstance(expr, Call):
            name = expr.name

            # Builtins
            if name == "read_file":
                p_raw, p_t = self._compile_expr(builder, expr.args[0])
                p = self._as_cstr(builder, p_raw, p_t)
                return builder.call(self.rt["read_file"], [p]), T_STRING

            if name == "list_dir":
                p_raw, p_t = self._compile_expr(builder, expr.args[0])
                p = self._as_cstr(builder, p_raw, p_t)
                return builder.call(self.rt["list_dir"], [p]), T_ARRAY

            if name == "exec_cmd":
                p_raw, p_t = self._compile_expr(builder, expr.args[0])
                p = self._as_cstr(builder, p_raw, p_t)
                return builder.call(self.rt["exec_cmd"], [p]), T_STRING

            if name == "len":
                x_raw, x_t = self._compile_expr(builder, expr.args[0])
                if x_t == T_ARRAY:
                    ap = self._as_jkyarray(builder, x_raw, x_t)
                    return builder.call(self.rt["len_arr"], [ap]), T_INT
                sp = self._as_jkystring(builder, x_raw, x_t)
                return builder.call(self.rt["len_str"], [sp]), T_INT

            # ---------- Tier 1: file ----------
            if name == "file_exists":
                p, pt = self._compile_expr(builder, expr.args[0])
                c = self._as_cstr(builder, p, pt)
                return builder.call(self.rt["file_exists"], [c]), T_INT

            if name == "file_size":
                p, pt = self._compile_expr(builder, expr.args[0])
                c = self._as_cstr(builder, p, pt)
                return builder.call(self.rt["file_size"], [c]), T_INT

            if name == "file_mtime":
                p, pt = self._compile_expr(builder, expr.args[0])
                c = self._as_cstr(builder, p, pt)
                return builder.call(self.rt["file_mtime"], [c]), T_INT

            if name == "read_file_lines":
                p, pt = self._compile_expr(builder, expr.args[0])
                c = self._as_cstr(builder, p, pt)
                return builder.call(self.rt["read_file_lines"], [c]), T_ARRAY

            if name == "read_bytes":
                p, pt = self._compile_expr(builder, expr.args[0])
                c = self._as_cstr(builder, p, pt)
                off, _ = self._compile_expr(builder, expr.args[1])
                cnt, _ = self._compile_expr(builder, expr.args[2])
                off_i = self._to_i64(builder, off)
                cnt_i = self._to_i64(builder, cnt)
                return builder.call(self.rt["read_bytes"], [c, off_i, cnt_i]), T_STRING

            if name == "readlink":
                p, pt = self._compile_expr(builder, expr.args[0])
                c = self._as_cstr(builder, p, pt)
                return builder.call(self.rt["readlink"], [c]), T_STRING

            # ---------- Tier 1: string ----------
            if name == "substr":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                a, _ = self._compile_expr(builder, expr.args[1])
                b, _ = self._compile_expr(builder, expr.args[2])
                ai = self._to_i64(builder, a)
                bi = self._to_i64(builder, b)
                return builder.call(self.rt["substr"], [sp, ai, bi]), T_STRING

            if name == "split":
                s, st = self._compile_expr(builder, expr.args[0])
                d, dt = self._compile_expr(builder, expr.args[1])
                sp = self._as_jkystring(builder, s, st)
                dp = self._as_jkystring(builder, d, dt)
                return builder.call(self.rt["split"], [sp, dp]), T_ARRAY

            if name == "find":
                s, st = self._compile_expr(builder, expr.args[0])
                n, nt = self._compile_expr(builder, expr.args[1])
                sp = self._as_jkystring(builder, s, st)
                np = self._as_jkystring(builder, n, nt)
                return builder.call(self.rt["find"], [sp, np]), T_INT

            if name == "trim":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["trim"], [sp]), T_STRING

            if name == "lower":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["lower"], [sp]), T_STRING

            if name == "upper":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["upper"], [sp]), T_STRING

            if name == "to_int":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["to_int"], [sp]), T_INT

            if name == "replace":
                s, st = self._compile_expr(builder, expr.args[0])
                o, ot = self._compile_expr(builder, expr.args[1])
                n, nt = self._compile_expr(builder, expr.args[2])
                sp = self._as_jkystring(builder, s, st)
                op = self._as_jkystring(builder, o, ot)
                np = self._as_jkystring(builder, n, nt)
                return builder.call(self.rt["replace"], [sp, op, np]), T_STRING

            if name == "starts_with":
                s, st = self._compile_expr(builder, expr.args[0])
                p, pt = self._compile_expr(builder, expr.args[1])
                sp = self._as_jkystring(builder, s, st)
                pp = self._as_jkystring(builder, p, pt)
                return builder.call(self.rt["starts_with"], [sp, pp]), T_INT

            if name == "ends_with":
                s, st = self._compile_expr(builder, expr.args[0])
                p, pt = self._compile_expr(builder, expr.args[1])
                sp = self._as_jkystring(builder, s, st)
                pp = self._as_jkystring(builder, p, pt)
                return builder.call(self.rt["ends_with"], [sp, pp]), T_INT

            # ---------- Tier 1: array ----------
            if name == "append":
                a, at = self._compile_expr(builder, expr.args[0])
                v, vt = self._compile_expr(builder, expr.args[1])
                ap = self._as_jkyarray(builder, a, at)
                vp = self._as_jkystring(builder, v, vt)
                return builder.call(self.rt["append"], [ap, vp]), T_ARRAY

            if name == "contains":
                a, at = self._compile_expr(builder, expr.args[0])
                v, vt = self._compile_expr(builder, expr.args[1])
                ap = self._as_jkyarray(builder, a, at)
                vp = self._as_jkystring(builder, v, vt)
                return builder.call(self.rt["contains"], [ap, vp]), T_INT

            # ---------- Tier 1: system ----------
            if name == "getenv":
                n, nt = self._compile_expr(builder, expr.args[0])
                np = self._as_jkystring(builder, n, nt)
                return builder.call(self.rt["getenv"], [np]), T_STRING

            if name == "getpid":
                return builder.call(self.rt["getpid"], []), T_INT

            if name == "getuid":
                return builder.call(self.rt["getuid"], []), T_INT

            if name == "getcwd":
                return builder.call(self.rt["getcwd"], []), T_STRING
            # ---------- Tier 2: maps ----------
            if name == "map_new":
                return builder.call(self.rt["map_new"], []), T_ARRAY

            if name == "map_set":
                m, mt = self._compile_expr(builder, expr.args[0])
                k, kt = self._compile_expr(builder, expr.args[1])
                v, vt = self._compile_expr(builder, expr.args[2])
                mp = self._as_jkyarray(builder, m, mt)
                kp = self._as_jkystring(builder, k, kt)
                vp = self._as_jkystring(builder, v, vt)
                builder.call(self.rt["map_set"], [mp, kp, vp])
                return ir.Constant(i64, 0), T_INT

            if name == "map_get":
                m, mt = self._compile_expr(builder, expr.args[0])
                k, kt = self._compile_expr(builder, expr.args[1])
                mp = self._as_jkyarray(builder, m, mt)
                kp = self._as_jkystring(builder, k, kt)
                return builder.call(self.rt["map_get"], [mp, kp]), T_STRING

            if name == "map_has":
                m, mt = self._compile_expr(builder, expr.args[0])
                k, kt = self._compile_expr(builder, expr.args[1])
                mp = self._as_jkyarray(builder, m, mt)
                kp = self._as_jkystring(builder, k, kt)
                return builder.call(self.rt["map_has"], [mp, kp]), T_INT

            if name == "map_size":
                m, mt = self._compile_expr(builder, expr.args[0])
                mp = self._as_jkyarray(builder, m, mt)
                return builder.call(self.rt["map_size"], [mp]), T_INT

            if name == "map_key_at":
                m, mt = self._compile_expr(builder, expr.args[0])
                i, _ = self._compile_expr(builder, expr.args[1])
                mp = self._as_jkyarray(builder, m, mt)
                ii = self._to_i64(builder, i)
                return builder.call(self.rt["map_key_at"], [mp, ii]), T_STRING

            if name == "map_val_at":
                m, mt = self._compile_expr(builder, expr.args[0])
                i, _ = self._compile_expr(builder, expr.args[1])
                mp = self._as_jkyarray(builder, m, mt)
                ii = self._to_i64(builder, i)
                return builder.call(self.rt["map_val_at"], [mp, ii]), T_STRING

            # ---------- Tier 2: strings/io ----------
            if name == "build_string":
                a, at = self._compile_expr(builder, expr.args[0])
                s, st = self._compile_expr(builder, expr.args[1])
                ap = self._as_jkyarray(builder, a, at)
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["build_string"], [ap, sp]), T_STRING

            if name == "match":
                s, st = self._compile_expr(builder, expr.args[0])
                p, pt = self._compile_expr(builder, expr.args[1])
                sp = self._as_jkystring(builder, s, st)
                pp = self._as_jkystring(builder, p, pt)
                return builder.call(self.rt["match"], [sp, pp]), T_STRING

            if name == "regex_test":
                s, st = self._compile_expr(builder, expr.args[0])
                p, pt = self._compile_expr(builder, expr.args[1])
                sp = self._as_jkystring(builder, s, st)
                pp = self._as_jkystring(builder, p, pt)
                return builder.call(self.rt["regex_test"], [sp, pp]), T_INT

            if name == "write_file":
                p, pt = self._compile_expr(builder, expr.args[0])
                c, ct = self._compile_expr(builder, expr.args[1])
                pp = self._as_jkystring(builder, p, pt)
                cp = self._as_jkystring(builder, c, ct)
                return builder.call(self.rt["write_file"], [pp, cp]), T_INT

            if name == "append_file":
                p, pt = self._compile_expr(builder, expr.args[0])
                c, ct = self._compile_expr(builder, expr.args[1])
                pp = self._as_jkystring(builder, p, pt)
                cp = self._as_jkystring(builder, c, ct)
                return builder.call(self.rt["append_file"], [pp, cp]), T_INT

            if name == "sleep":
                ms, _ = self._compile_expr(builder, expr.args[0])
                msi = self._to_i64(builder, ms)
                builder.call(self.rt["sleep"], [msi])
                return ir.Constant(i64, 0), T_INT

            if name == "json_escape":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["json_escape"], [sp]), T_STRING
            # ---------- Tier 3: array transforms ----------
            if name == "sort":
                a, at = self._compile_expr(builder, expr.args[0])
                ap = self._as_jkyarray(builder, a, at)
                return builder.call(self.rt["sort"], [ap]), T_ARRAY

            if name == "reverse":
                a, at = self._compile_expr(builder, expr.args[0])
                ap = self._as_jkyarray(builder, a, at)
                return builder.call(self.rt["reverse"], [ap]), T_ARRAY

            if name == "slice":
                a, at = self._compile_expr(builder, expr.args[0])
                s, _ = self._compile_expr(builder, expr.args[1])
                e, _ = self._compile_expr(builder, expr.args[2])
                ap = self._as_jkyarray(builder, a, at)
                si = self._to_i64(builder, s)
                ei = self._to_i64(builder, e)
                return builder.call(self.rt["slice"], [ap, si, ei]), T_ARRAY

            if name == "unique":
                a, at = self._compile_expr(builder, expr.args[0])
                ap = self._as_jkyarray(builder, a, at)
                return builder.call(self.rt["unique"], [ap]), T_ARRAY

            if name == "join":
                a, at = self._compile_expr(builder, expr.args[0])
                s, st = self._compile_expr(builder, expr.args[1])
                ap = self._as_jkyarray(builder, a, at)
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["join"], [ap, sp]), T_STRING

            # ---------- Tier 3: encoding ----------
            if name == "base64_encode":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["base64_encode"], [sp]), T_STRING

            if name == "base64_decode":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["base64_decode"], [sp]), T_STRING

            if name == "hex_encode":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["hex_encode"], [sp]), T_STRING

            if name == "hex_decode":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["hex_decode"], [sp]), T_STRING

            # ---------- Tier 3: hashing ----------
            if name == "sha256_file":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["sha256_file"], [sp]), T_STRING

            if name == "sha256_string":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["sha256_string"], [sp]), T_STRING

            if name == "str_len_bytes":
                s, st = self._compile_expr(builder, expr.args[0])
                sp = self._as_jkystring(builder, s, st)
                return builder.call(self.rt["str_len_bytes"], [sp]), T_INT          

            if name == "emit":
                k_raw, k_t = self._compile_expr(builder, expr.args[0])
                v_raw, v_t = self._compile_expr(builder, expr.args[1])
                kp = self._as_cstr(builder, k_raw, k_t)
                if v_t == T_INT:
                    # Convert integer to JkyString before emit
                    v_raw = builder.call(self.rt["int_to_str"], [v_raw])
                    vp = builder.bitcast(v_raw, i8p)
                else:
                    vp = self._as_jkystring(builder, v_raw, v_t)
                builder.call(self.rt["emit"], [kp, vp])
                return ir.Constant(i64, 0), T_INT
            # User function
            fn = self.functions.get(name)
            if fn is None:
                raise RuntimeError(f"unknown function: {name}")
            args_i64 = []
            for a in expr.args:
                raw, t = self._compile_expr(builder, a)
                args_i64.append(self._to_i64(builder, raw))
            ret = builder.call(fn, args_i64)
            return ret, T_INT

        raise NotImplementedError(f"expr {type(expr).__name__}")

    # ---------- Type coercions ----------
    def _to_i8p(self, builder, val):
        """Universal rep: everything is i8* in slots."""
        i8p = ir.IntType(8).as_pointer()
        if isinstance(val.type, ir.PointerType):
            return builder.bitcast(val, i8p)
        return builder.inttoptr(val, i8p)

    def _to_i64(self, builder, val):
        i64 = ir.IntType(64)
        if isinstance(val.type, ir.PointerType):
            return builder.ptrtoint(val, i64)
        if val.type == i64:
            return val
        # Widen smaller int
        return builder.sext(val, i64)

    def _as_jkystring(self, builder, val, typ):
        """Ensure val is a JkyString* (i8*)."""
        i8p = ir.IntType(8).as_pointer()
        if isinstance(val.type, ir.PointerType):
            return builder.bitcast(val, i8p)
        return builder.inttoptr(val, i8p)

    def _as_jkyarray(self, builder, val, typ):
        i8p = ir.IntType(8).as_pointer()
        if isinstance(val.type, ir.PointerType):
            return builder.bitcast(val, i8p)
        return builder.inttoptr(val, i8p)

    def _as_cstr(self, builder, val, typ):
        """For runtime calls that want const char* (path/cmd).
        If val is a JkyString*, extract the first field (.data)."""
        i8p = ir.IntType(8).as_pointer()
        if typ == T_STRING:
            # val is JkyString* — first 8 bytes are `char* data`
            data_ptr_slot = builder.bitcast(val, i8p.as_pointer())
            return builder.load(data_ptr_slot, name="cstr")
        # For literals or unknown types, treat as raw i8*
        return builder.bitcast(val, i8p)
    @staticmethod
    def _str_hash(s: str) -> int:
        h = 1469598103934665603
        for ch in s.encode():
            h ^= ch
            h *= 1099511628211
        return h & 0x7FFFFFFFFFFFFFFF


def compile_source(src: str) -> str:
    from lexer import Lexer
    from parser import Parser
    tokens = Lexer(src).tokenize()
    ast = Parser(tokens).parse_program()
    return str(CodeGenV2(ast).generate())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 codegen_v2.py <file.jky>")
        sys.exit(1)
    src = Path(sys.argv[1]).read_text()
    llvm_ir = compile_source(src)
    out = Path(sys.argv[1]).with_suffix(".v2.ll")
    out.write_text(llvm_ir)
    print(f"[+] LLVM IR written to {out}")
    print(f"[+] Total lines: {len(llvm_ir.splitlines())}")
