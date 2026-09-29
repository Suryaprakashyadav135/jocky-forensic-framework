"""
JOCKY Language — LLVM IR Code Generator with Control-Flow Flattening

LLVM SSA rule: every alloca must live in the entry block so it dominates
all uses. Strategy:
  1. Pre-scan the AST to know var names, block counts, command counts.
  2. Emit every alloca into `entry` in one pass, plus store params.
  3. Emit `br body_entry` — the entry block is now terminated forever.
  4. Compile the body into `body_entry` and beyond — no more allocas.
"""

import sys
from pathlib import Path
from typing import Dict, List, Set

import llvmlite.ir as ir

sys.path.insert(0, str(Path(__file__).parent))
from parser import (
    Program, VarDecl, FnDecl, Command, Block, If, For, Return,
    Assign, ExprStmt, BinOp, IntLit, StrLit, Ident, Call,
)


# ---------- AST scan ----------
def scan(node, vars_out: Set[str], counters: Dict[str, int], params: Set[str]):
    if isinstance(node, Ident):
        vars_out.add(node.name)
        return
    if isinstance(node, VarDecl):
        vars_out.add(node.name)
        scan(node.value, vars_out, counters, params)
    elif isinstance(node, Assign):
        vars_out.add(node.target)
        scan(node.value, vars_out, counters, params)
    elif isinstance(node, FnDecl):
        vars_out.update(node.params)
        params.update(node.params)
        scan(node.body, vars_out, counters, params)
    elif isinstance(node, Block):
        if node.statements:
            counters["blocks"] += 1
        for s in node.statements:
            scan(s, vars_out, counters, params)
    elif isinstance(node, If):
        scan(node.condition, vars_out, counters, params)
        scan(node.then_block, vars_out, counters, params)
        if node.else_block:
            scan(node.else_block, vars_out, counters, params)
    elif isinstance(node, For):
        vars_out.add(node.var)
        scan(node.start, vars_out, counters, params)
        scan(node.end, vars_out, counters, params)
        scan(node.body, vars_out, counters, params)
    elif isinstance(node, Return):
        if node.value:
            scan(node.value, vars_out, counters, params)
    elif isinstance(node, ExprStmt):
        scan(node.expr, vars_out, counters, params)
    elif isinstance(node, Command):
        counters["commands"] += 1
    elif isinstance(node, BinOp):
        scan(node.left, vars_out, counters, params)
        scan(node.right, vars_out, counters, params)
    elif isinstance(node, Call):
        for a in node.args:
            scan(a, vars_out, counters, params)


class CodeGen:
    def __init__(self, program: Program):
        self.program = program
        self.module = ir.Module(name="jocky_module")
        self.module.triple = "x86_64-pc-linux-gnu"

        i64 = ir.IntType(64)
        i64_ptr = i64.as_pointer()
        cmd_type = ir.FunctionType(i64, [i64, i64, i64_ptr])
        self.cmd_fn = ir.Function(self.module, cmd_type, name="jocky_cmd")

        self.functions: Dict[str, ir.Function] = {}
        self.entry_builder: ir.IRBuilder = None
        self.var_slots: Dict[str, ir.AllocaInstr] = {}
        self.state_slots: List[ir.AllocaInstr] = []
        self.state_idx = 0
        self.cmd_arg_slots: List[ir.AllocaInstr] = []
        self.cmd_idx = 0

    def generate(self) -> ir.Module:
        import random as _rnd
        import string as _str

        # Binary mutation: randomize function names so symbol table
        # doesn't leak function semantics to static analysis.
        self._name_map = {}
        for decl in self.program.declarations:
            if isinstance(decl, FnDecl):
                rnd_name = "f_" + "".join(
                    _rnd.choices(_str.ascii_lowercase + _str.digits, k=12)
                )
                self._name_map[decl.name] = rnd_name

        for decl in self.program.declarations:
            if isinstance(decl, FnDecl):
                self._declare_function(decl)
        for decl in self.program.declarations:
            if isinstance(decl, FnDecl):
                self._generate_function(decl)
        self._generate_main()
        return self.module
    def _declare_function(self, fn: FnDecl):
        i64 = ir.IntType(64)
        param_types = [i64] * len(fn.params)
        fn_type = ir.FunctionType(i64, param_types)
        func = ir.Function(self.module, fn_type, name=self._name_map.get(fn.name, fn.name))
        for i, pname in enumerate(fn.params):
            func.args[i].name = pname
        self.functions[fn.name] = func

    # ---------- Pre-allocation ----------
    def _preallocate(self, func: ir.Function, root_node, params_to_store: list = None):
        """
        Emit entry block with ALL allocas, store parameters, then branch to
        body_entry. Return an IRBuilder positioned at start of body_entry.
        """
        i64 = ir.IntType(64)

        var_names: Set[str] = set()
        params: Set[str] = set()
        counters = {"blocks": 0, "commands": 0}
        scan(root_node, var_names, counters, params)

        entry = func.append_basic_block("entry")
        eb = ir.IRBuilder(entry)
        self.entry_builder = eb
        self.var_slots = {}

        # Every variable slot
        for name in sorted(var_names):
            self.var_slots[name] = eb.alloca(i64, name=f"{name}_slot")

        # State slots (+ headroom)
        n_states = counters["blocks"] + 8
        self.state_slots = [eb.alloca(i64, name=f"state_{i}") for i in range(n_states)]
        self.state_idx = 0

        # Command arg buffers (+ headroom)
        arr_type = ir.ArrayType(i64, 16)
        n_cmds = counters["commands"] + 8
        self.cmd_arg_slots = [eb.alloca(arr_type, name=f"cmd_args_{i}") for i in range(n_cmds)]
        self.cmd_idx = 0

        # Store parameters BEFORE branching
        if params_to_store:
            for i, pname in enumerate(params_to_store):
                eb.store(func.args[i], self.var_slots[pname])

        # Terminate entry
        body_entry = func.append_basic_block("body_entry")
        eb.branch(body_entry)
        return ir.IRBuilder(body_entry)

    def _next_state_slot(self) -> ir.AllocaInstr:
        slot = self.state_slots[self.state_idx]
        self.state_idx += 1
        return slot

    def _next_cmd_slot(self) -> ir.AllocaInstr:
        slot = self.cmd_arg_slots[self.cmd_idx]
        self.cmd_idx += 1
        return slot

    def _get_slot(self, name: str) -> ir.AllocaInstr:
        if name not in self.var_slots:
            # Safety fallback — should not happen due to pre-scan
            self.var_slots[name] = self.entry_builder.alloca(
                ir.IntType(64), name=f"{name}_slot_late"
            )
        return self.var_slots[name]

    # ---------- Function bodies ----------
    def _generate_function(self, fn: FnDecl):
        func = self.functions[fn.name]
        builder = self._preallocate(func, fn, params_to_store=fn.params)

        self._compile_block_flattened(builder, fn.body)
        if not builder.block.is_terminated:
            builder.ret(ir.Constant(ir.IntType(64), 0))

    def _generate_main(self):
        i64 = ir.IntType(64)
        main = ir.Function(self.module, ir.FunctionType(i64, []), name="main")
        top_stmts = [d for d in self.program.declarations if not isinstance(d, FnDecl)]
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

        state_slot = self._next_state_slot()
        builder.store(ir.Constant(i64, 0), state_slot)

        n = len(block.statements)
        func = builder.function
        dispatcher = func.append_basic_block("dispatcher")
        stmt_blocks = [func.append_basic_block(f"stmt_{i}") for i in range(n)]
        exit_block = func.append_basic_block("exit")

        builder.branch(dispatcher)

        builder.position_at_end(dispatcher)
        state_val = builder.load(state_slot, name="state_val")
        for i in range(n):
            cmp = builder.icmp_unsigned("==", state_val, ir.Constant(i64, i))
            nxt = func.append_basic_block(f"check_{i+1}")
            builder.cbranch(cmp, stmt_blocks[i], nxt)
            builder.position_at_end(nxt)
            state_val = builder.load(state_slot, name=f"state_val_{i+1}")

        cmp_exit = builder.icmp_unsigned("==", state_val, ir.Constant(i64, n))
        builder.cbranch(cmp_exit, exit_block, dispatcher)

        for i, stmt in enumerate(block.statements):
            builder.position_at_end(stmt_blocks[i])
            self._compile_statement(builder, stmt)
            if not builder.block.is_terminated:
                builder.store(ir.Constant(i64, i + 1), state_slot)
                builder.branch(dispatcher)

        builder.position_at_end(exit_block)

    # ---------- Statements ----------
    def _compile_statement(self, builder, stmt):
        if isinstance(stmt, VarDecl):
            v = self._compile_expr(builder, stmt.value)
            builder.store(v, self._get_slot(stmt.name))
        elif isinstance(stmt, Assign):
            v = self._compile_expr(builder, stmt.value)
            builder.store(v, self._get_slot(stmt.target))
        elif isinstance(stmt, Command):
            self._compile_command(builder, stmt)
        elif isinstance(stmt, If):
            self._compile_if(builder, stmt)
        elif isinstance(stmt, For):
            self._compile_for(builder, stmt)
        elif isinstance(stmt, Return):
            self._compile_return(builder, stmt)
        elif isinstance(stmt, ExprStmt):
            self._compile_expr(builder, stmt.expr)

    def _compile_command(self, builder, cmd: Command):
        i64 = ir.IntType(64)
        arr_slot = self._next_cmd_slot()
        arg_hashes = [self._str_hash(a) for a in cmd.args]
        for i, h in enumerate(arg_hashes):
            idx = ir.Constant(ir.IntType(32), i)
            ep = builder.gep(arr_slot, [ir.Constant(ir.IntType(32), 0), idx])
            builder.store(ir.Constant(i64, h), ep)
        arr_ptr = builder.bitcast(arr_slot, i64.as_pointer())
        builder.call(self.cmd_fn, [
            ir.Constant(i64, self._str_hash(cmd.name)),
            ir.Constant(i64, len(arg_hashes)),
            arr_ptr,
        ])

    def _compile_if(self, builder, node: If):
        i64 = ir.IntType(64)
        cond = self._compile_expr(builder, node.condition)
        cond_bool = builder.icmp_unsigned("!=", cond, ir.Constant(i64, 0))
        func = builder.function
        then_b = func.append_basic_block("if_then")
        else_b = func.append_basic_block("if_else")
        after_b = func.append_basic_block("if_after")
        builder.cbranch(cond_bool, then_b, else_b)

        builder.position_at_end(then_b)
        self._compile_block_flattened(builder, node.then_block)
        if not builder.block.is_terminated:
            builder.branch(after_b)

        builder.position_at_end(else_b)
        if node.else_block:
            self._compile_block_flattened(builder, node.else_block)
        if not builder.block.is_terminated:
            builder.branch(after_b)

        builder.position_at_end(after_b)

    def _compile_for(self, builder, node: For):
        i64 = ir.IntType(64)
        start_v = self._compile_expr(builder, node.start)
        end_v = self._compile_expr(builder, node.end)
        slot = self._get_slot(node.var)
        builder.store(start_v, slot)

        func = builder.function
        cond_b = func.append_basic_block("for_cond")
        body_b = func.append_basic_block("for_body")
        after_b = func.append_basic_block("for_after")
        builder.branch(cond_b)

        builder.position_at_end(cond_b)
        cur = builder.load(slot, name="for_cur")
        cmp = builder.icmp_signed("<", cur, end_v)
        builder.cbranch(cmp, body_b, after_b)

        builder.position_at_end(body_b)
        self._compile_block_flattened(builder, node.body)
        if not builder.block.is_terminated:
            cur2 = builder.load(slot, name="for_cur2")
            builder.store(builder.add(cur2, ir.Constant(i64, 1)), slot)
            builder.branch(cond_b)

        builder.position_at_end(after_b)

    def _compile_return(self, builder, node: Return):
        i64 = ir.IntType(64)
        if node.value is None:
            builder.ret(ir.Constant(i64, 0))
        else:
            builder.ret(self._compile_expr(builder, node.value))

    # ---------- Expressions ----------
    def _compile_expr(self, builder, expr) -> ir.Value:
        i64 = ir.IntType(64)
        if isinstance(expr, IntLit):
            return ir.Constant(i64, expr.value)
        if isinstance(expr, StrLit):
            return ir.Constant(i64, self._str_hash(expr.value))
        if isinstance(expr, Ident):
            return builder.load(self._get_slot(expr.name), name=f"{expr.name}_v")
        if isinstance(expr, BinOp):
            L = self._compile_expr(builder, expr.left)
            R = self._compile_expr(builder, expr.right)
            op = expr.op
            if op == "+":  return builder.add(L, R)
            if op == "-":  return builder.sub(L, R)
            if op == "*":  return builder.mul(L, R)
            if op == "/":  return builder.sdiv(L, R)
            if op == "%":  return builder.srem(L, R)
            if op == "==": return builder.zext(builder.icmp_unsigned("==", L, R), i64)
            if op == "!=": return builder.zext(builder.icmp_unsigned("!=", L, R), i64)
            if op == "<":  return builder.zext(builder.icmp_signed("<", L, R), i64)
            if op == ">":  return builder.zext(builder.icmp_signed(">", L, R), i64)
            if op == "<=": return builder.zext(builder.icmp_signed("<=", L, R), i64)
            if op == ">=": return builder.zext(builder.icmp_signed(">=", L, R), i64)
        if isinstance(expr, Call):
            fn = self.functions.get(expr.name)
            if fn is None:
                return ir.Constant(i64, 0)
            return builder.call(fn, [self._compile_expr(builder, a) for a in expr.args])
        raise NotImplementedError(f"expr {type(expr).__name__}")

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
    return str(CodeGen(ast).generate())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 codegen.py <file.jky>")
        sys.exit(1)
    src = Path(sys.argv[1]).read_text()
    llvm_ir = compile_source(src)
    out = Path(sys.argv[1]).with_suffix(".ll")
    out.write_text(llvm_ir)
    print(f"[+] LLVM IR written to {out}")
    print(f"[+] Total lines: {len(llvm_ir.splitlines())}")
