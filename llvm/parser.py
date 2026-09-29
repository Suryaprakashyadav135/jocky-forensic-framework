"""
JOCKY Language — Parser
Recursive descent parser producing an AST.

Grammar (informal):

program      := decl*
decl         := var_decl | fn_decl | command | stmt
var_decl     := "let" IDENT "=" expr ";"
fn_decl      := "fn" IDENT "(" params? ")" block
params       := IDENT ("," IDENT)*
command      := "@" IDENT arg* ";"
arg          := IDENT | INT | STRING | symbol
stmt         := var_decl | command | if_stmt | for_stmt | return_stmt
                | assign_stmt | expr_stmt
assign_stmt  := IDENT "=" expr ";"
if_stmt      := "if" expr block ("else" block)?
for_stmt     := "for" IDENT "in" expr ".." expr block
return_stmt  := "return" expr? ";"
expr_stmt    := expr ";"
block        := "{" stmt* "}"
expr         := comparison
comparison   := additive (("==" | "!=" | "<" | ">" | "<=" | ">=") additive)?
additive     := term (("+" | "-") term)*
term         := factor (("*" | "/" | "%") factor)*
factor       := INT | STRING | IDENT | call | "(" expr ")"
call         := IDENT "(" (expr ("," expr)*)? ")"
"""

from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from lexer import Lexer, Token


# ---------- AST Nodes ----------
@dataclass
class Node: pass

@dataclass
class While(Node):
    condition: Node
    body: "Block"

@dataclass
class Break(Node):
    pass

@dataclass
class Continue(Node):
    pass

@dataclass
class Program(Node):
    declarations: list = field(default_factory=list)

@dataclass
class VarDecl(Node):
    name: str
    value: Node

@dataclass
class FnDecl(Node):
    name: str
    params: List[str]
    body: "Block"

@dataclass
class Command(Node):
    name: str
    args: List[str]

@dataclass
class Block(Node):
    statements: list = field(default_factory=list)

@dataclass
class If(Node):
    condition: Node
    then_block: Block
    else_block: Optional[Block]

@dataclass
class For(Node):
    var: str
    start: Node
    end: Node
    body: Block

@dataclass
class Return(Node):
    value: Optional[Node]

@dataclass
class Assign(Node):
    target: str
    value: Node

@dataclass
class ExprStmt(Node):
    expr: Node

@dataclass
class BinOp(Node):
    op: str
    left: Node
    right: Node

@dataclass
class IntLit(Node):
    value: int

@dataclass
class StrLit(Node):
    value: str

@dataclass
class Ident(Node):
    name: str

@dataclass
class Call(Node):
    name: str
    args: List[Node]

@dataclass
class Index(Node):
    target: Node
    index: Node

# ---------- Parser ----------
class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self, offset: int = 0) -> Token:
        i = self.pos + offset
        return self.tokens[i] if i < len(self.tokens) else self.tokens[-1]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def expect(self, kind: str) -> Token:
        tok = self.peek()
        if tok.kind != kind:
            raise SyntaxError(
                f"Expected {kind}, got {tok.kind} ({tok.value!r}) "
                f"at line {tok.line}, col {tok.col}"
            )
        return self.advance()

    def match(self, *kinds: str) -> Optional[Token]:
        if self.peek().kind in kinds:
            return self.advance()
        return None

    # ---------- Top-level ----------
    def parse_program(self) -> Program:
        prog = Program()
        while self.peek().kind != "EOF":
            prog.declarations.append(self.parse_declaration())
        return prog

    def parse_declaration(self) -> Node:
        tok = self.peek()
        if tok.kind == "LET":
            return self.parse_var_decl()
        if tok.kind == "FN":
            return self.parse_fn_decl()
        if tok.kind == "AT":
            return self.parse_command()
        if tok.kind == "IF":
            return self.parse_if()
        if tok.kind == "FOR":
            return self.parse_for()
        if tok.kind == "RETURN":
            return self.parse_return()
        if tok.kind == "WHILE":
            return self.parse_while()
        if tok.kind == "BREAK":
            return self.parse_break()
        if tok.kind == "CONTINUE":
            return self.parse_continue()
        return self.parse_expr_stmt()

    # ---------- Declarations ----------
    def parse_var_decl(self) -> VarDecl:
        self.expect("LET")
        name = self.expect("IDENT").value
        self.expect("=")
        value = self.parse_expr()
        self.expect(";")
        return VarDecl(name=name, value=value)

    def parse_fn_decl(self) -> FnDecl:
        self.expect("FN")
        name = self.expect("IDENT").value
        self.expect("(")
        params = []
        if self.peek().kind != ")":
            params.append(self.expect("IDENT").value)
            while self.match(","):
                params.append(self.expect("IDENT").value)
        self.expect(")")
        body = self.parse_block()
        return FnDecl(name=name, params=params, body=body)

    # ---------- Commands ----------
    def parse_command(self) -> Command:
        self.expect("AT")
        name = self.expect("IDENT").value
        args = []
        while self.peek().kind not in (";", "EOF"):
            tok = self.advance()
            args.append(tok.value)
        self.expect(";")
        return Command(name=name, args=args)

    # ---------- Statements ----------
    def parse_block(self) -> Block:
        self.expect("{")
        stmts = []
        while self.peek().kind not in ("}", "EOF"):
            stmts.append(self.parse_declaration())
        self.expect("}")
        return Block(statements=stmts)

    def parse_if(self) -> If:
        self.expect("IF")
        cond = self.parse_expr()
        then_block = self.parse_block()
        else_block = None
        if self.match("ELSE"):
            else_block = self.parse_block()
        return If(condition=cond, then_block=then_block, else_block=else_block)

    def parse_for(self) -> For:
        self.expect("FOR")
        var = self.expect("IDENT").value
        self.expect("IN")
        start = self.parse_expr()
        self.expect("..")
        end = self.parse_expr()
        body = self.parse_block()
        return For(var=var, start=start, end=end, body=body)
    def parse_while(self) -> While:
        self.expect("WHILE")
        cond = self.parse_expr()
        body = self.parse_block()
        return While(condition=cond, body=body)

    def parse_break(self) -> Break:
        self.expect("BREAK")
        self.expect(";")
        return Break()

    def parse_continue(self) -> Continue:
        self.expect("CONTINUE")
        self.expect(";")
        return Continue()

    def parse_return(self) -> Return:
        self.expect("RETURN")
        if self.peek().kind == ";":
            self.expect(";")
            return Return(value=None)
        value = self.parse_expr()
        self.expect(";")
        return Return(value=value)

    def parse_expr_stmt(self) -> Node:
        # Look-ahead: IDENT followed by '=' is an assignment
        if self.peek().kind == "IDENT" and self.peek(1).kind == "=":
            name = self.advance().value
            self.expect("=")
            value = self.parse_expr()
            self.expect(";")
            return Assign(target=name, value=value)
        expr = self.parse_expr()
        self.expect(";")
        return ExprStmt(expr=expr)

    # ---------- Expressions ----------
    def parse_expr(self) -> Node:
        return self.parse_comparison()

    def parse_comparison(self) -> Node:
        left = self.parse_additive()
        op = self.match("==", "!=", "<", ">", "<=", ">=")
        if op:
            right = self.parse_additive()
            return BinOp(op=op.kind, left=left, right=right)
        return left

    def parse_additive(self) -> Node:
        left = self.parse_term()
        while self.peek().kind in ("+", "-"):
            op = self.advance().kind
            right = self.parse_term()
            left = BinOp(op=op, left=left, right=right)
        return left

    def parse_term(self) -> Node:
        left = self.parse_factor()
        while self.peek().kind in ("*", "/", "%"):
            op = self.advance().kind
            right = self.parse_factor()
            left = BinOp(op=op, left=left, right=right)
        return left

    def parse_factor(self) -> Node:
        tok = self.peek()
        if tok.kind == "INT":
            self.advance()
            return IntLit(value=int(tok.value))
        if tok.kind == "STRING":
            self.advance()
            return StrLit(value=tok.value)
        if tok.kind == "IDENT":
            self.advance()
            # function call?
            if self.peek().kind == "(":
                self.advance()
                args = []
                if self.peek().kind != ")":
                    args.append(self.parse_expr())
                    while self.match(","):
                        args.append(self.parse_expr())
                self.expect(")")
                return Call(name=tok.value, args=args)
            # indexing?
            if self.peek().kind == "[":
                self.advance()
                idx = self.parse_expr()
                self.expect("]")
                return Index(target=Ident(name=tok.value), index=idx)
            return Ident(name=tok.value)
        if tok.kind == "(":
            self.advance()
            expr = self.parse_expr()
            self.expect(")")
            return expr
        raise SyntaxError(
            f"Unexpected token {tok.kind} ({tok.value!r}) "
            f"at line {tok.line}, col {tok.col}"
        )

# ---------- AST printer ----------
def print_ast(node, indent: int = 0):
    pad = "  " * indent
    if isinstance(node, Program):
        print(f"{pad}Program")
        for d in node.declarations:
            print_ast(d, indent + 1)
    elif isinstance(node, VarDecl):
        print(f"{pad}VarDecl({node.name})")
        print_ast(node.value, indent + 1)
    elif isinstance(node, FnDecl):
        print(f"{pad}FnDecl({node.name}, params={node.params})")
        print_ast(node.body, indent + 1)
    elif isinstance(node, Command):
        print(f"{pad}Command({node.name}, args={node.args})")
    elif isinstance(node, Block):
        print(f"{pad}Block")
        for s in node.statements:
            print_ast(s, indent + 1)
    elif isinstance(node, If):
        print(f"{pad}If")
        print(f"{pad}  cond:")
        print_ast(node.condition, indent + 2)
        print(f"{pad}  then:")
        print_ast(node.then_block, indent + 2)
        if node.else_block:
            print(f"{pad}  else:")
            print_ast(node.else_block, indent + 2)
    elif isinstance(node, For):
        print(f"{pad}For({node.var})")
        print(f"{pad}  start:")
        print_ast(node.start, indent + 2)
        print(f"{pad}  end:")
        print_ast(node.end, indent + 2)
        print(f"{pad}  body:")
        print_ast(node.body, indent + 2)
    elif isinstance(node, Return):
        print(f"{pad}Return")
        if node.value:
            print_ast(node.value, indent + 1)
    elif isinstance(node, Assign):
        print(f"{pad}Assign({node.target})")
        print_ast(node.value, indent + 1)
    elif isinstance(node, ExprStmt):
        print(f"{pad}ExprStmt")
        print_ast(node.expr, indent + 1)
    elif isinstance(node, BinOp):
        print(f"{pad}BinOp({node.op})")
        print_ast(node.left, indent + 1)
        print_ast(node.right, indent + 1)
    elif isinstance(node, IntLit):
        print(f"{pad}IntLit({node.value})")
    elif isinstance(node, StrLit):
        print(f"{pad}StrLit({node.value!r})")
    elif isinstance(node, Ident):
        print(f"{pad}Ident({node.name})")
    elif isinstance(node, Call):
        print(f"{pad}Call({node.name})")
        for a in node.args:
            print_ast(a, indent + 1)
    elif isinstance(node, Index):
        print(f"{pad}Index")
        print_ast(node.target, indent + 1)
        print_ast(node.index, indent + 1)
    elif isinstance(node, While):
        print(f"{pad}While")
        print(f"{pad} cond:")
        print_ast(node.condition, indent + 2)
        print(f"{pad} body:")
        print_ast(node.body, indent + 2)
    elif isinstance(node, Break):
        print(f"{pad}Break")
    elif isinstance(node, Continue):
        print(f"{pad}Continue")
    else:
        print(f"{pad}<unknown: {node}>")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parser.py <file.jky>")
        sys.exit(1)

    src = Path(sys.argv[1]).read_text()
    tokens = Lexer(src).tokenize()
    parser = Parser(tokens)
    ast = parser.parse_program()
    print_ast(ast)
