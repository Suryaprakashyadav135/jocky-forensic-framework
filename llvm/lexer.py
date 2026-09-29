"""
JOCKY Language — Lexer
Tokenizes .jky source files.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class Token:
    kind: str       # e.g. "LET", "IDENT", "INT", "STRING", ...
    value: str      # raw text
    line: int
    col: int

    def __repr__(self):
        return f"Token({self.kind}, {self.value!r})"


KEYWORDS = {
    "let", "fn", "if", "else", "for", "in", "return", "true", "false","while", "break", "continue",
}
SYMBOLS = {
    "=", "+", "-", "*", "/", "%",
    "==", "!=", "<", ">", "<=", ">=",
    "(", ")", "{", "}", "[", "]",
    ";", ",", "..",
}

class Lexer:
    def __init__(self, source: str):
        self.src = source
        self.pos = 0
        self.line = 1
        self.col = 1

    def _peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def _advance(self) -> str:
        ch = self._peek()
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _skip_whitespace_and_comments(self):
        while self.pos < len(self.src):
            ch = self._peek()
            if ch in " \t\r\n":
                self._advance()
            elif ch == "/" and self._peek(1) == "/":
                while self._peek() and self._peek() != "\n":
                    self._advance()
            elif ch == "#":
                while self._peek() and self._peek() != "\n":
                    self._advance()
            else:
                break

    def _read_identifier(self) -> str:
        start = self.pos
        while self._peek().isalnum() or self._peek() == "_":
            self._advance()
        return self.src[start:self.pos]

    def _read_number(self) -> str:
        start = self.pos
        while self._peek().isdigit():
            self._advance()
        return self.src[start:self.pos]

    def _read_string(self) -> str:
        self._advance()  # opening quote
        start = self.pos
        while self._peek() and self._peek() != '"':
            self._advance()
        value = self.src[start:self.pos]
        self._advance()  # closing quote
        return value

    def tokenize(self) -> List[Token]:
        tokens = []
        while True:
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.src):
                break

            line, col = self.line, self.col
            ch = self._peek()

            # Identifier or keyword
            if ch.isalpha() or ch == "_":
                ident = self._read_identifier()
                kind = ident.upper() if ident in KEYWORDS else "IDENT"
                tokens.append(Token(kind, ident, line, col))
                continue

            # Number
            if ch.isdigit():
                num = self._read_number()
                tokens.append(Token("INT", num, line, col))
                continue

            # String
            if ch == '"':
                s = self._read_string()
                tokens.append(Token("STRING", s, line, col))
                continue

            # Command marker: @
            if ch == "@":
                self._advance()
                tokens.append(Token("AT", "@", line, col))
                continue

            # Symbols (2-char first, then 1-char)
            two = self.src[self.pos:self.pos+2]
            if two in ("==", "!=", "<=", ">=", ".."):
                self._advance(); self._advance()
                tokens.append(Token(two, two, line, col))
                continue

            if ch in "=+-*/%<>(){}[];,!":
                self._advance()
                tokens.append(Token(ch, ch, line, col))
                continue
            raise SyntaxError(f"Unexpected character {ch!r} at line {line}, col {col}")

        tokens.append(Token("EOF", "", self.line, self.col))
        return tokens


if __name__ == "__main__":
    import sys
    src = open(sys.argv[1]).read()
    lexer = Lexer(src)
    for tok in lexer.tokenize():
        print(tok)
