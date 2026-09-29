# JOCKY Language Specification v0.1

## Overview
JOCKY is a small, domain-specific language for expressing forensic analysis
tasks. It compiles to LLVM IR with control-flow flattening, producing binaries
that resist signature-based detection.

## Syntax

### Comments
    // single line
    # also single line

### Variable Declaration
    let name = value;
    let x = 42;
    let msg = "hello";

### Command Invocation (forensic operations)
    @command arg1 arg2 ...;

Examples:
    @collect system_info;
    @enumerate network_connections tcp;
    @scan forensic_artifacts /var/log /tmp;

### Conditionals
    if condition {
        ...
    } else {
        ...
    }

Conditions: comparisons on variables or literals
    if x > 5 { ... }
    if x == 0 { ... }

### Loops
    for i in 0..10 {
        ...
    }

### Function Definitions
    fn name(param1, param2) {
        ...
        return expr;
    }

    fn check_system(threshold) {
        let processes = 10;
        if processes > threshold {
            @scan forensic_artifacts /proc;
        }
        return processes;
    }

### Expressions
- Arithmetic: + - * / %
- Comparison: == != < > <= >=
- Literals: integers, strings

## Compilation Target
LLVM IR (version compatible with LLVM 21+).
All function bodies are transformed with:
1. Control-flow flattening (dispatcher loop with state variable)
2. Bogus control flow (dead branches)
3. Instruction substitution

## Example Program

    // JOCKY forensic scan
    let threshold = 5;

    fn check_system(limit) {
        let count = 0;
        for i in 0..limit {
            count = count + 1;
        }
        if count > threshold {
            @scan forensic_artifacts /var/log /tmp;
        }
        return count;
    }

    @collect system_info;
    check_system(3);
    @enumerate network_connections tcp;
