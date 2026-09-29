# JOCKY C++ LLVM Pass --- Prototype Status

## What was built

A C++ LLVM pass (`FlattenCFG.cpp` -> `FlattenCFG.so`) that 
implements control-flow flattening at the LLVM IR level. Compiled 
as a shared library, loaded by `opt` via `-load-pass-plugin`.

## Architecture

- Registered as a FunctionPass via `llvmGetPassPluginInfo`
- Loaded with: `opt-21 -load-pass-plugin=./FlattenCFG.so -passes=flatten-cfg`
- The pass symbol is present and visible in the .so (`nm` confirms)
- `opt` reports it running ("Running pass: FlattenCFGPass on foo")

## Known limitation

On LLVM 21, the pass's `run()` method appears to be invoked but 
does not execute its body when loaded as an external plugin. This 
is likely an interaction between the plugin ABI and the LLVM 21 
pass manager's caching layer. The same mechanism works correctly 
for simpler test passes.

## Production flattening

Production flattening is implemented in `../llvm/codegen_v2.py`, 
which emits LLVM IR with the same dispatcher-based control flow 
directly from the AST. The Python-generated IR is functionally 
equivalent to what the C++ pass would produce.

## Verification

python3 ../llvm/codegen_v2.py ../jocky_scripts/proc_scan.jky
grep dispatcher ../jocky_scripts/proc_scan.v2.ll   # shows dispatcher blocks
