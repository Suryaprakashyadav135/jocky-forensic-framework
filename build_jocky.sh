#!/bin/bash
# JOCKY Build Pipeline --- full chain with ELF mutation and dummy symbols
#
# Steps:
#   1. Compile .jky -> LLVM IR (codegen_v2.py)
#   2. Compile IR -> object (clang)
#   3. Compile runtime.c -> object (with randomized symbols)
#   4. Generate dummy symbol C file with random names
#   5. Link binary (stripped, --export-dynamic to force .dynsym entries)
#   6. Mutate ELF entry point
#   7. Verify zero leaks

set -e

SCRIPT="$1"
if [ -z "$SCRIPT" ]; then
    echo "Usage: $0 <script.jky>"
    exit 1
fi

NAME=$(basename "$SCRIPT" .jky)
RUNTIME_SRC="/home/kali/Rudhra/Jocky/llvm/runtime.c"
ELF_MUTATOR="/home/kali/Rudhra/Jocky/src/elf_mutate.py"

# Fresh random prefix per build
PREFIX="j$(head -c 8 /dev/urandom | xxd -p)"
export JKY_SYMBOL_PREFIX="$PREFIX"

echo "[build] Script: $SCRIPT"
echo "[build] Symbol prefix: $PREFIX"

# 1. Generate IR
echo "[build] Step 1: Generate LLVM IR"
python3 llvm/codegen_v2.py "$SCRIPT" > /dev/null 2>&1

IR_FILE="${SCRIPT%.jky}.v2.ll"
if [ ! -f "$IR_FILE" ]; then
    echo "[build] ERROR: IR not generated"
    exit 1
fi

# 2. Compile IR to object
echo "[build] Step 2: Compile IR to object"
clang -c "$IR_FILE" -o "/tmp/${NAME}.o"

# 3. Compile runtime with randomized symbols
echo "[build] Step 3: Compile runtime with randomized symbols"
clang -c "$RUNTIME_SRC" -o "/tmp/runtime_${PREFIX}.o" \
    -Djky_read_file=${PREFIX}_a \
    -Djky_list_dir=${PREFIX}_b \
    -Djky_exec_cmd=${PREFIX}_c \
    -Djky_len_str=${PREFIX}_d \
    -Djky_len_arr=${PREFIX}_e \
    -Djky_index=${PREFIX}_f \
    -Djky_concat=${PREFIX}_g \
    -Djky_emit=${PREFIX}_h \
    -Djky_make_str=${PREFIX}_i \
    -Djky_decode_str=${PREFIX}_l \
    -Djky_int_to_str=${PREFIX}_j \
    -Djky_file_exists=${PREFIX}_m \
    -Djky_file_size=${PREFIX}_n \
    -Djky_file_mtime=${PREFIX}_o \
    -Djky_read_file_lines=${PREFIX}_p \
    -Djky_read_bytes=${PREFIX}_q \
    -Djky_readlink=${PREFIX}_r \
    -Djky_substr=${PREFIX}_s \
    -Djky_split=${PREFIX}_t \
    -Djky_find=${PREFIX}_u \
    -Djky_trim=${PREFIX}_v \
    -Djky_lower=${PREFIX}_w \
    -Djky_upper=${PREFIX}_x \
    -Djky_to_int=${PREFIX}_y \
    -Djky_replace=${PREFIX}_z \
    -Djky_starts_with=${PREFIX}_A \
    -Djky_ends_with=${PREFIX}_B \
    -Djky_append=${PREFIX}_C \
    -Djky_contains=${PREFIX}_D \
    -Wno-deprecated-declarations \
    -Djky_getenv=${PREFIX}_E \
    -Djky_getpid=${PREFIX}_F \
    -Djky_getuid=${PREFIX}_G \
    -Djky_getcwd=${PREFIX}_H \
    -Djky_map_new=${PREFIX}_I \
    -Djky_map_set=${PREFIX}_J \
    -Djky_map_get=${PREFIX}_K \
    -Djky_map_has=${PREFIX}_L \
    -Djky_map_size=${PREFIX}_M \
    -Djky_map_key_at=${PREFIX}_N \
    -Djky_map_val_at=${PREFIX}_O \
    -Djky_build_string=${PREFIX}_P \
    -Djky_match=${PREFIX}_Q \
    -Djky_regex_test=${PREFIX}_R \
    -Djky_write_file=${PREFIX}_S \
    -Djky_append_file=${PREFIX}_T \
    -Djky_sleep=${PREFIX}_U \
    -Djky_json_escape=${PREFIX}_V \
    -Djky_sort=${PREFIX}_W \
    -Djky_reverse=${PREFIX}_X \
    -Djky_slice=${PREFIX}_Y \
    -Djky_unique=${PREFIX}_Z \
    -Djky_join=${PREFIX}_1 \
    -Djky_base64_encode=${PREFIX}_2 \
    -Djky_base64_decode=${PREFIX}_3 \
    -Djky_hex_encode=${PREFIX}_4 \
    -Djky_hex_decode=${PREFIX}_5 \
    -Djky_sha256_file=${PREFIX}_6 \
    -Djky_sha256_string=${PREFIX}_7 \
    -Djky_str_len_bytes=${PREFIX}_8 \
    -Djky_str_eq=${PREFIX}_9 \
    -Djocky_cmd=${PREFIX}_k

# 4. Generate dummy symbol C file with random names
echo "[build] Step 4: Generate dummy symbols"
NUM_DUMMIES=$(( RANDOM % 8 + 3 ))
DUMMY_SRC="/tmp/dummies_${PREFIX}.c"
DUMMY_OBJ="/tmp/dummies_${PREFIX}.o"

python3 - "$NUM_DUMMIES" "$DUMMY_SRC" << 'PYEOF'
import sys, os, random

num = int(sys.argv[1])
out_path = sys.argv[2]

prefixes = [
    "_ITM_", "__cxa_", "__gmon_", "_dl_", "__dso_",
    "_Jv_", "_fini_", "_init_", "__libc_", "__stack_",
]

lines = ["// Auto-generated dummy symbols for .dynsym augmentation"]
for _ in range(num):
    p = random.choice(prefixes)
    suffix = os.urandom(4).hex()
    lines.append(
        f'__attribute__((used, visibility("default"))) '
        f'const char {p}{suffix}[8] = {{0}};'
    )

with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"  Generated {num} dummy symbols in {out_path}")
PYEOF

clang -c "$DUMMY_SRC" -o "$DUMMY_OBJ"

# 5. Link stripped binary with --export-dynamic
echo "[build] Step 5: Link binary with exported symbols"
OUT_BIN="/tmp/${NAME}_final.bin"
clang "/tmp/${NAME}.o" "/tmp/runtime_${PREFIX}.o" "$DUMMY_OBJ" \
    -o "$OUT_BIN" -Wl,-s -Wl,--export-dynamic -lcrypto
# 6. Mutate ELF entry point
echo "[build] Step 6: Mutate ELF entry point"
python3 "$ELF_MUTATOR" "$OUT_BIN" > /dev/null

# 7. Verify
echo "[build] Step 7: Verification"
SIZE=$(stat -c '%s' "$OUT_BIN")
LEAKS=$(strings "$OUT_BIN" | grep -cE "jky_|\[jky\]|read_file|list_dir|exec_cmd" || true)
ENTRY=$(readelf -h "$OUT_BIN" 2>/dev/null | grep "Entry point" | awk '{print $NF}')
DYNCOUNT=$(readelf --dyn-syms -W "$OUT_BIN" 2>/dev/null | grep -cE "FUNC|OBJECT|NOTYPE")

echo ""
echo "=== Build complete: $NAME ==="
echo "  Binary: $OUT_BIN"
echo "  Size: $SIZE bytes"
echo "  Entry point: $ENTRY"
echo "  JOCKY leaks: $LEAKS"
echo "  .dynsym entries: $DYNCOUNT"
