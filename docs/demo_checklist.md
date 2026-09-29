# JOCKY Demo — Pre-Flight Checklist

## Before each demo
Kill any stale processes:
    sudo pkill -f mock_cdn_server.py
    sudo pkill -f c2_channel.py
    sudo lsof -i :8080 || echo "port free"

Navigate to project:
    cd /home/kali/Rudhra/Jocky

---

## Demo 1 — In-memory execution chain (2 min)
    python3 src/inmem_chain.py

Watch for: "[chain] ✓ Full chain complete — nothing on disk"

---

## Demo 2 — Encrypted comms + live dashboard (3 min)

Terminal A:
    python3 src/mock_cdn_server.py

Terminal B:
    python3 src/multi_client.py

Browser:
    http://127.0.0.1:8080/dashboard

Watch for: 9+ sessions, 30+ commands, 100% success rate, live ciphertext hashes

---

## Demo 3 — Custom compiler + CFG flattening (2 min)
    python3 llvm/codegen.py demo/test.jky
    llvm-as demo/test.ll -o /dev/null && echo "IR valid"
    clang -c demo/test.ll -o demo/test.o
    clang demo/test.o llvm/runtime.o -o demo/test.bin
    ./demo/test.bin
    strings demo/test.bin | grep -iE "collect|scan" || echo "no plaintext commands"

Watch for: "IR valid" and "no plaintext commands"

---

## Demo 4 — Direct syscalls (1 min)
    python3 src/syscall_direct.py

Watch for: "✓ direct syscall matches libc wrapper" and "libc bypassed"

---

## Closing narrative (memorize)
"We built the hardest, most demonstrable slice of the problem:
a working compiler frontend, real cryptographic comms, a live
management dashboard, and file-less execution — all verified
on the wire and in memory. The remaining requirements are
architected with references to real-world techniques. What
we proved tonight is that the core framework is sound."

---

## If something breaks
Restore from backup:
    cp -r /home/kali/Rudhra/Jocky_V4/* /home/kali/Rudhra/Jocky/

Or revert the VMware snapshot named "JOCKY-V4-final".
