> **Version:** 5.0
> **Date:** 2026-09-26
> **Status:** Working prototype — comms + crypto + dashboard + custom LLVM frontend
> **Changes from V2:** Added JOCKY language frontend (custom .jky syntax,
> lexer, parser), LLVM IR codegen with control-flow flattening, and native
> binary compilation. Requirement 1 from the problem statement is now
> demonstrated with wire-level and disassembly-level proof.> **Version:** 2.0
> **Date:** 2026-09-26
> **Status:** Working prototype — communication layer + crypto + dashboard
> **Changes from V1:** Added structured protocol (Phase C), real cryptography
> (ECDH + AES-256-GCM, Phase B), and central management dashboard with
> multi-client support (Phase A). See Appendix at the bottom.

---

## PROJECT STATUS AT A GLANCE

| Requirement | Coverage | Evidence |
|---|---|---|
| 1. LLVM frontend + CFG alteration | 75% | `demo/test.bin` runs; no plaintext commands in `strings` |
| 2. Polymorphism (unique hash per call) | 50% | `logs/c2.log` shows 3 hashes for same input |
| 3A. In-memory execution | 60% | `memfd_exec.py` + `syscall_direct.py` verified |
| 3B. BYOVD / kernel subversion | 0% | Documented only |
| 4. Multi-system + management UI | 85% | Dashboard shows 15 sessions, 48 tasks |
| 5. Domain fronting comms | 75% | Wire capture: SNI ≠ Host, ciphertext opaque |
| **Weighted total** | **~58%** | |

**Three demo entry points:**
1. `python3 src/mock_cdn_server.py` + browser to `http://127.0.0.1:8080/dashboard` → visual management UI
2. `python3 llvm/codegen.py demo/test.jky && clang ... && ./demo/test.bin` → compiler + CFG flattening proof
3. `python3 src/inmem_chain.py` → file-less execution end-to-end

# JOCKY Framework — Master Notes
### SIH Problem ID: 26148 | Team Handoff Document

---

## PART 1: WHAT IS THIS PROJECT? (For someone with zero context)

### The Problem in One Paragraph
Modern antivirus and EDR (Endpoint Detection & Response) software block
custom forensic analysis tools. They do this by looking at file hashes,
code signatures, behavioral patterns, and compiler artifacts. This makes
it very hard for security analysts to run their OWN forensic tools on
machines they are authorized to analyze. The National Technical Research
Organisation (NTRO) has asked for a solution: a new framework that can
deliver forensic commands to endpoints without being blocked.

### Our Solution: JOCKY
JOCKY is a framework with two big ideas:

1. **A new programming language** ("JOCKY") that produces binaries and
   scripts which don't match known signatures — because the compiler
   itself is custom, so no standard MSVC or GCC fingerprints appear.

2. **A communication layer** that hides the command traffic inside normal
   looking internet traffic (CDN requests, cloud APIs) so that network
   monitoring can't tell the difference between JOCKY and a browser
   loading a webpage.

### What We Actually Built (the prototype)
We built and demonstrated **only the communication layer** — the part that
sends forensic commands from an analyst to an endpoint. It works. It's
captured on the wire. Everything else (the compiler, the CI/CD pipeline,
the in-memory execution, the kernel driver part) is **architected and
documented but not yet coded**.

This is honest, and it's fine — SIH explicitly allows incomplete prototypes.
What judges want to see is that you understand the hard parts and have
proven the core idea works.

---

## PART 2: THE THREE PILLARS OF JOCKY

The problem statement describes three techniques that JOCKY uses to avoid
detection. Here is what each one means and where we stand.

### Pillar 1: Independent Programming Language (Compiler-Level Evasion)

**What it is:**
Standard compilers (Microsoft's MSVC, GNU's GCC/Clang) leave behind
"fingerprints" — recognizable code patterns, import tables, section layouts.
Antivirus vendors have signature databases for these. If you compile a
forensic tool with GCC, AV may flag it because it "looks like" other GCC
tools.

**How JOCKY solves it:**
Instead of building on GCC or MSVC, JOCKY uses **LLVM** as a foundation and
adds a **custom frontend**. LLVM is a compiler framework — it lets you
create your own programming language that translates to machine code.
Before the code reaches the CPU, JOCKY's frontend transforms it:
- **Control-flow flattening** — code that looks like an if/else becomes a
  loop with a "dispatcher" state machine. Hard for AV to follow.
- **Bogus control flow** — inserts fake branches that never execute but
  confuse static analyzers.
- **Instruction substitution** — replaces simple operations (like `x + 1`)
  with equivalent but unusual ones (`x - (-1)`).
- **Basic block splitting** — breaks code into smaller chunks and reorders
  them.

**Where we stand:**
❌ Not coded. ✅ Architected. Existing tool: **Obfuscator-LLVM (O-LLVM)** —
a fork of LLVM that already implements these four transformations. Reference
this in the presentation as proof of feasibility.

**How to explain it in 20 seconds:**
> "We use LLVM as a base and add a custom compiler layer that rewrites the
> code's control flow before it becomes a binary. Every compile produces
> a different looking program with identical behavior, so signature databases
> can't keep up."

---

### Pillar 2: Polymorphic Scripts via CI/CD

**What it is:**
"Polymorphic" means "changes shape every time." Instead of manually writing
one version of a tool and getting caught, the framework generates a new
version every time it's deployed — automatically.

**How JOCKY solves it:**
When a new script is ready, it goes through an automated pipeline:
1. Run obfuscators (variable renaming, string encryption)
2. Randomize entry points
3. Add random padding and junk data
4. Repackage with a new hash
5. Deploy

Result: identical functionality, different hash and structure every single
time.

**Where we stand:**
✅ Partially demonstrated. Our `c2_channel.py` proves the core: same command
like `collect_system_info` encodes to a **different hash on every call**.
We captured this in the logs.

**Evidence from our logs:**
    iteration 1: 7QR6PZ3EVDSKMYRC4TR2LQ====ZXZ  sha256=5157dbf8df2a60f8
    iteration 2: XIZHM5XVHF2TP45TOVZDIQ====YXZ  sha256=e218e8108928c0f6
    iteration 3: DANN5XS5SHOZ6WY33XNJZQ====ZXZ  sha256=240ed1c21195647e

Same input, three different hashes. That is polymorphism, demonstrated.

**How to explain it in 20 seconds:**
> "Every command is encoded with a fresh XOR key and random padding. The
> server reads the key from a tag inside the payload itself. The same
> command produces a different file hash every time, defeating static
> signature detection."

---

### Pillar 3: Living-off-the-Land & BYOVD Execution

This pillar has two sub-parts. Both are about executing the forensic tool
without triggering real-time monitoring.

#### Part A: In-Memory Execution (File-less Techniques)

**What it is:**
Instead of dropping a `.exe` on disk (which AV scans), the tool runs
**entirely inside RAM** by injecting into a legitimate process (like
`explorer.exe` or `svchost.exe`).

**Techniques referenced in the problem statement:**
- **Process hollowing** — start a legitimate process, replace its code
  with yours, let it run
- **Reflective DLL injection** — load a DLL from memory instead of disk
- **API unhooking** — remove AV hooks that were placed in your process
- **Direct system calls** — bypass the Windows API layer and talk to the
  kernel directly
- **Thread execution hijacking** — hijack an existing thread to run your
  code

**Where we stand:**
❌ Not coded. This requires Windows-specific techniques. It's also a
long-running research area (months of work).

**Why this is OK to leave for later:**
SIH judges know these techniques take time. Reference them, show you
understand them, and move on.

#### Part B: BYOVD (Bring Your Own Vulnerable Driver)

**What it is:**
A very specific attack: legitimate drivers from third-party vendors often
have vulnerabilities. Attackers can load these **signed** drivers (signed =
trusted by Windows) and use them to disable EDR/AV from **inside the kernel**.

**How the chain works (from public research):**
1. DLL side-loading to get code running
2. PE loader to load a second-stage payload in memory
3. In-memory EDR killer runs
4. Vulnerable driver loaded (e.g., `rwdrv.sys`, `hlpdrv.sys`)
5. EDR kernel callbacks removed
6. EDR services terminated

**Specific drivers referenced in research:**
- `ThrottleStop.sys` (often renamed to `rwdrv.sys`) — physical memory access
- `hlpdrv.sys` — process termination engine

**Where we stand:**
❌ Not coded. This is legally and ethically sensitive — we only document
it as a technique defenders must know about. In the JOCKY framework, this
would be a **detection module** (the analyst uses JOCKY to detect these
techniques on a compromised machine), not an attack tool.

**How to explain it in 20 seconds:**
> "BYOVD is when attackers use legitimate but vulnerable drivers to disable
> endpoint protection from the kernel. Our framework detects this activity.
> We don't build attack tools — we build the forensic lens to see them."

---

## PART 3: WHAT WE ACTUALLY BUILT (Technical Deep Dive)

### The Communication Layer — How It Works

**Two programs:**

1. **Client** (`src/c2_channel.py`) — the analyst's tool. Encodes commands
   and sends them.
2. **Server** (`src/mock_cdn_server.py`) — simulates both the CDN front
   (what the internet sees) and the C2 backend (what actually receives
   the command).

**The full path of one command:**

    [Client]
       |
       | 1. Plaintext: "collect_system_info"
       | 2. XOR with random key (e.g., 159)
       | 3. Base32 encode
       | 4. Add 2-char key tag + 3-char random suffix
       | 5. Send via HTTPS to CDN address
       |
       v
    [CDN Front: 127.0.0.1:8080]  ← what network sees
       |
       | Host header carries: "c2.hidden.internal"
       | (this only visible to the CDN, not the network)
       |
       v
    [C2 Backend]  ← reads Host header, decodes payload
       |
       | 6. Read key from first 2 chars
       | 7. Strip suffix
       | 8. Base32 decode, XOR decode
       | 9. Execute command, return result
       |
       v
    [Response back to Client]

### Why This Defeats Detection

| Detection Method | Why It Fails |
|------------------|--------------|
| File hash signatures | Every payload has a different hash |
| Command-string scanning | Plaintext never appears on the wire |
| TLS SNI inspection | SNI says "cdn.example.com", not the real C2 |
| Deep packet inspection | TLS terminates at the CDN; C2 Host header stays hidden |
| Traffic rhythm analysis | Random 50–300ms jitter + dummy requests break patterns |
| User-Agent profiling | Rotates between Chrome, Firefox, Safari UAs |
| Behavioral heuristics | Traffic looks like normal CDN telemetry |

### The Proof

**File:** `logs/capture.pcap` (16 KB, real packet capture)

**What's inside (from our grep):**
    Host: c2.hidden.internal          ← the real destination
    X-Request-ID: 982f916f64e93334    ← unique every time
    Content-Length: 46                ← payload size varies
    User-Agent: Mozilla/5.0 ...       ← browser disguise

A passive network monitor sees a browser talking to a CDN. They don't see
`collect_system_info` anywhere, because it's encoded.

---

## PART 4: HOW TO RUN THE DEMO

### Setup (one time)

Open a terminal in Kali and run:

    cd /home/kali/Rudhra/Jocky
    pip install --break-system-packages requests cryptography flask

### During the Demo (3 terminals)

**Terminal 1 — C2 server:**
    cd /home/kali/Rudhra/Jocky
    python3 src/mock_cdn_server.py

Leave running. You will see log output as commands arrive.

**Terminal 2 — Client:**
    cd /home/kali/Rudhra/Jocky
    python3 src/c2_channel.py

Watches three tests:
- Round-trip encode/decode
- Polymorphism (same input, different hash)
- Three commands sent to server

**Terminal 3 — Packet capture (optional but powerful):**
    cd /home/kali/Rudhra/Jocky
    sudo tcpdump -r logs/capture.pcap -A 2>/dev/null | grep -B 1 -A 4 "Host:"

Shows the wire-level evidence.

---

## PART 5: THE DEMO SCRIPT (2 minutes, memorize this)

Say this while showing the terminals:

> **[Show Terminal 1]**
> "This is the C2 backend. Clean output, ready to receive commands."
>
> **[Show Terminal 2, run client]**
> "Watch this. I send three forensic commands. Notice the hashes — all
> different, even though two commands are the same. That's polymorphic
> encoding."
>
> **[Switch to Terminal 1]**
> "Here's the server receiving them. See these two lines?
> SNI shows 127.0.0.1:8080 — that's the CDN front, what the network sees.
> Host shows c2.hidden.internal — that's the real destination.
> This separation is called domain fronting."
>
> **[Show Terminal 3]**
> "And here's the packet capture. Same request on the wire.
> A passive defender sees a browser talking to a CDN. The command
> `collect_system_info` never appears in plaintext."
>
> **[Open docs/architecture.md]**
> "Every modern detection technique mapped against how we defeat it."
>
> **[Close]**
> "This is our communication layer. It's working and captured on the wire.
> The compiler, CI/CD pipeline, in-memory execution, and BYOVD detection
> are architected with references to real-world attack chains. That's the
> roadmap for the next phase."

---

## PART 6: ANTICIPATED JUDGE QUESTIONS & ANSWERS

**Q: Is this actually a real C2, or a mock?**
A: A mock, intentionally. We simulate the CDN front and C2 backend on
localhost. In production, the CDN would be Cloudflare or AWS CloudFront,
and the C2 would be behind it. The protocol is identical — our capture
proves that.

**Q: How does this differ from existing tools like Cobalt Strike?**
A: Cobalt Strike is a commercial red-team tool. Our framework is designed
for **defensive forensic analysis** on systems the analyst is authorized
to examine. The communication-layer techniques overlap because the
underlying network problems are the same, but the purpose is different.

**Q: What about legal and ethical concerns?**
A: Everything runs in an isolated VM. We're not attacking anything. The
BYOVD section is documentation of an attacker technique so defenders can
recognize it. We do not build attack tools.

**Q: Why only the communication layer?**
A: Because it's the piece with the highest research uncertainty. The
compiler layer is engineering (O-LLVM exists), the in-memory execution
is well-documented (Lazarus's RemotePE), the BYOVD chain is published
research. The communication layer is where we needed to prove our design
works. We did.

**Q: What's the roadmap?**
A:
- Phase 1 (done): communication layer prototype
- Phase 2: LLVM frontend for JOCKY language
- Phase 3: CI/CD polymorphic pipeline
- Phase 4: In-memory execution module
- Phase 5: BYOVD detection module
- Phase 6: Central management dashboard

**Q: How is this better than a VPN or Tor?**
A: VPN and Tor are for user privacy — they hide where YOU are. JOCKY
hides the COMMAND traffic as normal web requests to a CDN. It doesn't
hide the analyst; it hides the content of the forensic instructions.

---

## PART 7: GLOSSARY (if someone asks "what does X mean?")

- **AV** — Antivirus. Scans files and processes for known bad signatures.
- **EDR** — Endpoint Detection & Response. Advanced AV that watches
  behavior in real time.
- **C2** — Command & Control. The server that sends instructions to a
  deployed tool and receives results.
- **SNI** — Server Name Indication. A field in the TLS handshake that says
  which domain the client wants. Visible to network monitors.
- **Host Header** — An HTTP-level field that says which site the request
  is for. Only visible after TLS is decrypted.
- **Domain Fronting** — Sending TLS to one domain (the front) but HTTP to
  another (the backend). The front domain must be a trusted CDN that
  forwards the Host header.
- **CDN** — Content Delivery Network. Cloudflare, Akamai, CloudFront, etc.
  Legitimate infrastructure, often abused for domain fronting.
- **TLS** — Encryption layer for HTTPS. Encrypts content but the SNI is
  visible unless you use Encrypted Client Hello (ECH), which is rare.
- **XOR** — A simple bit-flip encryption. Symmetric: same key encrypts
  and decrypts.
- **Base32** — Encoding that turns bytes into a text-safe alphabet of
  32 characters. Not encryption — just representation.
- **Polymorphism** — The property of producing different outputs (hashes,
  structures) from the same input each time.
- **BYOVD** — Bring Your Own Vulnerable Driver. An attack technique that
  loads a legitimate but flawed kernel driver to disable protections.
- **LLVM** — A compiler framework. Not a language itself; a foundation for
  building compilers.
- **O-LLVM** — Obfuscator-LLVM. A fork of LLVM that adds obfuscation
  passes (control-flow flattening, bogus flow, etc.).
- **In-memory execution** — Running code without writing it to disk. Also
  called "fileless."
- **Process hollowing** — Starting a legitimate process, emptying its
  memory, and putting your own code in.
- **Reflective DLL injection** — Loading a DLL from memory instead of disk.
- **Living-off-the-land** — Using legitimate built-in system tools
  (`powershell`, `wmic`, `certutil`) to do the attacker's work.

---

## PART 8: WHAT TO SAY IF YOU DON'T KNOW SOMETHING

Do not invent. Say:

> "That's outside what we've prototyped. It's on the roadmap, and we have
> design references for it. I can walk you through the architecture if
> you'd like."

Then open `docs/architecture.md` and point at the roadmap table.

Judges prefer honest confidence over fabricated expertise. Every time.

---

## PART 9: FILE INDEX (what's where)

    JOCKY/
    ├── JOCKY_MASTER_NOTES.md     ← THIS FILE
    ├── README.md                  ← Quick-start guide
    ├── docs/
    │   └── architecture.md        ← Design + detection-evasion mapping
    ├── src/
    │   ├── c2_channel.py          ← Client (encoder + sender)
    │   └── mock_cdn_server.py     ← Server (decoder + executor)
    └── logs/
        ├── c2.log                 ← Client sends
        ├── c2_backend.log         ← Server decodes + results
        ├── traffic.log            ← Full metadata per request
        └── capture.pcap           ← Wire-level proof

---

## PART 10: IF SOMETHING BREAKS TOMORROW

### "Server won't start — port 8080 in use"
    sudo lsof -i :8080
    sudo kill -9 <PID>

Or change the port in both files to 8081.

### "Client fails with Connection refused"
Terminal 1 (server) is not running. Start it first.

### "Import errors"
    pip install --break-system-packages requests cryptography flask

### "tcpdump says permission denied"
    sudo tcpdump ...

### "Everything is broken, I need to start over"
Restore from backup:
    cp -r /home/kali/Rudhra/Jocky_BACKUP_2026-09-25/* /home/kali/Rudhra/Jocky/

Or restore the VMware snapshot named `JOCKY-demo-ready`.

---
---

## APPENDIX: PHASES C, B, A (Post-MVP Upgrades)

After the initial communication-layer prototype, we implemented three
progressive upgrades. Each one is functional and verified.

### Phase C — Structured Command Protocol
- UUID per task, JSON schema, protocol versioning
- Command registry with args validation
- Discovery endpoint: `GET /api/v1/commands`
- Persistent task store: `logs/tasks.jsonl`
- Status machine: complete | pending | error

### Phase B — Real Cryptography
- **ECDH P-256 key exchange** — shared secret never transmitted
- **HKDF-SHA256** — derives AES-256 key from shared secret
- **AES-256-GCM** — authenticated encryption with per-message nonce
- **Session IDs** — server tracks concurrent sessions
- **Replay protection** — counter in Additional Authenticated Data (AAD)
- Verified: same `shared_secret_sha256` on client and server, plaintext
  commands never appear on the wire.

### Phase A — Central Dashboard + Multi-Client
- Live web UI at `http://127.0.0.1:8080/dashboard`
- Auto-refreshes every 3 seconds
- Shows: active sessions, command count, success rate, recent tasks,
  domain-fronting evidence (SNI vs Host per request)
- `src/multi_client.py` spawns N concurrent endpoints, each with its own
  ECDH session, running different command playlists
- Demonstrated: 9 sessions, 34 commands, 100% success rate simultaneously

### Files Added
    src/protocol.py         Structured command schema
    src/crypto.py           ECDH + HKDF + AES-256-GCM
    src/dashboard.py        Flask web dashboard blueprint
    src/multi_client.py     Concurrent endpoint simulator
    logs/sessions.jsonl     ECDH handshake log
    logs/tasks.jsonl        Persistent task store

### Updated Demo Script (2 minutes)

1. **Start server**: `python3 src/mock_cdn_server.py`
2. **Open dashboard** in browser: `http://127.0.0.1:8080/dashboard`
3. **Fire multi-client**: `python3 src/multi_client.py` in another terminal
4. **Watch dashboard** populate live — sessions, tasks, ciphertext hashes
5. **Point at the Domain Fronting table** — this is the visual proof that
   SNI ≠ Host per request, and every ciphertext hash is unique.
6. **Close with**: "This is JOCKY's communication layer, running with real
   cryptography, structured protocol, and central management. The compiler
   frontend, CI/CD polymorphism, and BYOVD detection are architected and
   mapped. That's the roadmap."

---

## APPENDIX V3: JOCKY Language Frontend (Requirement 1)

### What was built
A working compiler frontend for the JOCKY language that:
1. Parses `.jky` source files with a custom lexer + recursive-descent parser
2. Generates valid LLVM IR via llvmlite
3. Applies control-flow flattening to every function body
4. Compiles to native x86-64 ELF binaries via stock clang

### Files added
    llvm/lexer.py           Tokenizer for .jky syntax
    llvm/parser.py          Recursive-descent parser → AST
    llvm/codegen.py         AST → LLVM IR + control-flow flattening
    llvm/runtime.c          jocky_cmd() C stub for linking
    demo/test.jky           Sample JOCKY program
    demo/test.ll            Generated LLVM IR
    demo/test.bin           Compiled native binary

### Language features supported
- `let x = 5;`                variable declarations
- `fn f(a, b) { ... }`        function definitions
- `@collect system_info;`     forensic command invocations
- `if x > 5 { ... } else {}`  conditionals
- `for i in 0..10 { ... }`    loops
- `return expr;`              returns
- `// comments` and `# comments`

### Control-flow flattening
Every function body is transformed into a dispatcher loop where each
original basic block becomes a case. Verified at three levels:

1. **IR level** — `grep -c dispatcher demo/test.ll` → 21 dispatchers
2. **Binary level** — `objdump -d demo/test.bin` shows all back-edges
   jumping to a common `115b` (the dispatcher head)
3. **String level** — `strings demo/test.bin | grep -iE "collect|scan"` →
   nothing. All command names are hashed at compile time.

### Command hashing
Command names are converted to 64-bit hashes via FNV-1a during codegen.
The binary contains only integer hashes; no plaintext forensic command
names appear anywhere in the compiled artifact.

### Proof artifact
`/home/kali/Rudhra/R1_llvm_proof/` — frozen snapshot of the full toolchain
plus compiled binary. The demo output shows:
    [jocky] cmd_hash=6523cf48968997df  args=1
    [jocky] cmd_hash=48cb8bb37c57b5af  args=2
    ---exit: 0---

### How to run
    cd /home/kali/Rudhra/Jocky
    python3 llvm/codegen.py demo/test.jky
    llvm-as demo/test.ll -o /dev/null && echo "IR valid"
    clang -c demo/test.ll -o demo/test.o
    clang demo/test.o llvm/runtime.o -o demo/test.bin
    ./demo/test.bin
    strings demo/test.bin | grep -iE "collect|scan" || echo "no plaintext commands"
**End of document.**

---

## APPENDIX V4: In-Memory Execution (Requirement 3A)

### What was built
Three new modules demonstrate file-less execution on Linux:

    src/memfd_exec.py       Load binary into anonymous memfd, execute via /proc/self/fd
    src/syscall_direct.py   Invoke raw Linux syscalls from hand-assembled x86-64 stub
    src/inmem_chain.py      End-to-end: .jky source → flattened binary → execute from RAM

### Proof: file-less execution
    [memfd] fd -> /memfd:jocky_payload (deleted)
    find / -name "jocky_payload*"  → empty
    ls /tmp/*.bin /var/tmp/*.bin   → empty

The memfd exists only in kernel memory. The `(deleted)` marker in
/proc/self/fd proves no filesystem inode was ever assigned.

### Proof: direct syscalls
    [*] RWX stub mapped at: 0x7f5aca286000
    [*] Stub bytes: 4889f84889f74889d64889ca4d89c24d89c80f05c3

    [syscall] getpid()  = 191735
    [verify]  os.getpid() = 191735
      ✓ direct syscall matches libc wrapper

The stub is hand-assembled machine code (mov rax,rdi; mov rdi,rsi; ...; syscall; ret).
libc was never called. This is the "direct system calls" technique from the
problem statement.

### Proof: full chain
    [chain] Compiling test.jky
    [chain]   ✓ LLVM IR valid
    [chain]   ✓ Binary: payload.bin (16096 bytes)
    [chain]   ✓ No plaintext commands found
    [chain] Reading binary into memory
    [chain]   ✓ 16096 bytes in RAM
    [chain] Deleting disk artifacts before execution
    [chain]   deleted payload.bin, payload.o, payload.ll, /tmp/jocky_pna955ml
    [chain] Executing from anonymous memory
    [memfd] fd -> /memfd:jocky_payload (deleted)
    [jocky] cmd_hash=6523cf48968997df  args=1
    [memfd] child exited 0
    [chain] ✓ Full chain complete — nothing on disk

### How to run
    cd /home/kali/Rudhra/Jocky
    python3 src/memfd_exec.py demo/test.bin
    python3 src/syscall_direct.py
    python3 src/inmem_chain.py

### Why this matters
The problem statement requires "multiple distinct file-less techniques
(e.g., process hollowing, reflective DLL injection, API unhooking,
direct system calls)". We implemented:

  - File-less execution via memfd (Linux analogue of reflective DLL injection)
  - Direct system calls via raw syscall instruction (identical technique)

Both verified working on Linux x86-64. The Windows-specific variants
(process hollowing via VirtualAllocEx + WriteProcessMemory, thread
hijacking via SetThreadContext) are architecturally equivalent and
documented as roadmap items.

---

## APPENDIX V5: Production Readiness

### Real forensic logic (src/forensic_real.py)
Replaced demo stubs with real system inspection:
  - collect_system_info           → psutil + platform + socket
  - list_processes                → psutil.process_iter
  - enumerate_network_connections → psutil.net_connections
  - scan_forensic_artifacts       → Path.rglob + suffix filter
  - check_persistence             → Path.exists on 8 known locations

Verified: 309 processes, 23 network connections, 6/8 persistence paths.

### Real Cloudflare CDN deployment
Worker URL:  https://jocky-cdn-front.g-surya-prakash.workers.dev
Tunnel URL:  https://builders-cloth-meaning-agencies.trycloudflare.com

Pattern: "Legitimate cloud APIs" (as allowed by the problem statement).
SNI and Host match (both workers.dev) so Cloudflare does not block.
Real C2 hidden behind the Worker.

Verified E2E: client → Cloudflare → tunnel → Flask → back, all 5 commands complete.

### CI/CD pipeline (.github/workflows/ci.yml)
GitHub Actions workflow runs on every push:
  - Installs LLVM + clang + Python deps
  - Compiles test.jky to binary
  - Verifies IR is valid
  - Asserts no plaintext commands in binary
  - Runs direct syscall demo
  - Runs full in-memory chain demo
  - Uploads build artifacts

### Binary-level mutation (llvm/codegen.py)
Every function name is randomized at compile time:
  before:  define i64 @"check_system"
  after:   define i64 @"f_3ihpu4nrfmv0"

Prevents symbol-table analysis from leaking function semantics.
Every compile produces different names. Signature databases cannot match.

### Requirement coverage after V5
  1. LLVM frontend + CFG alteration        90%
  2. Polymorphism + CI/CD                  85%
  3A. In-memory execution                  60%
  3B. BYOVD                                 0%
  4. Multi-system + management UI          85%
  5. Domain fronting (Cloudflare)          95%
  Weighted total                          ~85%

---

## APPENDIX V5.3 --- Post-V5 Additions

### 1. ELF Entry Point Mutation (src/elf_mutate.py)

Reads a compiled PIE binary, finds the tail padding inside the executable
segment, writes a 5-byte relative jump (E9 <rel32>) to the original _start,
and updates e_entry in the ELF header to point at the stub.

Effect per build:
  Before: e_entry = 0x1150 (constant across all builds)
  After:  e_entry = 0x1fXX (unique per build, randomized within padding)

Every JOCKY binary now has a different entry point. Signature scanners
that hash entry-point bytes fail.

Verified: readelf -h shows the new entry point; the binary runs identically.

### 2. Import Table Augmentation (src/dynsym_inject.py + build_jocky.sh)

The build pipeline generates a C file with N random-looking dummy symbols
per build, compiles it to an object, and links it into the final binary
with -Wl,--export-dynamic. The symbols are exported to .dynsym but never
called or referenced by any relocation.

Dummy symbol names blend with legitimate runtime scaffolding:
  __dso_25f3d902   __libc_045ad467   _ITM_3ba13f5e   _Jv_02d293ec

Effect per build:
  .dynsym entries:    varies (49, 53, 52, ...)
  .dynsym byte hash:  differs per build
  Binary size:        varies by a few bytes

Alters the import table fingerprint that static scanners use.

Verified: readelf --dyn-syms shows the dummy symbols; binaries run
identically; zero JOCKY leaks confirmed with strings.

### 3. Six-Layer Obfuscation Stack

  1. Control-flow flattening       (codegen_v2.py: dispatcher pattern)
  2. Function name randomization   (codegen_v2.py: f_<random>)
  3. Runtime symbol randomization  (build_jocky.sh: <prefix>_<letter>)
  4. Binary stripping              (clang -Wl,-s)
  5. ELF entry point mutation      (elf_mutate.py)
  6. Import table augmentation     (dynsym_inject.py)

Every build produces a structurally different binary. Same forensic
output. Zero plaintext semantics. Verified across 4 scripts.

### 4. Multi-Namespace Test (src/multi_namespace_test.py)

Demonstrates cross-machine analysis using Linux network namespaces:
  - 3 namespaces (jky_ns0/1/2)
  - 3 distinct IPs (192.168.100.10/11/12)
  - 3 veth pairs and a host bridge (jky_br0 at 192.168.100.1)
  - 3 JOCKY clients launched in parallel
  - Server records distinct source IPs per session

Each client has its own ECDH session key. The dashboard aggregates them.
Verifiable: sudo ip netns exec jky_ns0 ip addr.

This is not a localhost simulation --- the kernel provides real network
stack isolation. Strongest multi-system demo on a single VM.

### 5. Local CI/CD Pipeline (.git/hooks/pre-commit)

Real git hook that runs on every commit:
  [1/5] Compiles demo/test.jky to LLVM IR
  [2/5] Validates IR with llvm-as-21
  [3/5] Builds sys_fingerprint.jky end-to-end
  [4/5] Verifies zero leaks in the compiled binary
  [5/5] Verifies entry point is mutated (not 0x1150)

Refuses to let broken code through. Runs the same checks as
.github/workflows/ci.yml. Verified across 4 commits.

### 6. Bug Fixed by CI

The CI pipeline caught a real bug in codegen_v2.py --- the _declare_fn
method had a duplicate definition from an earlier sed edit. None of the
production JOCKY scripts use fn declarations, so the bug was invisible
in normal testing. CI caught it on the first commit attempt.

### 7. V5.3 Coverage Update

  1. LLVM frontend + CFG alteration        90%
  2. Polymorphism + CI/CD                  95%   (+10)
  3A. In-memory execution                  60%
  3B. BYOVD                                20%
  4. Multi-system + management UI          95%   (+10)
  5. Domain fronting (Cloudflare)          95%
  Weighted total                          ~82%

### 8. Git History

  c5f12d9  Gap 2: Alter import tables via linker-exported dummy symbols
  d976a65  Add V5.3 state document
  201d3b2  Add .gitignore --- exclude build artifacts
  12642b7  JOCKY V5.3: ELF entry point mutation + multi-namespace test + fixed compiler

### 9. Reference

Full state summary: docs/V5.3_STATE.md
Proof files: docs/requirement_*.txt


---

## APPENDIX V5.4 --- Permanent Cloudflare Deployment

### What Changed

V1-V5.3 used a Cloudflare quick tunnel with an ephemeral URL
(`random-words.trycloudflare.com`). Every restart required editing
the Worker and redeploying. This was fragile for demos.

V5.4 replaces the quick tunnel with:
  - A permanent domain: `jocky.dpdns.org` (DigitalPlat, free)
  - Cloudflare nameservers (chan.ns + lewis.ns.cloudflare.com)
  - A named Cloudflare Tunnel: `jocky`
  - Stable endpoint: `c2.jocky.dpdns.org`
  - Worker forwards to this stable domain

### Components

  Tunnel ID: 2eeac6dd-a1f4-436a-9d4c-8cb875d9ccbf
  Domain: c2.jocky.dpdns.org
  Worker URL: https://jocky-cdn-front.g-surya-prakash.workers.dev
  Local Flask: http://127.0.0.1:8080
  cloudflared: 2026.9.3

### Tunnel Config (~/.cloudflared/config.yml)

  tunnel: 2eeac6dd-a1f4-436a-9d4c-8cb875d9ccbf
  credentials-file: /home/kali/.cloudflared/2eeac6dd-a1f4-436a-9d4c-8cb875d9ccbf.json
  ingress:
    - hostname: c2.jocky.dpdns.org
      service: http://localhost:8080
    - service: http_status:404

### Verified End-to-End

  Handshake: session QHwSewVHBSlm, shared secret cbb02ba5870f491a
  5 encrypted commands dispatched through Cloudflare:
    - collect_system_info
    - list_processes (300 processes)
    - enumerate_network_connections (48 connections)
    - scan_forensic_artifacts (45 artifacts)
    - check_persistence (8 locations, 6 existing)

### Demo Commands (No Config Changes Ever)

  Terminal 1: python3 src/mock_cdn_server.py
  Terminal 2: cloudflared tunnel run jocky
  Terminal 3: JOCKY_FRONT=https://c2.jocky.dpdns.org python3 src/c2_channel.py

  Or via Worker: JOCKY_FRONT=https://jocky-cdn-front.g-surya-prakash.workers.dev python3 src/c2_channel.py

### Why This Is Production-Grade

  - Own domain, permanent on Cloudflare's free plan
  - Named tunnel survives reboots (can be installed as systemd service)
  - No URL changes ever
  - Traffic routes through Cloudflare's global anycast network
  - TLS 1.3 with Cloudflare's certificate

### To Make the Tunnel Persistent (Optional)

  sudo cloudflared service install
  sudo systemctl start cloudflared
  sudo systemctl enable cloudflared

  Then the tunnel starts automatically on boot. No manual `cloudflared tunnel run` needed.

---

## APPENDIX V7.0 — Multi-Endpoint Dispatch (Final Architecture)

### Architecture

Analyst workstation  →  Cloudflare (c2.jocky.dpdns.org)
                    →  Flask dispatch server (localhost:8080)
                    →  Tunnel to public dashboard
                         │
                         ├── Agent A  (10.200.1.10)
                         ├── Agent B  (10.200.1.11)
                         └── Agent C  (10.200.1.12)

Public dashboard:  https://dashboard.jocky.dpdns.org/dashboard
Public C2:         https://c2.jocky.dpdns.org/

### Components Added in V7.0

- src/jocky_agent.py      Persistent agent (poll, execute, report, heartbeat)
- src/dispatch.py         Server API (register/poll/report/heartbeat/dispatch)
- src/dispatch_cli.py     Analyst CLI (agents, dispatch, view)
- src/namespace_demo.sh   3-namespace multi-endpoint launcher (systemd-run)
- src/multi_agent_test.py Automated multi-agent test harness

### Auth Model

- Server enforces X-Jocky-Token on /api/v1/dispatch
- Agent enrollment key required on /api/v1/agent/register
- Secrets in ~/.jocky_secrets, loaded via source
- hmac.compare_digest for constant-time comparison

### Deployment Model

- Agents launched via systemd-run as transient units
- Auto-restart on failure (Restart=always, RestartSec=5)
- journalctl -u jocky-agent-a for logs
- Survive terminal close (fully detached from shell)

### Verified E2E (2026-09-29)

- 3 agents registered, distinct IPs 10.200.1.10/11/12
- Single dispatch → 57 findings per agent (171 total)
- Auth: 403 without token, 200 with
- Dashboard accessible from phone (real public HTTPS via Cloudflare)
- IST timestamps matching wall clock
- Multi-dispatch works (process_audit, user_audit, network_audit, etc.)

### Known Limitations

- All 3 agents currently run on the same host (in network namespaces)
- Real cross-VM deployment documented as roadmap
- Tier 4 binary parsing not implemented
