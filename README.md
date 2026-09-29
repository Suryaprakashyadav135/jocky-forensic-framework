# JOCKY — Forensic Command & Control Framework (v3.0)**SIH Problem ID:** 26148
**Category:** Software | **Theme:** Blockchain & Cybersecurity

## Overview
JOCKY is a Next-Gen framework for computer & network forensic analysis.
This repository contains a **working prototype of the communication layer**,
demonstrating how forensic commands can reach endpoints without triggering
signature-based or behavioral AV/EDR detection.

## Quick Start

### Terminal 1 — C2 backend
    cd ~/Rudhra/Jocky
    python3 src/mock_cdn_server.py

### Terminal 2 — client
    cd ~/Rudhra/Jocky
    python3 src/c2_channel.py

### Terminal 3 — capture proof (needs sudo)
    cd ~/Rudhra/Jocky
    sudo tcpdump -i lo -s 0 'tcp port 8080' -w logs/capture.pcap
    # run client, then Ctrl+C
    sudo tcpdump -r logs/capture.pcap -A | grep -A 3 "Host:"

## What's Implemented
- [x] Polymorphic encoder (XOR + Base32 + random padding → unique hash per call)
- [x] Domain fronting simulation (SNI ≠ Host header)
- [x] Traffic shaping (50-300ms jitter + random CDN dummy requests)
- [x] User-agent rotation (Chrome, Firefox, Safari)
- [x] Structured logging (client-side + server-side)
- [x] Wire-level proof captured to `logs/capture.pcap`
- [x] Architecture + detection-evasion mapping (`docs/architecture.md`)

## Verified On The Wire
From `logs/capture.pcap`:
    Host: c2.hidden.internal
    X-Request-ID: 982f916f64e93334    ← unique every time
    Content-Length: 46                ← variable payload size
    User-Agent: Mozilla/5.0 ...       ← browser disguise

## Roadmap
- LLVM-based JOCKY language frontend
- Polymorphic CI/CD pipeline
- In-memory execution (process hollowing, reflective DLL)
- BYOVD module for EDR callback removal
- Central management dashboard

## Files
    src/c2_channel.py         Client — encodes + sends commands
    src/mock_cdn_server.py    Server — receives + decodes + executes
    logs/c2.log               Client-side send log
    logs/c2_backend.log       Server-side decode + result log
    logs/traffic.log          Full request metadata
    logs/capture.pcap         Wire-level packet capture
    docs/architecture.md      Design + detection-evasion mapping
