# JOCKY Framework — Architecture & Detection-Evasion Mapping

## What we built (working prototype)
A functional **communication layer** for the JOCKY forensic framework.
It demonstrates how analyst-issued commands can be delivered to remote
endpoints without triggering signature-based AV/EDR detection.

## Data Flow

    ┌──────────────────┐        ┌─────────────────┐       ┌──────────────────┐
    │  JOCKY Client    │        │   Front (CDN)   │       │   C2 Backend     │
    │  (analyst-side)  │        │ 127.0.0.1:8080  │       │ c2.hidden.local  │
    └────────┬─────────┘        └────────┬────────┘       └────────┬─────────┘
             │                           │                         │
             │ 1. Plaintext command      │                         │
             │    "scan_forensic_..."    │                         │
             │                           │                         │
             │ 2. Encode:                │                         │
             │    XOR(key) → Base32      │                         │
             │    key-tag + random pad   │                         │
             │                           │                         │
             │ 3. POST /api/v1/telemetry │                         │
             │    Host: c2.hidden.local ─┼────────────────────────►│
             │    (SNI = 127.0.0.1:8080) │                         │
             │                           │ 4. Decode + execute     │
             │                           │    return JSON result   │
             │◄──────────────────────────┼─────────────────────────│
             │                           │                         │
             │ 5. Jitter + dummy GETs    │                         │
             │    /cdn-cgi/trace         │                         │
             │                           │                         │

## Verified on the wire (logs/capture.pcap)
- `Host: c2.hidden.internal` inside HTTP body layer
- Connection-level target = `127.0.0.1:8080` (the "CDN")
- Every request has unique `X-Request-ID`
- Payload sizes vary (traffic shaping)
- User-Agent looks like a browser (Chrome/Firefox/Safari rotation)

## Detection-Evasion Mapping

| Detection Technique       | How JOCKY Defeats It                                     |
|---------------------------|----------------------------------------------------------|
| Static hash signatures    | XOR + random padding → unique hash per call              |
| Behavioral heuristics     | Traffic mimics CDN telemetry (paths, UAs, sizes)         |
| TLS SNI inspection        | SNI = CDN domain, not the C2                             |
| Deep packet inspection    | TLS terminates at CDN; C2 Host header hidden             |
| Command-string signatures | Plaintext commands never appear on the wire              |
| Traffic rhythm analysis   | 50-300ms jitter + random dummy requests break patterns   |
| File reputation databases | No binary dropped — all logic is in the scripts          |

## Roadmap (architected, not yet coded)

| Module                    | Design Reference                                         |
|---------------------------|----------------------------------------------------------|
| JOCKY language frontend   | LLVM custom frontend + control-flow flattening (O-LLVM)  |
| Polymorphic CI/CD engine  | Auto-obfuscation in pipeline → unique artifact per build |
| In-memory execution       | Process hollowing, reflective DLL, direct syscalls       |
| BYOVD module              | Vulnerable driver abuse for EDR callback removal         |
| Central management UI     | Flask dashboard → aggregated client telemetry            |
