---
title: "Phatbot / Agobot / ForBot"
description: "The most architecturally sophisticated bot family - P2P WASTE protocol, polymorphic engine, RSA crypto, and cross-platform builds (2003-2005)"
---

Phatbot, derived from **Agobot3**, represents the **most architecturally sophisticated** bot family in the archived collection. With **12 directory entries** (10 unique specimens), it pioneered techniques years ahead of other IRC bot families: decentralized peer-to-peer command and control, server-side polymorphism, RSA-authenticated commands, and cross-platform build systems.

> **Educational context:** This analysis is based on static source-code inspection of historical specimens. All source references link to the [maestron/botnets](https://github.com/maestron/botnets) public archive.

---

## Historical Context

### The Agobot → Phatbot Lineage

```
2002    Agobot v1 - by Ago (German author)
2003    Agobot v2/v3 - modular rewrite, exploit framework
2003-04 Phatbot fork - adds WASTE P2P, polymorphism, RSA
2004-05 ForBot/Phatbot-stoney variants - community derivatives
```

While contemporary IRC bots (sdBot, rBot) were evolving through incremental feature addition, Phatbot took a fundamentally different architectural approach. It was designed from the ground up as a **professional software product** with enterprise-grade engineering practices.

[View source - Phatbot-stoney](https://github.com/maestron/botnets/tree/master/VirusPack)

---

## Key Differentiators vs. IRC Bots

| Feature | IRC Bots (rBot/sdBot) | Phatbot |
|---------|----------------------|---------|
| C2 Architecture | Single IRC server (SPOF) | P2P mesh network (no SPOF) |
| Command Auth | Password + hostmask | RSA digital signatures |
| AV Evasion | String encryption | Full polymorphic engine |
| Build System | Single compiler target | Cross-platform (MSVC, Borland, MinGW) |
| IRC Security | Optional Blowfish (later) | Native SSL support |
| Code Organization | Evolving modular | Professional OOP from inception |
| Resilience | Dual-server failover | Distributed mesh - survives partial takedown |

---

## WASTE P2P Protocol - Decentralized C&C

### Architecture

The WASTE protocol implementation in `p2p.cpp` represents the most significant architectural innovation in the collection. Instead of all bots connecting to a single IRC server (a single point of failure), Phatbot bots form a **distributed mesh network**.

### How It Works

```
Phase 1: Bootstrap
  New bot → connects to hardcoded "seed" node (port 24288)
  Seed node → returns list of known peers

Phase 2: Mesh Formation
  New bot → connects to received peers
  Peers → exchange their own peer lists
  Bot → builds local routing table of the mesh

Phase 3: Command Distribution
  Operator → issues command to any node
  Node → broadcasts command to all connected peers
  Each peer → forwards to its peers (with dedup cache)
  Result → command propagates across entire mesh

Phase 4: Maintenance
  Bots periodically → exchange peer lists
  Dead peers → pruned from routing tables
  New bots → continuously integrated via seed nodes
```

### Command Broadcast with Deduplication

To prevent infinite command loops in the mesh, Phatbot implemented a **command caching system**:

```c
// Pseudocode - P2P command deduplication
typedef struct {
    uint32_t command_hash;
    time_t   first_seen;
} CMD_CACHE_ENTRY;

CMD_CACHE_ENTRY cmd_cache[MAX_CACHE_SIZE];

bool ProcessP2PCommand(char* cmd) {
    uint32_t hash = ComputeHash(cmd);
    
    // Check if we've seen this command before
    for (int i = 0; i < cache_count; i++) {
        if (cmd_cache[i].command_hash == hash)
            return false;  // Already processed - drop
    }
    
    // New command - process and cache
    AddToCache(hash, time(NULL));
    ExecuteCommand(cmd);
    BroadcastToPeers(cmd);  // Forward to all peers
    return true;
}
```

### Resilience Properties

The P2P architecture provided several resilience advantages:

| Property | Mechanism |
|----------|-----------|
| **No single point of failure** | Removing any individual node does not disable the network |
| **Takedown resistance** | Law enforcement must neutralize a significant fraction of nodes simultaneously |
| **Self-healing** | Surviving nodes automatically reconnect and rebuild routing tables |
| **Scalable** | Each node only maintains connections to a subset of peers |

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Implementation |
|---|---|---|
| T1102.002 | Bidirectional Communication | WASTE P2P mesh network |
| T1008 | Fallback Channels | P2P provides inherent fallback via alternate paths |
| T1104 | Multi-Stage Channels | Seed nodes → peer discovery → mesh communication |

:::note[Historical Significance]
Phatbot's P2P C2 architecture predated GameOver Zeus (which used P2P extensively) by nearly a decade. It demonstrated the concept that would later make takedowns of advanced botnets extremely difficult for law enforcement.
:::

---

## Polymorphic Engine

### Server-Side Binary Morphing

The `polymorph.cpp` file contains a powerful polymorphic engine that **changes the bot's binary structure every time it spreads**. This is fundamentally different from simple string encryption - it alters the entire executable.

### Morphing Process

```
Step 1: Read own executable file into memory

Step 2: Select random encryption algorithm
         Options: XOR, ROL (rotate left), ROR (rotate right),
                  word-swap

Step 3: Generate random encryption key

Step 4: Encrypt main code section (.text) and data section (.data)
         using selected algorithm + key

Step 5: Generate custom decoder stub
         - Stub decrypts .text and .data at runtime
         - Stub itself is different each time (register selection,
           instruction ordering varies)

Step 6: Prepend decoder stub to binary

Step 7: Modify PE header entry point to decoder stub

Step 8: Write morphed binary to disk for spreading
```

### The Result

Every single copy of Phatbot that spreads has a **unique binary signature**:

| Component | Static? |
|-----------|---------|
| Decoder stub | Different each copy (random registers, ordering) |
| Encryption algorithm | Randomly selected per copy |
| Encryption key | Randomly generated per copy |
| .text section (code) | Encrypted - different ciphertext per copy |
| .data section (data) | Encrypted - different ciphertext per copy |
| PE header | Modified entry point |
| File hash | Completely unique per copy |

### Execution Flow of Morphed Binary

```
OS loads morphed executable
  └─> Entry point → Decoder stub
       └─> Decrypt .text section in memory
       └─> Decrypt .data section in memory
       └─> Jump to original entry point
            └─> Bot runs normally (from decrypted memory)
```

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Implementation |
|---|---|---|
| T1027 | Obfuscated Files or Information | Encrypted code and data sections |
| T1027.005 | Indicator Removal from Tools | Unique binary per propagation |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decoder stub |

### Impact on Defenses

This polymorphic engine **rendered traditional signature-based antivirus almost useless** against Phatbot. Defenders were forced to invest in:

- **Heuristic analysis** - detecting suspicious structural patterns (e.g., encrypted sections + decoder stubs)
- **Behavioral analysis** - detecting what the bot *does* rather than what it *looks like*
- **Sandboxed emulation** - executing suspect binaries in controlled environments to observe runtime behavior
- **Generic unpackers** - tools that could identify and emulate common decryption patterns

---

## RSA Command Authentication

Unlike IRC bots that relied on simple password authentication (vulnerable to interception and replay), Phatbot used **RSA public-key cryptography** to authenticate operator commands.

### Authentication Flow

```
Operator side:
  1. Operator creates command message
  2. Signs message with RSA private key
  3. Broadcasts signed command to mesh network

Bot side:
  1. Receives signed command from peer
  2. Verifies RSA signature using embedded public key
  3. Only executes command if signature is valid
```

### Security Properties

| Property | Benefit |
|----------|---------|
| **Command forgery prevention** | Only the operator with the private key can issue valid commands |
| **Sniffer resistance** | Even if traffic is intercepted, attacker cannot inject commands |
| **Rival bot protection** | Competing operators cannot hijack the botnet |
| **Law enforcement resistance** | Sinkholing the network doesn't allow sending shutdown commands |

This was a dramatic improvement over the simple password-based authentication used by rBot/sdBot, where anyone who intercepted the IRC password could issue commands to the entire botnet.

---

## Cross-Platform Build System

Phatbot supported compilation across **three different compiler toolchains**:

| Compiler | Platform | Build File |
|----------|----------|-----------|
| Microsoft Visual C++ | Windows | `.sln`/`.vcproj` |
| Borland C++ 5 | Windows | `Makefile.bcc` |
| MinGW (GCC for Windows) | Windows/Cross | `Makefile.mingw` |

### Why Multiple Compilers?

1. **Operator accessibility** - not all operators had access to commercial MSVC; MinGW was free
2. **Detection evasion** - different compilers produce different binary patterns; AV signatures for MSVC-compiled Phatbot wouldn't match MinGW-compiled versions
3. **Optimization differences** - different compilers optimize differently, producing binaries with different performance characteristics
4. **Future cross-platform potential** - MinGW's GCC base theoretically enabled Linux compilation with minimal changes

---

## SSL Support for IRC Fallback

While Phatbot's primary C2 mechanism was the WASTE P2P network, it retained **IRC as a fallback** channel. Critically, the IRC implementation included native **SSL/TLS support** - encrypting all IRC traffic to prevent network-level inspection.

| Feature | rBot IRC | Phatbot IRC |
|---------|----------|-------------|
| Encryption | None (early) / Blowfish (later) | Full SSL/TLS |
| Certificate validation | N/A | Optional |
| Port | Standard IRC (6667) | SSL IRC (6697 or custom) |
| Traffic visibility | Plaintext or partial encryption | Fully encrypted tunnel |

---

## Exploit Framework

Like rBot, Phatbot included a modular exploit framework. However, its implementation was more sophisticated:

| Exploit | CVE | Description |
|---------|-----|-------------|
| DCOM RPC | CVE-2003-0352 | MS03-026 - the same exploit shared with rBot |
| LSASS | CVE-2003-0533 | MS04-011 - LSASS buffer overflow |
| WebDAV | CVE-2003-0109 | MS03-007 - IIS 5.0 overflow |
| NetBIOS | Various | Brute-force Windows shares |
| MSSQL | CVE-2002-1123 | SQL Server credential attack |

:::note[Exploit Sharing]
Source comments in rBot explicitly acknowledge borrowing the DCOM exploit from Agobot's codebase, confirming the cross-pollination between these families.
:::

---

## Comparison: IRC Bots vs. Phatbot

### Architectural Philosophy

| Dimension | IRC Bots (rBot/sdBot) | Phatbot |
|-----------|----------------------|---------|
| **Development model** | Collaborative, incremental patches | Engineered, architect-driven |
| **Code quality** | Variable (community mods) | Consistently high |
| **Innovation focus** | Feature addition (more exploits) | Architectural innovation (P2P, crypto) |
| **Target operator** | Script kiddies to intermediate | Intermediate to advanced |
| **Maintenance burden** | Low - simple codebase | High - complex systems |
| **Resilience** | Low - single server SPOF | High - distributed mesh |
| **Detection difficulty** | Moderate | Very high (polymorphism + P2P) |

### Why IRC Bots "Won" Despite Inferior Architecture

Despite Phatbot's technical superiority, IRC bots (rBot/sdBot) achieved far wider deployment. Several factors explain this:

1. **Simplicity** - IRC bots were easy to configure, compile, and deploy. Phatbot required significantly more technical knowledge.
2. **Community** - The IRC bot community was larger and more collaborative, producing more variants and mods.
3. **IRC familiarity** - Most operators already used IRC daily; the C2 interface was natural.
4. **Lower infrastructure cost** - IRC servers were free and plentiful; P2P networks required more careful bootstrapping.
5. **Good enough** - For most use cases (DDoS, spam, basic theft), IRC bots were sufficient. Phatbot's advanced features were overkill.

---

## ForBot - The Simplified Fork

The collection also contains **ForBot** variants, which represent simplified forks of the Agobot/Phatbot codebase:

| Feature | Phatbot | ForBot |
|---------|---------|--------|
| P2P C2 | ✅ WASTE protocol | ❌ IRC only |
| Polymorphism | ✅ Full engine | ❌ Removed |
| RSA crypto | ✅ Command signing | ❌ Password-based |
| Cross-platform | ✅ 3 compilers | Partial |
| Complexity | High | Moderate |

ForBot stripped out the most advanced features in favor of easier operation - further evidence that complexity was often a barrier to adoption in the malware ecosystem.

---

## MITRE ATT&CK Summary

| Technique ID | Technique Name | Phatbot Implementation |
|---|---|---|
| T1102.002 | Bidirectional Communication | WASTE P2P mesh C&C |
| T1027 | Obfuscated Files or Information | Polymorphic binary encryption |
| T1027.005 | Indicator Removal from Tools | Unique signature per propagation |
| T1140 | Deobfuscate/Decode Files or Information | Runtime decoder stubs |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA command authentication |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | SSL for IRC fallback |
| T1008 | Fallback Channels | P2P primary + IRC secondary |
| T1568.002 | Dynamic Resolution: DNS | Seed node discovery |

---

## Legacy and Influence

Phatbot's innovations had lasting influence on the malware landscape:

1. **P2P C2** - Later adopted by Storm Worm (2007), Waledac (2008), GameOver Zeus (2011), and modern botnets
2. **Polymorphism** - Became standard in commercial crimeware (Zeus, SpyEye, Citadel)
3. **Crypto authentication** - Adopted by GameOver Zeus (RSA-2048) and modern threat actors
4. **Concept proof** - Demonstrated that botnets could be made extremely resilient to law enforcement takedown

Phatbot proved that the *concepts* were sound, even if the *adoption* was limited. The techniques it pioneered became industry-standard for advanced threats within 5–10 years.

---

## Source Code References

- [View VirusPack collection](https://github.com/maestron/botnets/tree/master/VirusPack)
- [View full repository](https://github.com/maestron/botnets)

:::caution[Disclaimer]
This page is produced for **educational and academic purposes only**. The source code described here is analyzed statically for research into historical malware evolution. No executable binaries are provided or endorsed.
:::
