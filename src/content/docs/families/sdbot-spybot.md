---
title: "sdBot / spyBot Family"
description: "The foundational IRC bot codebase - 73 specimens spanning sdBot origins through SpyBot info-stealing and SDX OOP rewrite (2002-2008)"
---

The sdBot family, originally authored by a developer known as **[sd]**, represents the **foundational IRC bot codebase** from which the entire rBot/rxBot lineage descended. With **73 directory entries** (~42 unique specimens), this family documents the complete arc from amateur single-file C bots to professionally engineered object-oriented malware platforms.

> **Educational context:** This analysis is based on static source-code inspection of historical specimens archived for university research. All source references link to the [maestron/botnets](https://github.com/maestron/botnets) public archive.

---

## Evolutionary Timeline

```
2002    sdbot 0.4b - original by [sd], single-file C
2003    sdbot 0.5a/0.5b + Tesla SYN mod
2003    spyBot 1.1–1.3 - Mich's keylogger fork
2003-04 spyBot 1.4 + sdbot community mods proliferate
2004    rBot forks off (see rBot/rxBot page)
2005-07 120-series emerges (sdBot lineage via rxBot)
2008    SDX/SBX OOP rewrites - maturation endpoint
```

---

## sdbot04b - The Archetype

*Source: `sdbot04b/sdbot04b.c`*

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

The initial public version of sdBot is characterized by stark simplicity - a defining trait of early 2000s malware. The entire bot is contained within a **single C file**.

### Code Structure

| Characteristic | Detail |
|----------------|--------|
| Language | C (compiled with LCC) |
| Architecture | Monolithic, single-file, procedural |
| Variables | Global state, hardcoded configuration |
| C2 Protocol | IRC - connects to hardcoded server/channel |
| Command Parsing | Prefix-based (`.`) from `PRIVMSG` messages |

### Command Set

sdbot04b's capabilities are rudimentary but effective for its era:

| Command | Function | MITRE ATT&CK |
|---------|----------|---------------|
| `udp` | UDP denial of service flood | T1498 (Network DoS) |
| `ping` | ICMP flood attack | T1498 (Network DoS) |
| `download` | Fetch file from URL and execute | T1105 (Ingress Tool Transfer) |
| `update` | Self-update from remote URL | T1105 (Ingress Tool Transfer) |
| `sysinfo` | Gather and report system info | T1082 (System Information Discovery) |
| `redirect` | TCP port redirector (proxy) | T1090 (Proxy) |

### Persistence Mechanism

```
// Pseudocode - sdbot04b persistence
CopyFile(self, "%SYSTEMDIR%\\bot_filename.exe");
RegSetValue(
    HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices,
    "bot_key", bot_path
);
```

The bot achieves persistence by copying itself to the Windows System directory and creating a registry key under `RunServices` - the simplest possible autostart mechanism.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Implementation |
|---|---|---|
| T1095 | Non-Application Layer Protocol | IRC for C2 communication |
| T1041 | Exfiltration Over C2 Channel | System info sent via IRC |
| T1568.002 | Dynamic Resolution: DNS | C2 server identified by DNS name |
| T1498 | Network Denial of Service | `udp` and `ping` commands |
| T1105 | Ingress Tool Transfer | `download` command |
| T1547.001 | Registry Run Keys | RunServices persistence |

---

## sdbot05b - Incremental Refinements

*Source: `sdbot05b/sdbot05b.c`*

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

The final public release of the original sdBot series demonstrates incremental but significant feature creep - a common evolutionary pattern in malware development.

### Key Additions

| Feature | Significance |
|---------|-------------|
| **Backup server** (`server2`, `port2`) | Fallback C2 - simple but dramatically increases botnet resilience |
| **Enhanced scanning** | Includes `icmp.dll`, `kernel32.dll` process functions for future scanning |
| **`visit` command** | Silently visits a URL - precursor to click-fraud bots |
| **Conditional compilation** | More `#define` flags for feature toggling before compilation |

### The `visit` Command - A New Monetization Vector

The addition of the `visit` command was a pivotal moment. It allowed operators to:
- Generate **fraudulent ad revenue** (click fraud)
- Drive traffic to **exploit kit landing pages**
- Participate in **pay-per-install** schemes

This opened monetization pathways beyond simple DDoS-for-hire.

### MITRE ATT&CK - New Mappings

| Technique ID | Technique Name | Implementation |
|---|---|---|
| T1568.001 | Dynamic Resolution: Fast Flux DNS | Backup server concept |
| T1189 | Drive-by Compromise | `visit` command directing bots to exploit kits |

---

## SpyBot 1.4 - The Rise of Information Stealing

*Source: `spybot1.4/spybot.c`*

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

SpyBot represents the most significant fork from the original sdBot codebase. Authored by **Mich**, it extended the bot's purpose from a simple DoS tool to a **multi-functional espionage platform**, introducing threat categories that would become staples of modern malware.

### New Capabilities

#### 1. Keylogging (T1056.001)

SpyBot integrated the Windows hook API for keystroke capture:

```c
// Pseudocode - SpyBot keylogging approach
HHOOK hook = Set​Windows​HookEx(
    WH_KEYBOARD_LL,     // Low-level keyboard hook
    KeyboardProc,        // Hook callback function
    hInstance,           // Module handle
    0                    // All threads
);

// KeyboardProc logs keystrokes to file/channel
// including window title for context
```

This captured usernames, passwords, and chat messages - with the active window title providing context for which application the keystrokes belonged to.

#### 2. Credential Theft (T1555)

Beyond keylogging, SpyBot actively searched for cached passwords:

| Target | Method |
|--------|--------|
| Web browsers | `cachedpasswords` function - reads Windows Protected Storage |
| FTP clients | File/registry parsing for saved credentials |
| IM clients | Profile/config file extraction |

#### 3. IM/P2P Spreading (T1071.001)

SpyBot spread via the popular communication applications of its era:

| Application | Spreading Method |
|-------------|-----------------|
| Kazaa | Drop bot into shared download folder with enticing filename |
| MSN Messenger | Send lure message with download link to contact list |
| Other P2P | Copy to generic shared folders |

#### 4. Built-in HTTP Server

The bot could start a small HTTP server, allowing the attacker to **browse the victim's file system** remotely using any web browser - a primitive but effective RAT capability.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Implementation |
|---|---|---|
| T1056.001 | Input Capture: Keylogging | `Set​Windows​HookEx` keyboard hook |
| T1555 | Credentials from Password Stores | `cachedpasswords` function |
| T1573 | Encrypted Channel | Encrypted command parameters |
| T1071.004 | Application Layer Protocol: P2P | Kazaa/P2P spreading |
| T1005 | Data from Local System | Active password file searches |

### Defensive Impact

SpyBot's information-stealing capabilities forced a paradigm shift in defense:

- **Network-based defenses alone were no longer sufficient** - host-based detection became critical
- **Behavioral monitoring** for suspicious API calls (like `Set​Windows​HookEx`) became a priority
- **User education** gained importance as IM-based spreading exploited social trust

---

## SDX.amk.0x00 - Maturation of Malware Engineering

*Source: `SDX.amk.0x00/Src/`*

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

SDX marks a crucial step in the **professionalization of malware development**. It was a ground-up rewrite in C++ adopting Object-Oriented Programming (OOP) principles - a stark contrast to the monolithic C files of its predecessors.

### OOP Architecture

| Component | File(s) | Purpose |
|-----------|---------|---------|
| Core definitions | `SDX.h` | Main bot structure and interfaces |
| Utilities | `Utilities.h`, `Utilities.cpp` | Process killing, hosts file modification |
| User management | `client.h` | `user_list_t`, `FindUser`, `AddUser`, `DelLogin` |
| Configuration | `config.h` | Centralized settings with XOR encryption |
| IRC handling | Dedicated module | Protocol parsing and command dispatch |

### Key Engineering Improvements

**Modular, OOP Design:**
The code is broken into logical components with defined interfaces. The use of `structs` and associated functions (e.g., `user_list_t`, `FindUser`) mimics a class-based structure - a significant architectural maturation.

**Abstraction and Encapsulation:**
Functionality is grouped logically. User management (`AddUser`, `DelLogin`) is handled by dedicated functions, separated from core IRC logic. The `Utilities` module encapsulates malicious actions (process killing, hosts modification).

**Encrypted Configuration:**
All configuration strings (server, channel, password) are stored in **XOR-encrypted** format and decoded at runtime:

```c
// Pseudocode - SDX configuration decryption
char* DecryptConfig(char* encrypted, int key) {
    char* result = malloc(strlen(encrypted));
    for (int i = 0; i < strlen(encrypted); i++) {
        result[i] = encrypted[i] ^ key;
    }
    return result;
}

// Usage at startup
char* server = DecryptConfig(enc_server, XOR_KEY);
char* channel = DecryptConfig(enc_channel, XOR_KEY);
```

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Implementation |
|---|---|---|
| T1027 | Obfuscated Files or Information | XOR-encrypted configuration |
| T1140 | Deobfuscate/Decode Files or Information | Runtime configuration decryption |
| T1587 | Develop Capabilities | OOP framework investment |

### Defensive Implications

- **Static analysis difficulty increased** - analysts could no longer run `strings` on the binary to find C2 servers
- **Behavioral analysis became essential** - detecting *actions* (IRC connection, process scanning, hosts modification) outweighed signature matching
- **Reverse engineering workload grew** - decryption routines had to be identified and emulated first

---

## Sub-Group Inventory

| Sub-Group | Count | Key Characteristics |
|---|---|---|
| Original sdBot (v0.4b–0.5b) | 13 | By [sd], single-file C source, LCC compiler |
| sdBot v0.5b mods/forks | 24 | Community mods: b0rg, skbot, fake xdcc, getadm |
| spyBot versions (v1.1–1.4) | 24 | By Mich, adds keylogger + HTTP server + spreading |
| 120-Series (sdBot via rxBot) | 21 | BuZ's modular rebuild with VNC/MySQL/MSSQL |
| svBot offshoots | 2 | Independent IRC bots in same niche |
| Sbot-RARSpreader | 1 | RAR archive infection variant |

---

## Comparative Evolution Table

| Feature | sdbot04b | sdbot05b | SpyBot 1.4 | SDX |
|---------|----------|----------|------------|-----|
| Language | C | C | C | C++ (OOP) |
| Files | 1 | 1 | 1 | Multiple modules |
| C2 Servers | 1 | 2 (failover) | 1+ | Configurable |
| DDoS | UDP, ICMP | UDP, ICMP | UDP, ICMP, SYN | Full suite |
| Keylogging | ❌ | ❌ | ✅ | ✅ |
| Password Theft | ❌ | ❌ | ✅ | ✅ |
| IM Spreading | ❌ | ❌ | ✅ (Kazaa, MSN) | ✅ |
| String Encryption | ❌ | ❌ | Partial | XOR |
| Click Fraud | ❌ | ✅ (`visit`) | ✅ | ✅ |

---

## The sdBot → rBot Fork Point

The rBot family forked from sdBot around 2003–2004. The fork point is documented explicitly in rBot source headers:

```
Authors:
  sdbot: sd
  rbot: Nils, D3ADLiN3, Edge, bohika, rewe, racerx91
```

Key differences at fork time:
- **rBot** focused on **exploit integration** and modular architecture
- **sdBot mods** continued as simpler, more accessible variants for lower-skill operators
- **SpyBot** diverged toward **information stealing** capabilities
- Both lineages eventually converged in the **120-series** which incorporated features from both branches

For the rBot side of the family tree, see the [rBot / rxBot Family](/botnet-research-archive/families/rbot-rxbot/) page.

---

## Source Code References

All specimens referenced in this analysis are available in the archived collection:

- [View VirusPack collection](https://github.com/maestron/botnets/tree/master/VirusPack)
- [View full repository](https://github.com/maestron/botnets)

:::caution[Disclaimer]
This page is produced for **educational and academic purposes only**. The source code described here is analyzed statically for research into historical malware evolution. No executable binaries are provided or endorsed.
:::
