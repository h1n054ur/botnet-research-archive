---
title: "rBot / rxBot Family"
description: "The largest IRC botnet family - 121 specimens tracing modular bot evolution from monolithic C to encrypted modular C++ (2004-2008)"
---

The rBot/rxBot lineage is the **single largest family** in the archived collection, spanning **121 directory entries** and an estimated 93 unique specimens. It documents one of the most thorough evolutionary arcs in early malware history - from a monolithic single-file C program to a fully modular, encrypted, directory-organized C++ framework with plug-in exploit support.

> **Educational context:** All analysis below is based on static source-code inspection of historical specimens. No executable binaries are provided. Source references link to the [maestron/botnets](https://github.com/maestron/botnets) public archive.

---

## Evolution Timeline

The rBot family descends from **sdBot**, authored by a developer known as "sd." The lineage is explicitly documented in source-file credits across every major variant.

### Phase 1 - The sdBot Origin (Pre-2003)

The earliest specimen, `rBot 0.2-MODE-by-akusot.v1.5`, retains the original credit block:

```
Authors:
  sdbot: sd
  rbot: Nils, D3ADLiN3, Edge, bohika, rewe, racerx91
```

At this stage the entire bot resides in a **single `rBot.cpp` file** exceeding 2,900 lines. Configuration values are hardcoded, and feature-gating uses primitive `#define` toggles. There is no modularization whatsoever.

[View source - rBot 0.2](https://github.com/maestron/botnets/tree/master/VirusPack)

### Phase 2 - The rx_dev Refactoring (March–April 2004)

The `rx_dev/rBot_041504` specimen is the **most historically significant** variant. It is RacerX90's private development tree containing a 682-line changelog spanning March 24 to April 14, 2004.

Key architectural changes introduced:

| Change | Detail |
|--------|--------|
| Module separation | Code split into ~90 separate `.cpp`/`.h` file pairs |
| Dynamic DLL loading | All API calls converted from static linking to `LoadLibrary`/`GetProcAddress`; calls prefixed with `f` (e.g., `fWSAStartup`) |
| Unified thread management | Centralized `THREAD` structure array with `clearthread()` |
| Exploit statistics | Universal tracking system for scan/exploit success rates |
| Exception handler | SEH-based crash recovery to keep bots alive |

[View source - rx_dev](https://github.com/maestron/botnets/tree/master/VirusPack)

### Phase 3 - rxBot Formalization (Mid-2004)

rxBot 0.6.6d formalized the branch with:
- GPL licensing (ironically applied to malware source)
- Further modularization
- LSA restriction module
- FTP transfer capability for bot updates

### Phase 4 - BlowSXT: Crypto-Enhanced (2004–2005)

Introduced **Blowfish encryption** for all C&C communications. The command prefix was changed to a non-printable character (`\xBB`) specifically to evade IDS pattern-matching rules that looked for plaintext IRC bot commands.

### Phase 5 - NZM: Refactored Fork (April 2005)

Complete reorganization into a proper directory hierarchy:

```
cpp/core/       cpp/exploits/     cpp/modules/
cpp/ddos/       cpp/scan/         cpp/xfer/
headers/        config/           doc/
```

NZM added PnP (MS05-039), WKSSVC, ASN.1, WINS, and RealCast exploits. This phase also introduced MD5-protected commands, preventing command replay attacks.

### Phase 6 - 120-Series: Operational Branch (2007)

Optimized for real-world botnet operations with:
- Full string encryption (no plaintext indicators in binary)
- Abbreviated filenames to reduce forensic footprint
- Bot-killer module with whitelist of **300+ legitimate Windows executables**
- SP2 patcher to re-enable security-weakening XP settings
- Modular scanner subdirectory architecture

[View source - 120-series variants](https://github.com/maestron/botnets/tree/master/VirusPack)

---

## Architecture Analysis

### Design Pattern Evolution

| Era | Pattern | Specimen | Lines of Code |
|-----|---------|----------|---------------|
| Early (2003) | Monolithic single-file | rBot 0.2 | ~2,900 |
| Refactoring (Q1 2004) | Modular with shared headers | rx_dev | ~90 files |
| Mature (Q2 2004) | MVC-like separation | rxBot 0.6.6d | Structured |
| Fork (2005) | Directory-based modules | NZM | 6 subdirs |
| Operational (2007) | Encrypted + stripped | 120-ModBot | Production-ready |

### Core Startup Flow

The startup sequence is consistent across all major variants:

```
WinMain()
  └─> LoadDLLs()          // Dynamic API resolution
  └─> Mutex Check          // Single-instance enforcement
  └─> Self-Copy()          // Copy to %SYSTEM% with hidden attributes
  └─> Registry Persist()   // Write Run keys
  └─> IRC Connect Loop     // Dual-server failover
        └─> Auth + Join
        └─> Command Dispatch
```

### Exploit Framework Architecture

The mature variants use a standardized `EXPLOIT` structure array in `advscan.cpp`. This allowed plug-in-style exploit development - adding a new exploit required only a single new entry in the structure array plus the corresponding exploit function:

```c
// Pseudocode - educational representation of the exploit array pattern
typedef struct {
    char  *name;           // Human-readable name
    int    port;           // Target port
    int    protocol;       // TCP or UDP
    void  (*exploit_func); // Pointer to exploit function
    BOOL   enabled;        // Feature toggle
} EXPLOIT;

EXPLOIT exploits[] = {
    {"dcom",    135, TCP, &exploit_dcom,  TRUE},
    {"lsass",   445, TCP, &exploit_lsass, TRUE},
    {"webdav",   80, TCP, &exploit_webdav, FALSE},
    // ... additional entries
};
```

This pattern made it trivial for community contributors to add new exploits without understanding the full codebase.

---

## Exploit Integration Timeline (CVE Mapping)

One of the most educationally valuable aspects of this family is the documented timeline of exploit integration. Lag times between public vulnerability disclosure and weaponized integration were measured in **days to weeks**.

| Exploit Module | CVE | MS Bulletin | Integration Date | Target Description |
|---|---|---|---|---|
| DCOM | CVE-2003-0352 | MS03-026 | Pre-Q1 2004 | RPC DCOM buffer overflow |
| DCOM2 | CVE-2003-0715 | MS03-039 | March 30, 2004 | Second DCOM wave |
| WebDAV | CVE-2003-0109 | MS03-007 | March 30, 2004 | IIS 5.0 WebDAV overflow |
| LSASS | CVE-2003-0533 | MS04-011 | April 2004 | LSASS buffer overflow via SMB |
| UPnP | CVE-2001-0876 | MS01-059 | March 2004 | UPnP buffer overflow |
| DameWare | CVE-2003-1030 | N/A | April 14, 2004 | DameWare Mini Remote Control overflow |
| MSSQL | CVE-2002-1123 | MS02-056 | March 25, 2004 | SQL Server brute-force |
| IIS5 SSL | CVE-2003-0719 | MS04-011 | April 2004 | IIS SSL PCT overflow |
| Workstation Svc | CVE-2003-0812 | MS03-049 | 2005 (NZM) | Workstation Service overflow |
| PnP | CVE-2005-1983 | MS05-039 | August 2005+ | Plug-and-Play overflow |
| NetAPI | CVE-2006-3439 | MS06-040 | 2006–2007 | Server Service overflow |
| Symantec | CVE-2006-2630 | N/A | 2006–2007 | Symantec Client Security overflow |
| ASN.1 | CVE-2003-0818 | MS04-007 | 2005 (NZM) | ASN.1 vulnerability |

:::note[Cross-Pollination]
The DCOM exploit was borrowed directly from Agobot's codebase, as documented in source comments. This cross-pollination between bot families was common - shared exploits, shellcode, and modules flowed freely in the underground development community.
:::

---

## C&C Protocol Analysis

### IRC-Based Command and Control

All rBot/rxBot variants use IRC as the C&C transport. The protocol evolved significantly across versions:

**Authentication System** - Multi-layer security:
1. Password check against hardcoded credential
2. Host mask matching (IRC `user@host` verification)
3. Multi-login support with session tracking
4. Login attempt logging

### Command Namespace Evolution

The command set grew from ~20 commands in rBot 0.2 to **100+ commands** in NZM/120-series variants. Commands were organized into namespaces:

| Namespace | Purpose | Example Commands |
|-----------|---------|-----------------|
| `irc.*` | IRC operations | `irc.join`, `irc.part`, `irc.nick`, `irc.quit` |
| `root.*` | Exploitation | `root.scan`, `root.exploit`, `root.stats` |
| `ddos.*` | DDoS attacks | `ddos.syn`, `ddos.udp`, `ddos.icmp`, `ddos.ack` |
| `daemon.*` | Services | `daemon.socks`, `daemon.httpd`, `daemon.tftp` |
| `com.*` | Data theft | `com.harvest`, `com.keylog`, `com.capture`, `com.findpass` |

### Topic Commands

In a particularly clever design, the bot accepted commands embedded in the IRC channel **topic**. Changing the channel topic instantly issued a command to every bot in that channel - enabling mass control with a single action.

### CTCP Camouflage

Bots responded to IRC CTCP VERSION queries with fake client strings to blend in with legitimate IRC traffic:

```
// Pseudocode - CTCP response rotation
responses[] = {
    "mIRC v6.16 Khaled Mardam-Bey",
    "BitchX-1.1-final",
    "xchat 2.4.5 Linux",
    "irssi v0.8.10",
    "eggdrop v1.6.17"
}
reply = responses[random() % count]
```

---

## Defense Evasion Techniques

The rBot/rxBot family implemented a layered defense-evasion strategy that evolved across versions. Each technique maps to modern MITRE ATT&CK categories:

### 1. File System Concealment
- Self-copy to `%SYSTEM%` directory with **hidden + system + read-only** file attributes
- **Timestamp modification** (timestomping) - copies the timestamp of a legitimate system file onto the bot binary
- *ATT&CK: T1564.001 (Hidden Files and Directories), T1070.006 (Timestomp)*

### 2. Registry Persistence
- Multiple redundant `Run` keys for resilience (if one is cleaned, others survive)
- Service installation in later variants
- *ATT&CK: T1547.001 (Registry Run Keys)*

### 3. Dynamic API Resolution
- All Windows API calls routed through `LoadLibrary`/`GetProcAddress` at runtime
- Prevents static import table analysis - disassemblers cannot determine capabilities from the PE import directory
- *ATT&CK: T1106 (Native API), T1027.007 (Dynamic API Resolution)*

### 4. String Encryption Evolution
The encryption of configuration strings evolved across versions:

| Version | Technique |
|---------|-----------|
| rBot 0.2 | Plaintext strings |
| rx_dev | Simple XOR encoding |
| BlowSXT | Blowfish encryption |
| 120-series | Full hex-encoded Blowfish with runtime decryption |

### 5. Anti-AV Measures
- **Process killing** - Enumerates running processes and kills known AV product processes
- **Hosts file modification** - Adds entries redirecting AV update servers (e.g., `windowsupdate.com`, `symantec.com`) to `127.0.0.1`
- *ATT&CK: T1562.001 (Disable or Modify Tools)*

### 6. Bot-Killer Module
The 120-series introduced an innovative **whitelist-based** process killer. Instead of maintaining a blacklist of AV products (easily outdated), it maintained a whitelist of **300+ legitimate Windows executable names**. Anything running that was *not* on the whitelist was terminated - killing competing bots, unauthorized tools, and unknown AV products.

### 7. Packet Sniffer
Described in source comments as a "scaled down Carnivore," the sniffer captured IRC traffic on the local network. Its primary purpose was to **steal control of competing botnets** by extracting their C&C credentials from intercepted IRC authentication exchanges.

### 8. System Lockdown
- Disable DCOM service
- Remove default network shares (C$, D$, ADMIN$, IPC$)
- Purpose: prevent *re-infection* by other bots or worms using the same vulnerabilities

### 9. Self-Deletion (Melt)
The "melt" routine launches a copy of the bot from the installation directory, then the original process deletes itself - leaving no trace at the initial infection point.

### 10. Uptime-Encoded Nicknames
Bot IRC nicknames encoded the system uptime, allowing operators to quickly identify **high-value long-lived bots** (servers, always-on machines) versus transient desktop infections.

---

## Data Theft Capabilities

### CD Key / License Theft

The bot scraped registry keys and known file locations for software license keys:

| Target Software | Registry/File Location |
|----------------|----------------------|
| Half-Life / Counter-Strike | HKLM\Software\Valve |
| Unreal Tournament 2003 | HKLM\Software\Unreal Technology |
| Battlefield 1942 | HKLM\Software\EA GAMES |
| Neverwinter Nights | HKLM\Software\BioWare |
| Call of Duty | HKLM\Software\Activision |
| Need for Speed | HKLM\Software\EA GAMES |
| FIFA series | HKLM\Software\EA SPORTS |
| Command & Conquer Generals | HKLM\Software\EA GAMES |

These keys had direct monetary value on underground forums - a single valid multiplayer key could sell for $2–$10.

### Password Brute-Force Dictionary

The NetBIOS spreading module included a hardcoded dictionary of **~80+ common passwords** for brute-forcing Windows shares. Sample entries:

```
// Pseudocode - partial password dictionary
passwords[] = {
    "", "password", "admin", "123456", "1234",
    "test", "guest", "master", "qwerty", "letmein",
    "server", "root", "changeme", "pass", "login",
    // ... ~65 more entries
}
```

### Additional Theft Modules

| Module | Capability |
|--------|-----------|
| Keylogger | Real-time keystroke capture, output to dedicated IRC channel |
| Screen Capture | Periodic screenshots sent to operator |
| Protected Storage | Dump IE/Outlook saved passwords from Windows credential store |
| Firefox Extraction | Parse Firefox profile SQLite databases for saved credentials |
| FTP Client Theft | Extract saved credentials from ServU, WS_FTP, GS-FTP, NetTerm |

---

## DDoS Attack Arsenal

| Method | Description | First Appeared |
|--------|-------------|---------------|
| SYN Flood | Raw socket SYN packets with spoofed source IPs | rBot 0.2 |
| UDP Flood | High-volume UDP packets to arbitrary ports | rBot 0.2 |
| ICMP Flood | Ping flood with oversized packets | rx_dev |
| TCP Connect | Full TCP connection flood (works behind NAT) | rxBot 0.6 |
| ACK Flood | TCP ACK packets to exhaust stateful firewall tables | NZM |
| SuperSYN | Optimized SYN flood with minimal per-packet overhead | 120-series |
| HTTP GET | Application-layer flood against web servers | 120-series |

---

## Spreading Mechanisms

| Vector | Method |
|--------|--------|
| NetBIOS | Brute-force Windows shares with password dictionary |
| TFTP Server | Built-in TFTP server serves bot binary post-exploitation |
| FTP Server | Built-in FTP server for binary transfer |
| HTTP Server | Built-in HTTP server for payload delivery |
| MSN Messenger | Send lure messages with bot download link to contact list |
| AIM | Send bot via AOL Instant Messenger |
| Yahoo Messenger | Send bot via Yahoo IM |
| Email | Mass-mail bot as attachment |
| USB | Drop bot + auto-execution config to removable drives |

---

## Sub-Group Summary

| Sub-Group | Count | Key Characteristics |
|---|---|---|
| Original rBot base (v0.2–0.3) | 13 | Earliest versions, basic scanning + DDoS |
| rxBot core releases (v0.6.5–0.7.7) | 11 | RacerX90's evolution, modular architecture |
| rxBot named mods | 12 | EcLiPsE, Xerion, Undertow, Temptation variants |
| rXSass / LSASS variants | 2 | LSASS exploit focused |
| Urxbot / URX variants | 7 | Major fork with Symantec + ASN exploits |
| RX-120 series (by BuZ) | 22 | Modular rebuild, MySQL/VNC/MSSQL focus |
| NZM mods | 9 | Restructured with organized subdirectories |
| Other named derivatives | 45 | Various community mods and forks |

---

## Evolutionary Significance

The rBot/rxBot family is educationally significant for several reasons:

1. **Open-source development model applied to malware** - GPL licensing, detailed changelogs, code reviews, and collaborative development mirroring legitimate open-source projects.

2. **Cross-pollination between families** - Shared exploits, shellcode, and modules flowed freely between rBot, Agobot, sdBot, and other families. The DCOM exploit alone appears in at least four distinct bot families.

3. **Professionalization arc** - The progression from single-file chaos to organized directory structures with documentation demonstrates the same software engineering maturation seen in legitimate projects.

4. **Arms race dynamics** - The lockdown module, bot-killer, and packet sniffer demonstrate that bot operators competed aggressively, building features specifically to steal or destroy rival botnets.

5. **Exploit lag times** - Source changelogs document new exploits being integrated within **days to weeks** of public vulnerability disclosure, providing concrete evidence of the patch-race problem.

6. **Commodity malware economics** - 121 variants from a single family, analogous to Linux distributions - many operators running slightly customized versions of the same core platform.

---

## Source Code References

All specimens referenced in this analysis are available in the archived collection:

- [View VirusPack collection](https://github.com/maestron/botnets/tree/master/VirusPack)
- [View full repository](https://github.com/maestron/botnets)

:::caution[Disclaimer]
This page is produced for **educational and academic purposes only**. The source code described here is analyzed statically for research into historical malware evolution. No executable binaries are provided or endorsed.
:::
