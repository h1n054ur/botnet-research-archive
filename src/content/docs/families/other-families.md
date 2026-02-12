---
title: "Other Notable Families"
description: "Smaller but historically significant bot families - NZM, AkBot, Darkness, CYBERBOT, Reptile, NinjaBot, and more (2005-2009)"
---

Beyond the major families (rBot/rxBot, sdBot/SpyBot, Phatbot/Agobot, Zeus), the archived collection contains several smaller but historically significant bot families. Each introduced unique capabilities or architectural approaches that influenced the broader malware ecosystem.

> **Educational context:** This analysis is based on static source-code inspection of historical specimens. All source references link to the [maestron/botnets](https://github.com/maestron/botnets) public archive.

---

## NZM Variants

**Specimens:** 7 directories (5 unique) | **Language:** C++ | **Era:** 2005–2006

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

### Overview

NZM is a major restructuring fork of the rBot/rxBot codebase. While functionally similar to its parent, NZM's primary contribution is **architectural organization** - it imposed a professional directory structure on what had been an increasingly chaotic codebase.

### Directory Structure

```
cpp/core/       - Core bot functionality (main loop, IRC, auth)
cpp/exploits/   - Exploit modules (PnP, WKSSVC, ASN.1, WINS)
cpp/modules/    - Feature modules (keylogger, sniffer, theft)
cpp/ddos/       - DDoS attack implementations
cpp/scan/       - Network scanning and target discovery
cpp/xfer/       - File transfer (TFTP, FTP, HTTP servers)
headers/        - Shared header files
config/         - Centralized configuration
doc/            - Documentation (changelogs, credits)
```

### Key Differentiators

| Feature | NZM Innovation |
|---------|---------------|
| **MD5-protected commands** | Commands include MD5 hash verification, preventing replay attacks and unauthorized command injection |
| **Organized exploit directory** | New exploits added as drop-in files in `cpp/exploits/` |
| **New exploit modules** | PnP (MS05-039), WKSSVC (MS03-049), ASN.1 (MS04-007), WINS, RealCast |
| **Documentation** | Included changelogs and credit files - rare for malware |

### MITRE ATT&CK Mapping

| Technique | Implementation |
|-----------|---------------|
| T1587 (Develop Capabilities) | Professional code organization framework |
| T1027 (Obfuscated Files or Information) | MD5 command authentication |
| T1210 (Exploitation of Remote Services) | Expanded exploit suite |

---

## AkBot

**Specimens:** 3 directories (3 unique) | **Language:** C++ | **Era:** 2005–2007

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

### Overview

AkBot stands out for its innovative use of **DNS SRV records** for C2 resolution - a technique that was ahead of its time and presaged modern domain generation algorithms (DGAs).

### Key Differentiators

| Feature | Detail |
|---------|--------|
| **DNS SRV record C2** | Instead of hardcoded IRC server addresses, AkBot queries DNS SRV records to discover C2 infrastructure. This allowed operators to change servers by updating DNS records without rebuilding the bot. |
| **XOR config encryption** | All configuration strings encrypted with XOR at compile time, decoded at runtime |
| **LimeWire spreading** | Bot copies itself to LimeWire shared folders with enticing filenames (music, cracks, keygens) to spread via P2P |
| **Minimal footprint** | Stripped-down codebase focused on reliability over features |

### DNS SRV Resolution Flow

```
// Pseudocode - AkBot C2 discovery
1. Bot queries DNS: _irc._tcp.domain.example → SRV record
2. SRV record returns: priority, weight, port, target_host
3. Bot connects to target_host:port
4. If primary fails, queries next SRV priority level
5. Operator updates DNS records to rotate infrastructure
```

### Why DNS SRV Matters

Traditional bots hardcoded server IPs or domain names. If the server was seized, the botnet was dead. DNS SRV records provided:

- **Infrastructure agility** - change servers without touching bots
- **Load balancing** - multiple SRV records with weights for distribution
- **Failover** - priority levels for automatic fallback
- **Stealth** - DNS queries blend with normal network traffic

### MITRE ATT&CK Mapping

| Technique | Implementation |
|-----------|---------------|
| T1568.002 (Dynamic Resolution: DNS) | DNS SRV record C2 discovery |
| T1071.004 (Application Layer Protocol: P2P) | LimeWire spreading |
| T1027 (Obfuscated Files or Information) | XOR configuration encryption |

---

## Darkness Bot

**Specimens:** 3 directories (2 unique codebases) | **Language:** C, C++ | **Era:** 2005–2009

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

### Overview

The "Darkness" name covers **two distinct codebases** that happen to share the name. Analysis reveals they have entirely separate authors and code lineages.

### Variant A - The Social Spreader

| Feature | Detail |
|---------|--------|
| **USB spreading** | Drops bot + auto-execution config to all removable drives |
| **MySpace integration** | Sends messages/friend requests with lure links to MySpace contacts |
| **HTTP flood** | Application-layer DDoS targeting web servers |
| **Era focus** | Peak MySpace era (2006–2008) social engineering |

### Variant B - The DDoS Specialist

| Feature | Detail |
|---------|--------|
| **Multi-method DDoS** | SYN, UDP, ICMP, HTTP, slowloris-style attacks |
| **Stripped design** | Minimal non-DDoS features - purpose-built attack tool |
| **Commercial model** | Evidence suggests it was sold as a DDoS-for-hire backend |

### MITRE ATT&CK Mapping

| Technique | Implementation |
|-----------|---------------|
| T1091 (Replication Through Removable Media) | USB removable media spreading |
| T1566.003 (Phishing: Spearphishing via Service) | MySpace social engineering |
| T1498 (Network Denial of Service) | Multi-method DDoS arsenal |

---

## CYBERBOT

**Specimens:** 3 directories (2 unique) | **Language:** C++ | **Era:** 2006–2007

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

### Overview

CYBERBOT, created by an author known as **DreamWoRK**, is a deliberately stripped-down fork of rxBot focused on **stability and operational reliability** over feature count.

### Design Philosophy

Where other bot authors competed to add features, DreamWoRK took the opposite approach:

| Design Choice | Rationale |
|--------------|-----------|
| **Removed unstable exploits** | Reduced crash rate in production botnets |
| **Simplified command set** | Faster command parsing, fewer bugs |
| **Hardened IRC handling** | Better reconnection logic, flood protection |
| **Reduced memory footprint** | More bots per compromised machine, less detection |

### Key Capabilities (Retained)

- Core DDoS methods (SYN, UDP, ICMP)
- NetBIOS brute-force spreading
- Basic keylogging
- Registry persistence
- Process killing (AV termination)

### Lesson for Defenders

CYBERBOT demonstrates that **less can be more** in malware design. By removing features, DreamWoRK created a bot that was:
- Harder to detect (smaller footprint, fewer behavioral indicators)
- More reliable (fewer crash-inducing code paths)
- Easier to operate (simpler command set)

### MITRE ATT&CK Mapping

| Technique | Implementation |
|-----------|---------------|
| T1498 (Network DoS) | Retained DDoS capabilities |
| T1547.001 (Registry Run Keys) | Standard persistence |
| T1562.001 (Disable or Modify Tools) | AV process termination |

---

## Reptile

**Specimens:** 6 directories (5 unique) | **Language:** C++ | **Era:** 2005–2006

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

### Overview

Reptile's defining feature is the integration of the **FU rootkit driver** for **kernel-mode process hiding** - a significant escalation in stealth capability beyond anything achieved by user-mode bots.

### FU Rootkit Integration

| Layer | Technique |
|-------|-----------|
| **Kernel driver** | FU rootkit loads as a Windows kernel driver (`.sys` file) |
| **DKOM** | Direct Kernel Object Manipulation - modifies kernel process lists |
| **Process hiding** | Bot process removed from `EPROCESS` linked list - invisible to Task Manager, `tasklist`, and most AV scanners |
| **Persistence** | Driver loaded at boot via service registration |

### How DKOM Process Hiding Works

```
// Pseudocode - DKOM process hiding concept
// The Windows kernel maintains a doubly-linked list of EPROCESS structures
// Each running process has an entry in this list

// Normal list: ... ↔ explorer.exe ↔ bot.exe ↔ svchost.exe ↔ ...
// After DKOM:  ... ↔ explorer.exe ↔ svchost.exe ↔ ...
//                                    (bot.exe unlinked but still running)

void HideProcess(PEPROCESS target) {
    // Get forward and backward links
    PLIST_ENTRY prev = target->ActiveProcessLinks.Blink;
    PLIST_ENTRY next = target->ActiveProcessLinks.Flink;
    
    // Unlink target from list
    prev->Flink = next;
    next->Blink = prev;
    
    // Process still runs - scheduler uses different list
    // But enumeration APIs no longer see it
}
```

### Detection Challenges

The FU rootkit posed severe detection challenges:

| Detection Method | Effectiveness Against Reptile |
|-----------------|------------------------------|
| Task Manager | ❌ Cannot see hidden process |
| `tasklist` / `ps` | ❌ Uses same kernel APIs |
| Standard AV scan | ❌ Relies on process enumeration |
| Cross-view detection | ✅ Compare API results vs. raw kernel memory |
| Rootkit detectors (GMER, etc.) | ✅ Designed for DKOM detection |
| Memory forensics | ✅ Raw memory analysis finds unlinked structures |

### MITRE ATT&CK Mapping

| Technique | Implementation |
|-----------|---------------|
| T1014 (Rootkit) | FU kernel driver for DKOM |
| T1564.001 (Hidden Files and Directories) | Process hidden from enumeration |
| T1543.003 (Windows Service) | Driver loaded as kernel service |
| T1068 (Exploitation for Privilege Escalation) | Kernel-mode access required |

### Historical Significance

Reptile demonstrated that bot authors were willing to invest in **kernel-level stealth** to protect their deployments. This drove the development of:
- Rootkit detection tools (GMER, RootkitRevealer, Blacklight)
- Kernel Patch Protection (PatchGuard) in 64-bit Windows
- Secure Boot and driver signing requirements

---

## NinjaBot

**Specimens:** 3 directories (1 unique) | **Language:** Delphi | **Era:** 2005–2006

[View source](https://github.com/maestron/botnets/tree/master/VirusPack)

### Overview

NinjaBot is the **only Delphi-based bot** in the collection. It stands out for two unique capabilities found nowhere else in the archive: **cooperative bot-to-bot spreading** and a **built-in honeypot detection mechanism**.

### Cooperative Bot-to-Bot Communication

Unlike other bots that operated as independent agents receiving commands from a central C2, NinjaBot bots could **communicate with each other** to coordinate spreading:

```
// Pseudocode - NinjaBot cooperative spreading
Bot_A infects Machine_X via Exploit_1
Bot_A reports to C2: "Machine_X compromised, port 445 open"
C2 relays to Bot_B: "Attack Machine_X via Exploit_2"
Bot_B attacks Machine_X, installing additional persistence

// Result: Machine_X has two independent infection vectors
// Cleaning one doesn't remove the other
```

This cooperative model created **redundant infections** - cleaning one bot from a machine didn't eliminate the threat if a second infection vector remained.

### Honeypot Detection

NinjaBot included routines to detect if it was running inside a **security researcher's honeypot** environment:

| Check | Target |
|-------|--------|
| VM detection | VMware, VirtualPC artifacts in registry/drivers |
| Sandbox detection | Known sandbox process names and file paths |
| Network analysis | Check for unrealistic network topology (too many open ports) |
| Uptime check | Very low uptime + clean system = likely fresh VM |
| Process analysis | Debuggers, analysis tools, monitoring software |

If honeypot indicators were detected, the bot would either:
- **Not install** - exit silently without revealing capabilities
- **Alter behavior** - run in a reduced mode to appear benign
- **Report back** - alert the operator about the researcher's infrastructure

### Why Delphi?

| Advantage | Detail |
|-----------|--------|
| **AV evasion** | Most AV signatures targeted C/C++ compiled binaries; Delphi binaries had different structure |
| **Rapid development** | Delphi's RAD environment enabled fast GUI and feature development |
| **VCL library** | Rich component library for networking, UI automation |
| **Different audience** | Delphi developers brought different perspectives to malware design |

### MITRE ATT&CK Mapping

| Technique | Implementation |
|-----------|---------------|
| T1497 (Virtualization/Sandbox Evasion) | Honeypot/VM detection routines |
| T1570 (Lateral Tool Transfer) | Bot-to-bot cooperative spreading |
| T1210 (Exploitation of Remote Services) | Multi-vector exploitation |
| T1082 (System Information Discovery) | Environment fingerprinting |

---

## Quick Reference Comparison

| Family | Specimens | Language | Unique Innovation | Primary Purpose |
|--------|-----------|----------|-------------------|----------------|
| **NZM** | 7 | C++ | Professional directory organization, MD5 commands | rBot reorganization |
| **AkBot** | 3 | C++ | DNS SRV record C2, LimeWire spreading | Agile infrastructure |
| **Darkness** | 3 | C/C++ | MySpace social spreading, dedicated DDoS | Social engineering + DDoS |
| **CYBERBOT** | 3 | C++ | Stability-focused minimalism | Reliable operations |
| **Reptile** | 6 | C++ | FU rootkit kernel-mode hiding | Stealth |
| **NinjaBot** | 3 | Delphi | Bot-to-bot comms, honeypot detection | Cooperative infection |

---

## Other Notable Specimens

The collection also contains several standalone specimens worth brief mention:

### Hydra (hydra-2008.1)
An **early IoT botnet precursor** - cross-compiled for MIPSEL architecture to target D-Link routers via Telnet brute-force. Conceptually identical to Mirai but appearing **8 years earlier** (2008 vs. 2016). Uses `wget` injection to install bot payload on routers.

### STEAMBOT
Exploits the **Steam gaming platform's Miles Sound System** plugin loading mechanism to achieve code execution - a highly targeted attack vector specific to the gaming community.

### hdbotv0.2
Includes a **Cisco router scanner** - probing for default credentials on Cisco networking equipment, demonstrating early interest in infrastructure-level compromise.

### Beast Bot 6.2
A prolific **multi-vector spreader** with simultaneous NetBIOS, email, IM, USB, and P2P spreading capabilities - designed for maximum propagation speed.

### pBot (PHP)
A PHP-based IRC bot designed for **compromised web servers** - lives parasitically on already-compromised hosting, using the server's bandwidth for DDoS and spam operations.

---

## Ecosystem Context

These smaller families, while less prolific than rBot or sdBot, collectively demonstrate several important evolutionary trends:

1. **Specialization** - Families increasingly focused on specific niches (DDoS, stealth, spreading) rather than trying to do everything
2. **Language diversification** - Movement beyond C/C++ to Delphi, PHP, Java expanded the attack surface and evaded C-focused signatures
3. **Stealth escalation** - Progression from user-mode hiding (file attributes) to kernel-mode rootkits (DKOM)
4. **Infrastructure innovation** - DNS SRV records, cooperative spreading, and social platform abuse expanded the C2 and propagation toolkit
5. **Anti-research measures** - Honeypot detection demonstrated awareness of and adaptation to security research methodologies

---

## Source Code References

- [View VirusPack collection](https://github.com/maestron/botnets/tree/master/VirusPack)
- [View full repository](https://github.com/maestron/botnets)

:::caution[Disclaimer]
This page is produced for **educational and academic purposes only**. The source code described here is analyzed statically for research into historical malware evolution. No executable binaries are provided or endorsed.
:::
