<div align="center">

# Botnet Research Archive

**Educational documentation and academic analysis of historical botnet source code (2002–2009)**

[![Live Site](https://img.shields.io/badge/Live_Site-00ff41?style=for-the-badge&logo=github&logoColor=000)](https://h1n054ur.github.io/botnet-research-archive/)
[![Original Repo](https://img.shields.io/badge/Source_Collection-maestron%2Fbotnets-333?style=for-the-badge&logo=github)](https://github.com/maestron/botnets)
[![Built with Starlight](https://img.shields.io/badge/Built_with-Astro_Starlight-BC52EE?style=for-the-badge&logo=astro&logoColor=fff)](https://starlight.astro.build)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

</div>

---

## Overview

This project provides comprehensive, university-level educational documentation of a publicly available collection of **369 historical malware specimens** spanning 2002 to 2009. All analysis is conducted for academic purposes with a focus on **defensive cybersecurity** and **MITRE ATT&CK mapping**.

> **This repository contains ZERO malicious code.** All source references link back to the [original public repository](https://github.com/maestron/botnets). This is a documentation-only project for educational and research purposes.

## What's Covered

| Section | Content |
|---|---|
| **Malware Families** | rBot/rxBot (121 specimens), sdBot/spyBot (73), Phatbot/Agobot, Zeus, NZM, AkBot, and more |
| **Categories** | Exploit packs, worms, RATs, stealers, crypters, cross-platform bots, DDoS/IoT |
| **Analysis** | Evolution timeline, IRC→HTTP paradigm shift, malware economy, CVE mapping, MITRE ATT&CK |
| **Reference** | Complete inventory, glossary, bibliography |

### Key Research Highlights

- **Complete evolutionary chain**: sdBot (2002) → rBot (2004) → rxBot → URX/NZM/120 (2007) traced through source-level analysis
- **hydra-2008.1**: An IoT botnet precursor targeting D-Link routers via MIPSEL cross-compilation, **8 years before Mirai**
- **Zeus banking trojan**: Full architecture analysis of the crimeware kit that shifted botnets from IRC to HTTP
- **Exploit pack economics**: How Fragus, ICEPack, and Fiesta industrialized browser exploitation
- **All techniques mapped to MITRE ATT&CK** framework for defensive application

## Tech Stack

| Component | Technology |
|---|---|
| Framework | [Astro](https://astro.build) + [Starlight](https://starlight.astro.build) |
| Runtime | [Bun](https://bun.sh) |
| Hosting | GitHub Pages |
| CI/CD | GitHub Actions |
| Theme | Custom dark hacker terminal theme |
| Search | Pagefind (client-side, built-in) |

## Development

```bash
# Clone
git clone https://github.com/h1n054ur/botnet-research-archive.git
cd botnet-research-archive

# Install
bun install

# Dev server
bun run dev

# Build
bun run build

# Preview production build
bun run preview
```

## Project Structure

```
src/content/docs/
├── index.mdx                    # Landing page
├── families/                    # Deep-dives per malware family
│   ├── rbot-rxbot.md
│   ├── sdbot-spybot.md
│   ├── phatbot-agobot.md
│   ├── zeus.md
│   └── other-families.md
├── categories/                  # Analysis by malware type
│   ├── exploit-packs.md
│   ├── worms.md
│   ├── rats.md
│   ├── stealers-crypters.md
│   ├── cross-platform.md
│   └── ddos-iot.md
├── analysis/                    # Thematic cross-cutting analysis
│   ├── evolution-timeline.md
│   ├── irc-vs-http.md
│   ├── malware-economy.md
│   ├── cve-mapping.md
│   ├── mitre-attack.md
│   └── defensive-lessons.md
└── reference/                   # Supporting materials
    ├── inventory.md
    ├── glossary.md
    ├── bibliography.md
    └── about.md
```

## Disclaimer

This project is **strictly educational**. It is intended for:

- University students studying cybersecurity and malware analysis
- Security researchers studying historical threats
- Educators building curriculum around threat intelligence

No malicious code is hosted, compiled, or executed. All specimen references link to the [original public repository](https://github.com/maestron/botnets) maintained by [maestron](https://github.com/maestron). The documentation focuses on **defensive analysis**, **detection techniques**, and **lessons learned** for the security community.

## Acknowledgments

- Source collection: [maestron/botnets](https://github.com/maestron/botnets)
- Documentation framework: [Astro Starlight](https://starlight.astro.build)
- MITRE ATT&CK: [attack.mitre.org](https://attack.mitre.org)
