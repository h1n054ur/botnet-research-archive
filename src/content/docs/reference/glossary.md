---
title: "Glossary of Terms"
description: "Definitions of all technical terms used throughout this botnet research documentation"
---

This glossary defines the technical terms, acronyms, and concepts referenced throughout this documentation. Terms are listed alphabetically for quick reference.

---

## A

### API Hooking
A technique where malware intercepts calls to operating system Application Programming Interface (API) functions by modifying function pointers, import address tables (IAT), or injecting jump instructions ("trampolines") at the start of target functions. Used extensively by Zeus to intercept browser network calls and inject content into web pages. See also: **Hooking**, **MitB**.

### AV (Antivirus)
Security software that detects and removes malware. Many specimens in this collection include dedicated AV-killing modules that terminate known antivirus processes, delete their files, or modify the Windows Security Center registry keys to disable protection. See also: **FUD**.

---

## B

### Bot
A compromised computer running malware that connects to a command-and-control server to receive instructions. The term derives from "robot." Each infected machine in a botnet is a bot (also called a "zombie"). In the specimens studied, bots typically connect to an IRC channel upon infection and await commands from the botmaster.

### Botmaster
The operator who controls a botnet by issuing commands through the C&C infrastructure. In the IRC-based specimens, the botmaster authenticates using a password and sends commands as IRC channel messages or private messages.

### Botnet
A network of compromised computers (bots) controlled remotely by an attacker (botmaster) through a command-and-control infrastructure. The specimens in this collection represent the source code that, when compiled and deployed, would create such networks. Botnets are used for DDoS attacks, spam distribution, credential theft, and proxy services.

### Brute Force
An attack method that systematically tries all possible passwords or keys until the correct one is found. Many specimens in this collection include brute-force modules targeting VNC, MSSQL, MySQL, FTP, and NetBIOS share passwords. The 120-series variants are particularly notable for their modular brute-force capabilities.

### Bullet-Proof Hosting
Web hosting services that are intentionally lenient about what content they allow, often ignoring abuse complaints and law enforcement requests. Frequently located in jurisdictions with weak cybercrime laws. Used by botmasters to host C&C servers, exploit kit landing pages, and drop zones for stolen data.

---

## C

### C&C / C2 (Command and Control)
The infrastructure and communication protocols used by a botmaster to send commands to and receive data from compromised bots. The collection demonstrates two major C2 paradigms:
- **IRC-based C2** (majority of specimens): Bots join an IRC channel and parse commands from channel messages or topic strings.
- **HTTP-based C2** (Zeus): Bots poll a web server for encrypted configuration updates and POST stolen data to gate scripts.

See also: **Fast Flux**, **P2P**.

### Credential Stuffing
An attack that uses lists of previously stolen username/password pairs to attempt logins on other services, exploiting password reuse. Distinguished from brute force in that it uses known credentials rather than guessing. The stealer specimens in this collection harvest the credentials that would feed such attacks.

### Cross-Compilation
The process of compiling code on one platform to produce executables for a different platform or architecture. The **hydra-2008.1** specimen is notable for cross-compiling from a standard Linux development environment to produce MIPSEL binaries targeting D-Link routers - a technique later made famous by Mirai.

### Crypter
A tool that encrypts or obfuscates a malware binary's code to evade antivirus detection. The encrypted payload is bundled with a "stub" that decrypts it at runtime. The collection includes several crypter source codes (DynastryCrypterSource, SPKRYPT series, PE-Crypt) that demonstrate both PE-level encryption and source-code obfuscation techniques. See also: **FUD**, **Packer**.

---

## D

### DDoS (Distributed Denial of Service)
An attack where many bots simultaneously flood a target with network traffic to make it unavailable. The specimens implement multiple flood types:
- **SYN flood**: Sends TCP SYN packets without completing the handshake
- **UDP flood**: Sends large volumes of UDP packets to random ports
- **ICMP flood**: Sends ICMP echo request (ping) packets
- **ACK flood**: Sends TCP ACK packets to bypass stateless firewalls
- **HTTP flood**: Sends legitimate-looking HTTP requests to exhaust web server resources
- **SuperSYN**: An enhanced SYN flood variant found in rxBot

### Drive-By Download
A method of malware distribution where visiting a compromised or malicious website automatically triggers exploitation of browser vulnerabilities to install malware without user interaction. The exploit pack specimens (Fragus, ICEPack, Fiesta, my_poly_sploit) are purpose-built frameworks for delivering drive-by downloads.

---

## E

### Exfiltration
The unauthorized transfer of data from a compromised system to an attacker-controlled location. Methods observed in the collection include:
- IRC private messages (keylog data, credentials)
- HTTP POST to gate scripts (Zeus stolen form data)
- Email (CC.Trojan.EMAIL3 phishing results)
- FTP upload (stolen files)

### Exploit Kit
A server-side software package that probes visiting browsers for vulnerabilities and serves appropriate exploits. The collection contains four: **Fragus** (commercial-grade, 8 exploits), **ICEPack**, **Fiesta3**, and **my_poly_sploit** (polymorphic shellcode). See also: **Drive-By Download**, **Heap Spray**.

---

## F

### Fast Flux
A DNS technique where the IP addresses associated with a domain name change rapidly (every few minutes), pointing to different compromised machines that act as proxies. Used to make C&C servers and phishing sites resilient against takedown. Some advanced specimens in the collection reference fast-flux DNS configurations.

### FTP (File Transfer Protocol)
A standard network protocol for transferring files. Many specimens include FTP server functionality to distribute copies of themselves or use FTP to exfiltrate stolen data. FTP credentials are also a common target for stealer modules.

### FUD (Fully Undetectable)
Slang term in the malware community meaning a binary is not detected by any antivirus engine at the time of testing. Achieving FUD status is the primary goal of crypters and packers. The DynastryCrypterSource specimen notably includes an enterprise-style licensing system for selling FUD crypting as a service.

---

## G–H

### Heap Spray
An exploitation technique that fills large regions of a process's heap memory with copies of shellcode (typically as NOP sleds followed by payload), increasing the probability that a corrupted pointer will land in attacker-controlled memory. Used extensively by the exploit pack specimens (particularly **my_poly_sploit**) to exploit browser memory corruption vulnerabilities.

### Hooking
A general technique for intercepting function calls, messages, or events within a software system. In malware context, used to intercept system API calls, modify browser behavior, or hide processes. Specific types include **API hooking** (modifying function entry points), **IAT hooking** (modifying import tables), and **inline hooking** (patching instructions). Zeus uses hooking extensively for its MitB attacks.

---

## I

### IRC (Internet Relay Chat)
A text-based real-time messaging protocol from 1988. The dominant C&C protocol for botnets in the 2003–2008 era. Bots connect to an IRC server, join a specified channel, and parse commands from channel messages. Advantages: widely available servers, built-in multi-cast (channels), authentication via passwords. Disadvantages: easy to monitor, single point of failure, detectable traffic patterns. The vast majority of specimens in this collection use IRC for C&C.

---

## K

### Keylogger
A component that records keystrokes on the compromised system. Present in spyBot, rxBot, Zeus, FBIRAT, and many others. Techniques observed include:
- `GetAsyncKeyState()` polling (most common in the specimens)
- `Set​Windows​HookEx()` with `WH_KEYBOARD_LL` hook
- Browser form grabbing (Zeus - intercepts data before SSL encryption)

---

## L

### Lateral Movement
The techniques an attacker uses to move through a network after initial compromise, accessing additional systems. Observed in the collection via NetBIOS brute force, network share enumeration, exploitation of vulnerable services on adjacent hosts, and IM-based spreading to contacts of the infected user.

---

## M

### MIPSEL
A little-endian variant of the MIPS processor architecture, commonly found in embedded devices like routers, access points, and IoT devices. The **hydra-2008.1** specimen cross-compiles to MIPSEL to target D-Link routers, making it a documented IoT botnet precursor eight years before Mirai (2016).

### MitB (Man-in-the-Browser)
An attack where malware modifies web page content and intercepts transactions within the browser in real time. Zeus pioneered this technique by hooking browser network functions to inject additional form fields into banking websites (requesting PINs, TANs, social security numbers) and modifying displayed account balances to hide fraudulent transfers. See also: **Web Inject**, **Hooking**.

### Mule
A person (often unwitting) who transfers stolen money or goods on behalf of criminals. In the Zeus ecosystem, web injects would redirect wire transfers to mule accounts. The mule would withdraw the cash and forward it (minus a commission) to the attacker, typically via money transfer services.

### Mutex
A mutual exclusion object used in programming to prevent multiple instances of a program from running simultaneously. Nearly all specimens in the collection create a named mutex on startup to ensure only one copy of the bot is running on an infected machine. The mutex name often serves as a signature for antivirus detection.

---

## N–O

### NAT Traversal
Techniques for establishing network connections through Network Address Translation devices (routers/firewalls). The **AryanRat** specimen uses UPnP (Universal Plug and Play) to automatically configure port forwarding on the victim's router, enabling inbound connections for remote access.

---

## P

### P2P (Peer-to-Peer)
A decentralized network architecture where nodes communicate directly with each other rather than through a central server. **Phatbot** uniquely implements P2P C&C using the WASTE protocol (port 24288), eliminating the single point of failure inherent in IRC-based botnets. This represents a significant evolutionary step in botnet architecture.

### Packer
A tool that compresses and/or encrypts an executable, decompressing it in memory at runtime. Similar to a crypter but traditionally focused on compression rather than encryption. Packers change the binary's signature, complicating static analysis. See also: **Crypter**, **FUD**.

### PE (Portable Executable)
The file format for executables, DLLs, and other binary files on Windows. Understanding PE structure is essential for analyzing the Win32 specimens in this collection. Crypters and packers manipulate PE sections, headers, and entry points. Key PE concepts: sections (.text, .data, .rsrc), import/export tables, entry point (AddressOfEntryPoint), and relocations.

### Persistence
Techniques used by malware to survive system reboots and maintain presence on a compromised machine. Methods observed across the collection:
- **Registry Run keys** (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`) - most common
- **Windows service installation** - used by more sophisticated variants
- **Startup folder shortcuts**
- **DLL search order hijacking** (STEAMBOT via Steam's plugin loading)
- **Boot sector modification** (rare in this collection)

### Polymorphic Engine
A component that automatically mutates malware code or encrypted layers to produce different binary signatures each time, while maintaining identical functionality. Present in **Phatbot** (for P2P node identification) and **wworm2/WoodWorm** (for AV evasion). The **my_poly_sploit** exploit kit uses polymorphic shellcode generation.

---

## R

### RAT (Remote Access Trojan)
Malware that provides the attacker with full remote control of the compromised system, typically including screen viewing, webcam access, file management, keylogging, and shell access. Distinguished from bots by their focus on individual target surveillance rather than mass automated operations. The collection includes **FBIRAT** and **AryanRat**.

### RFI (Remote File Inclusion)
A web application vulnerability where an attacker can cause the server to include and execute a remote file (typically PHP). Used as an infection vector - the included file is usually a PHP bot or downloader. The collection includes an RFI Scanner tool and a 120-series rxBot variant with built-in RFI scanning.

### Rootkit
Software that hides the presence of malware on a system by modifying operating system behavior. The **Reptile** specimen is notable for including the **FU rootkit** driver, which operates in kernel mode to hide processes from the Windows task manager and other enumeration tools by manipulating the kernel's process linked list (DKOM - Direct Kernel Object Manipulation).

---

## S

### SEH (Structured Exception Handling)
The Windows mechanism for handling hardware and software exceptions. SEH is commonly exploited in buffer overflow attacks - overwriting the SEH handler pointer on the stack to redirect execution to shellcode. Several exploit modules in the collection target SEH-based vulnerabilities. SEH overwrite is also used as an anti-debugging technique.

### Shellcode
Small, self-contained machine code that is injected and executed as part of an exploit. Called "shellcode" because early examples opened a command shell. The exploit pack specimens contain shellcode for various architectures and browsers. **my_poly_sploit** generates polymorphic shellcode that changes its byte pattern on each delivery. See also: **Heap Spray**.

### SOCKS Proxy
A general-purpose proxy protocol that routes network traffic through an intermediary. Many specimens (particularly rxBot variants) include SOCKS4 and SOCKS5 proxy servers, allowing the botmaster to route traffic through infected machines to anonymize their activities. The **PsyProxy** tool provides a management panel for controlling botnet SOCKS proxies.

---

## T

### TAN (Transaction Authentication Number)
A one-time password used by European banks to authorize individual transactions. Zeus web injects specifically targeted TAN entry, either harvesting TANs entered by the user or presenting fake prompts to collect unused TANs. The shift to mobile TANs (mTANs) later drove the development of Zeus mobile variants (ZitMo).

### TFTP (Trivial File Transfer Protocol)
A simple file transfer protocol with no authentication. Several rBot variants include built-in TFTP servers to distribute copies of themselves to newly compromised hosts - after exploiting a vulnerability, the shellcode uses TFTP to download the full bot binary from the attacking machine.

---

## U–V

### UDF (User Defined Function)
In the context of this collection, refers to MySQL UDF injection - a technique where the attacker uploads a malicious shared library to a MySQL server and registers it as a user-defined function, achieving operating system command execution through SQL queries. Used by the **120-series** rxBot variants after brute-forcing MySQL credentials.

---

## W

### Web Inject
A configuration file or template that tells Zeus (or similar banking trojans) how to modify specific web pages in the victim's browser. Web injects add, remove, or modify HTML form fields to capture additional information (PINs, TANs, security questions) or redirect transactions. The Zeus specimen includes inject configs targeting eBay, HSBC, e-gold, Santander, and Citibank. See also: **MitB**.

---

## X–Z

### XOR Encryption
A simple symmetric cipher using the exclusive-or (XOR) bitwise operation. Frequently used in the specimens for lightweight obfuscation of configuration data (C&C server addresses, passwords, channel names). Trivially reversible with a known or brute-forced key. **AkBot** uses XOR encryption for its configuration; many IRC bots XOR-encode their traffic. Not to be confused with strong encryption - XOR with a short key provides obfuscation, not security.

### Zero-Day
A vulnerability that is unknown to the software vendor and for which no patch exists. While none of the specimens in this collection contain true zero-day exploits (all target known, patched vulnerabilities), several exploit modules were likely weaponized when the vulnerabilities were fresh. The DCOM (MS03-026), LSASS (MS04-011), and ASN.1 (MS04-007) exploits found across the rBot/sdBot families were devastating when first deployed.
