---
title: "Bibliography & Further Reading"
description: "Academic references, industry reports, and recommended resources for botnet research"
---

This bibliography collects the key academic, industry, and online resources relevant to understanding the botnet specimens documented in this archive. References are organized by category and listed with full citation information.

---

## Textbooks

These books provide foundational knowledge for malware analysis and understanding the techniques observed in the collection.

1. **Sikorski, Michael & Honig, Andrew.** *Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software.* No Starch Press, 2012. ISBN: 978-1593272906.
   - The definitive guide to static and dynamic malware analysis. Covers PE format, x86 disassembly, debugging, and anti-analysis techniques directly applicable to every Win32 specimen in this collection.

2. **Mitnick, Kevin D. & Simon, William L.** *The Art of Intrusion: The Real Stories Behind the Exploits of Hackers, Intruders & Deceivers.* Wiley, 2005. ISBN: 978-0471782667.
   - Contextualizes the human and social engineering dimensions of the intrusion techniques that botnets automate.

3. **Ligh, Michael Hale; Adair, Steven; Hartstein, Blake & Richard, Matthew.** *Malware Analyst's Cookbook and DVD: Tools and Techniques for Fighting Malicious Code.* Wiley, 2010. ISBN: 978-0470613030.
   - Practical recipes for analyzing malware including network traffic analysis, memory forensics, and automated unpacking - all applicable to botnet analysis.

4. **Szor, Peter.** *The Art of Computer Virus Research and Defense.* Addison-Wesley Professional, 2005. ISBN: 978-0321304544.
   - Comprehensive coverage of virus and worm techniques including polymorphic engines (relevant to Phatbot, wworm2) and AV evasion methods.

5. **Eilam, Eldad.** *Reversing: Secrets of Reverse Engineering.* Wiley, 2005. ISBN: 978-0764574818.
   - Foundational reverse engineering text covering x86, PE format, and API hooking techniques found throughout the collection.

6. **Hoglund, Greg & Butler, Jamie.** *Rootkits: Subverting the Windows Kernel.* Addison-Wesley Professional, 2005. ISBN: 978-0321294319.
   - Directly relevant to the Reptile specimen's FU rootkit driver and DKOM techniques for kernel-mode process hiding.

7. **Schiller, Craig A.; Binkley, Jim; Harley, David; Evron, Gadi; Bradley, Tony; Willems, Carsten & Cross, Michael.** *Botnets: The Killer Web App.* Syngress, 2007. ISBN: 978-1597491358.
   - One of the earliest comprehensive texts on botnets covering IRC-based C&C, the sdBot/rBot/Agobot families, and botnet economics - directly overlapping with this collection's era.

---

## Academic Research Papers

### Botnet Architecture & Detection

8. **Barford, Paul & Yegneswaran, Vinod.** "An Inside Look at Botnets." *Advances in Information Security*, vol. 27, Springer, 2007, pp. 171–191.
   DOI: [10.1007/978-0-387-44599-1_8](https://doi.org/10.1007/978-0-387-44599-1_8)
   - Analysis of botnet source code including rBot and sdBot variants directly relevant to this collection.

9. **Cooke, Evan; Jahanian, Farnam & McPherson, Danny.** "The Zombie Roundup: Understanding, Detecting, and Disrupting Botnets." *Proceedings of the USENIX Workshop on Steps to Reducing Unwanted Traffic on the Internet (SRUTI)*, 2005.
   - Early academic treatment of IRC botnet detection techniques.

10. **Abu Rajab, Moheeb; Zarfoss, Jay; Monrose, Fabian & Terzis, Andreas.** "A Multifaceted Approach to Understanding the Botnet Phenomenon." *Proceedings of the 6th ACM SIGCOMM Conference on Internet Measurement (IMC)*, 2006, pp. 41–52.
    DOI: [10.1145/1177080.1177086](https://doi.org/10.1145/1177080.1177086)
    - Large-scale botnet measurement study covering the same era as this collection.

11. **Gu, Guofei; Porras, Phillip; Yegneswaran, Vinod; Fong, Martin & Lee, Wenke.** "BotHunter: Detecting Malware Infection Through IDS-Driven Dialog Correlation." *Proceedings of the 16th USENIX Security Symposium*, 2007, pp. 167–182.
    - Network-based botnet detection using the infection lifecycle model.

12. **Bailey, Michael; Cooke, Evan; Jahanian, Farnam; Xu, Yunjing & Karir, Manish.** "A Survey of Botnet Technology and Defenses." *Proceedings of the 2009 Cybersecurity Applications & Technology Conference for Homeland Security (CATCH)*, 2009, pp. 299–304.
    DOI: [10.1109/CATCH.2009.40](https://doi.org/10.1109/CATCH.2009.40)

### IRC Bot Analysis

13. **Bacher, Paul; Holz, Thorsten; Kötter, Markus & Wicherski, Georg.** "Know Your Enemy: Tracking Botnets." *The Honeynet Project*, 2005.
    URL: [https://www.honeynet.org/papers/bots/](https://www.honeynet.org/papers/bots/)
    - Seminal paper on using honeypots to track IRC botnets, with direct analysis of sdBot and Agobot families.

14. **Freiling, Felix C.; Holz, Thorsten & Wicherski, Georg.** "Botnet Tracking: Exploring a Root-Cause Methodology to Prevent Distributed Denial-of-Service Attacks." *Proceedings of the 10th European Symposium on Research in Computer Security (ESORICS)*, LNCS 3679, 2005, pp. 319–335.
    DOI: [10.1007/11555827_19](https://doi.org/10.1007/11555827_19)

### Zeus / Banking Trojan Research

15. **Binsalleeh, Hamad; Ormerod, Thomas; Boukhtouta, Amine; Sinha, Prosenjit; Youssef, Amr; Debbabi, Mourad & Wang, Lingyu.** "On the Analysis of the Zeus Botnet Crimeware Toolkit." *Proceedings of the 8th Annual Conference on Privacy, Security and Trust (PST)*, 2010, pp. 31–38.
    DOI: [10.1109/PST.2010.5593240](https://doi.org/10.1109/PST.2010.5593240)
    - Academic analysis of Zeus internals directly relevant to the Zeus specimen in this collection.

16. **Wyke, James.** "The ZeuS Sourcecode: A Case Study in Do-It-Yourself Crimeware." *Sophos Technical Papers*, 2011.
    - Detailed walkthrough of Zeus source code after its public leak.

17. **Stone-Gross, Brett; Cova, Marco; Cavallaro, Lorenzo; Gilbert, Bob; Szydlowski, Martin; Kemmerer, Richard; Kruegel, Christopher & Vigna, Giovanni.** "Your Botnet is My Botnet: Analysis of a Botnet Takeover." *Proceedings of the 16th ACM Conference on Computer and Communications Security (CCS)*, 2009, pp. 635–647.
    DOI: [10.1145/1653662.1653738](https://doi.org/10.1145/1653662.1653738)
    - Describes the Torpig botnet takeover, methodologically relevant to banking trojan analysis.

### P2P Botnets

18. **Holz, Thorsten; Steiner, Moritz; Dahl, Frederic; Biersack, Ernst & Freiling, Felix.** "Measurements and Mitigation of Peer-to-Peer-based Botnets: A Case Study on Storm Worm." *Proceedings of the 1st USENIX Workshop on Large-Scale Exploits and Emergent Threats (LEET)*, 2008.
    - P2P botnet analysis relevant to Phatbot's WASTE protocol implementation.

19. **Wang, Ping; Sparks, Sherri & Zou, Cliff C.** "An Advanced Hybrid Peer-to-Peer Botnet." *IEEE Transactions on Dependable and Secure Computing*, vol. 7, no. 2, 2010, pp. 113–127.
    DOI: [10.1109/TDSC.2008.35](https://doi.org/10.1109/TDSC.2008.35)

### IoT Botnets (Context for hydra-2008.1)

20. **Antonakakis, Manos et al.** "Understanding the Mirai Botnet." *Proceedings of the 26th USENIX Security Symposium*, 2017, pp. 1093–1110.
    - While covering Mirai (2016), this paper provides essential context for understanding how hydra-2008.1 anticipated IoT botnet techniques eight years earlier.

21. **Kolias, Constantinos; Kambourakis, Georgios; Stavrou, Angelos & Voas, Jeffrey.** "DDoS in the IoT: Mirai and Other Botnets." *Computer*, vol. 50, no. 7, IEEE, 2017, pp. 80–84.
    DOI: [10.1109/MC.2017.201](https://doi.org/10.1109/MC.2017.201)

---

## Industry Reports

### Threat Landscape Reports

22. **Symantec.** *Internet Security Threat Report (ISTR)*, Volumes X–XIV (2006–2009). Symantec Corporation.
    URL: [https://www.broadcom.com/support/security-center](https://www.broadcom.com/support/security-center)
    - Annual threat reports covering the exact era of this collection's specimens, documenting the prevalence of IRC botnets, banking trojans, and exploit kits in the wild.

23. **McAfee.** *McAfee Threats Report: Fourth Quarter 2008.* McAfee Labs, 2009.
    - Documents the rise of Zeus and the shift from IRC to HTTP-based C&C.

24. **ENISA (European Union Agency for Cybersecurity).** *ENISA Threat Landscape Report*, 2012–2024 editions.
    URL: [https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends](https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends)
    - Ongoing threat landscape analysis providing historical context for botnet evolution.

25. **FBI Internet Crime Complaint Center (IC3).** *Internet Crime Report*, Annual editions 2005–2009.
    URL: [https://www.ic3.gov/](https://www.ic3.gov/)
    - Law enforcement perspective on the financial impact of botnets and banking trojans during the collection's era.

### Botnet-Specific Reports

26. **Trend Micro.** "A Taxonomy of Botnet Structures." *Trend Micro Research Paper*, 2006.
    - Classification of botnet architectures applicable to the IRC, HTTP, and P2P specimens.

27. **SecureWorks (Dell).** "Zeus Banking Trojan Threat Analysis." *Counter Threat Unit Research*, 2010.
    - Detailed Zeus analysis from a threat intelligence perspective.

28. **Shadowserver Foundation.** Botnet tracking statistics and reports, 2005–2010.
    URL: [https://www.shadowserver.org/](https://www.shadowserver.org/)
    - Real-time botnet tracking data from the era of these specimens.

---

## Online Resources & Tools

### Threat Intelligence Frameworks

29. **MITRE ATT&CK Framework.**
    URL: [https://attack.mitre.org/](https://attack.mitre.org/)
    - The standard framework for classifying adversary tactics and techniques. Used throughout this documentation to map specimen capabilities to standardized technique IDs (e.g., T1059 Command and Scripting Interpreter, T1547 Boot or Logon Autostart Execution).

30. **MITRE ATT&CK - Software entries for relevant malware.**
    - Zeus: [https://attack.mitre.org/software/S0018/](https://attack.mitre.org/software/S0018/)
    - ATT&CK's own documentation of Zeus techniques.

### Malware Analysis Platforms

31. **VirusTotal.**
    URL: [https://www.virustotal.com/](https://www.virustotal.com/)
    - Multi-engine malware scanning service. Useful for checking detection rates of compiled specimens (in controlled research environments only).

32. **MalwareBazaar (abuse.ch).**
    URL: [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)
    - Malware sample sharing platform for researchers. Contains tagged samples from many families in this collection.

33. **ANY.RUN.**
    URL: [https://any.run/](https://any.run/)
    - Interactive malware analysis sandbox. Useful for behavioral analysis research (not used in this static-analysis-only project).

34. **Hybrid Analysis (CrowdStrike).**
    URL: [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/)
    - Free malware analysis service combining static and dynamic analysis.

35. **Malpedia (Fraunhofer FKIE).**
    URL: [https://malpedia.caad.fkie.fraunhofer.de/](https://malpedia.caad.fkie.fraunhofer.de/)
    - Curated malware family encyclopedia with YARA rules and references. Contains entries for Zeus, Agobot, and other families in this collection.

### Vulnerability Databases

36. **NIST National Vulnerability Database (NVD).**
    URL: [https://nvd.nist.gov/](https://nvd.nist.gov/)
    - Standard reference for CVE details. Key CVEs referenced in the collection:
    - **CVE-2003-0352** (MS03-026): DCOM RPC buffer overflow - exploited by rBot, sdBot, Agobot
    - **CVE-2004-0200** (MS04-011): LSASS buffer overflow - exploited by rBot, Sasser-derived code
    - **CVE-2003-0818** (MS04-007): ASN.1 vulnerability - exploited by rBot, rxBot
    - **CVE-2006-3439** (MS06-040): NetAPI32 buffer overflow - exploited by later rBot/rxBot variants
    - **CVE-2005-1983** (MS05-039): PnP buffer overflow - exploited by rxBot
    - **CVE-2004-1029**: Symantec AV ActiveX vulnerability - exploited by URX variants
    - **CVE-2006-2630**: Symantec AV stack overflow - exploited by rxBot mods
    - **CVE-2003-0109**: WebDAV ntdll.dll overflow - exploited by rBot
    - **CVE-2003-0533**: IIS SSL PCT overflow - exploited by rBot

37. **MITRE CVE Database.**
    URL: [https://cve.mitre.org/](https://cve.mitre.org/)
    - Canonical CVE identifier database.

38. **Microsoft Security Bulletins Archive.**
    URL: [https://learn.microsoft.com/en-us/security-updates/](https://learn.microsoft.com/en-us/security-updates/)
    - Original Microsoft advisories for the Windows vulnerabilities exploited by the specimens.

### Historical References

39. **The Honeynet Project.**
    URL: [https://www.honeynet.org/](https://www.honeynet.org/)
    - Produced foundational research on IRC botnets using honeypots during the 2004–2008 era.

40. **SANS Internet Storm Center.**
    URL: [https://isc.sans.edu/](https://isc.sans.edu/)
    - Real-time threat monitoring with historical diary entries covering the spread of the bot families in this collection.

---

## Source Repository

41. **maestron/botnets** - Original GitHub repository containing the source code specimens analyzed in this documentation.
    URL: [https://github.com/maestron/botnets](https://github.com/maestron/botnets)
    - Archival collection of historical botnet source code for educational and research purposes.

---

## Recommended Reading Order

For students new to malware analysis, we recommend the following progression:

1. Start with **Sikorski & Honig (2012)** for analysis fundamentals
2. Read **Schiller et al. (2007)** for botnet-specific context
3. Review the **MITRE ATT&CK** framework for standardized terminology
4. Study **Bacher et al. (2005)** for IRC botnet tracking methodology
5. Explore **Binsalleeh et al. (2010)** for Zeus-specific analysis
6. Reference **Antonakakis et al. (2017)** for IoT botnet evolution context
7. Use the **NVD** to understand each exploited vulnerability in detail
