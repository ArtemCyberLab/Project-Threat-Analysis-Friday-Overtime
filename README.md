Project Objective:
My goal was to conduct a detailed investigation into a cyber threat identified by the financial company SwiftSpend Finance. I analyzed malware samples, performed both static and dynamic analysis, and identified related threats and attack tactics.

What I Did:

Initial Data Analysis:

Obtained files suspected to contain malware.

Uploaded the files to an isolated environment for safe examination.

Preliminary Research:

Conducted an automated analysis of the files using specialized tools.

Identified the structure of the malicious files and potential indicators of compromise.

In-Depth Analysis:

Conducted a detailed analysis of the malware, studying its dynamic behavior and propagation mechanisms.

Identified the obfuscation and evasion techniques used by attackers.

Correlation with Global Threat Databases:

Determined the SHA1 hash of the "pRsm.dll" file (9d1ecbbe8637fed0d89fca1af35ea821277ad2e8).

Discovered that this file is part of the MgBot malware framework.

Identified the associated MITRE ATT&CK technique (T1123).

Investigation of Attacker Infrastructure:

Found the malware download URL, first detected on November 2, 2020 (hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe).

Identified the command-and-control (C&C) server used by the attackers (122[.]10[.]90[.]12), first detected on September 14, 2020.

Determined the SHA1 hash of spyware targeting Android devices (1c1fe906e822012f6235fcc53f601d006d15d7be), which was distributed via this server on November 16, 2022.

Conclusion:
During the investigation, I confirmed the presence of malware within the SwiftSpend Finance infrastructure. I identified that this malware is part of the advanced MgBot malware framework, associated with APT group activity. The methods of distribution were established, along with the IP addresses and domains used by the attackers. The obtained data will enable effective threat mitigation and minimize potential attack consequences.
