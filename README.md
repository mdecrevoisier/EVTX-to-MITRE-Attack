# EVTX to MITRE Att@ck

## Project purpose
**EVTX to MITRE Att@ck** is a *Security Information Management System* orientated project. It provides >270 Windows IOCs indicators classified per Tactic and Technique in order to address different security scenarios with your SIEM:
* Measure your security coverage
* Enhance your detection capacities
* Identify security gaps or uncovered threats
* Design new use cases

## How to use the IOCs
IOCs are provided in the EVTX format, the standard format established by Microsoft starting Windows Server 2008 and Windows Vista for event logs. Depending on the SIEM solution you utilize, you may need to make your agent (NXLog, Winlogbeat, Splunk UF, ArcSight, WinCollect, Snare, ...) pointing to the EVTX files and send the content to your SIEM in the adequate format.

## Microsoft log sources used:
* Windows 10
* Windows Server 2012 R2 and higher
* Active Directory Domain Services (ADDS)
* Active Directory Certification Services (ADCS / PKI) with online responder (OCSP)
* SQL Server 2014
* Windows Defender
* SYSMON v11 and higher
* Exchange 2016
* Internet Information Services (IIS web server) -- *planned*

## Related and/or connected projects:
If you are interesting in external projects arround SIGMA and EVTX analysis, I would like to suggest the following ones:
* **EVTX-ATTACK** from @sbousseaden: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
* **OTRF/Security-Datasets (from Mordor project)**: https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows
* **Atomic RedTeam**: https://github.com/redcanaryco/atomic-red-team
* Export EVTX to Elastic with Winlogbeat: https://medium.com/@duzvik/import-evtx-collections-in-to-elastic-989b7f49b4b8
* **EvtxToElk**: https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/
* **Zircolite** (SIGMA detection for EVTX): https://github.com/wagga40/Zircolite

## IOCs content

Att@ck Tactic	| Att@ck  Technique	| Description | 	Event IDs   |			Threat name / Tool / CVE
|:-------------------------|:------------------|:-------------------------|:------------------|:------------------|
Antivirus | Antivirus | Defender: antivirus not up to date | 1151 | 
Antivirus | Antivirus | Defender: massive malware outbreak detected on multiple hosts | 1116 | 
Antivirus | Antivirus | Defender: massive malwares detected on a single host | 1116 | 
TA0001-Initial access | T1078.002-Valid accounts-Domain accounts | Login denied due to account policy restrictions | 4625 | 
TA0001-Initial access | T1078.002-Valid accounts-Domain accounts | Login failure from a single source with a disabled account | 33205 | 
TA0001-Initial access | T1078.002-Valid accounts-Domain accounts | Success login on OpenSSH server | 4624/4 | SSH server
TA0001-Initial access | T1078-Valid accounts | RDP reconnaissance with valid credentials performed to multiple hosts | 4624/1149 | 
TA0002-Execution | T1047-Windows Management Instrumentation | Impacket WMIexec process execution | 4688 | WMIexec
TA0002-Execution | T1053.005-Scheduled Task | Interactive shell triggered by scheduled task (at, deprecated) | 4688 | 
TA0002-Execution | T1053.005-Scheduled Task | Persistent scheduled task with SYSTEM privileges creation | 4688 | 
TA0002-Execution | T1053.005-Scheduled Task | Remote schedule task creation via named pipes | 5145 | Atexec
TA0002-Execution | T1053.005-Scheduled Task | Schedule task created and deleted in a short period of time | 4698-4699 | 
TA0002-Execution | T1053.005-Scheduled Task | Schedule task created with suspicious arguments | 4698 | Atexec
TA0002-Execution | T1053.005-Scheduled Task | Schedule task fastly created and deleted | 4698,4699 | Atexec
TA0002-Execution | T1053.005-Scheduled Task | Scheduled task creation | 4688 | 
TA0002-Execution | T1059.001-Command and Scripting Interpreter: PowerShell | Encoded PowerShell payload deployed | 800/4103/4104 | 
TA0002-Execution | T1059.001-Command and Scripting Interpreter: PowerShell | Interactive PipeShell over SMB named pipe | 800/4103/4104 | 
TA0002-Execution | T1059.001-Command and Scripting Interpreter: PowerShell | Payload downloaded via PowerShell | 800/4103/4104 | 
TA0002-Execution | T1059.003-Windows Command Shell | Encoded PowerShell payload deployed via process execution | 4688 | 
TA0002-Execution | T1059.003-Windows Command Shell | SQL Server payload injectection for reverse shell (MSF) | 4688 | 
TA0002-Execution | T1204-User execution | Edge abuse for payload download via console | 4688 | 
TA0002-Execution | T1204-User execution | Edge/Chrome headless feature abuse for payload download | 4688 | 
TA0002-Execution | T1569.002-Service Execution | PSexec installation detected | 4688 | 
TA0002-Execution | T1569.002-Service Execution | Service massive failures (native) | 7000/7009 | Tchopper
TA0002-Execution | T1569.002-Service Execution | Service massive installation (native) | 7045/4697 | Tchopper
TA0002-Execution | T1569.002-Service Execution | Service massive remote creation via named pipes (native) | 5145 | Tchopper
TA0003-Persistence | T1078.002-Valid accounts-Domain accounts | Account renamed to "admin" (or likely) | 4781 | 
TA0003-Persistence | T1098.xxx-Account manipulation | Computer account created with privileges | 4741 | CVE-2021-42278/42287 & SAM-the-admin
TA0003-Persistence | T1098.xxx-Account manipulation | Computer account renamed without a trailing $ | 4781 | CVE-2021-42278/42287 & SAM-the-admin
TA0003-Persistence | T1098.xxx-Account Manipulation | High risk domain group membership change | 4728/4756 | 
TA0003-Persistence | T1098.xxx-Account manipulation | High risk Exchange group membership change | 4728,4756,4732 | 
TA0003-Persistence | T1098.xxx-Account Manipulation | High risk local-domain local group membership change | 4732 | 
TA0003-Persistence | T1098.xxx-Account manipulation | High risk Skype/Lync/OCS group membership change | 4728,4756,4732 | 
TA0003-Persistence | T1098.xxx-Account manipulation | Host delegation settings changed for potential abuse (any protocol) | 4742 | Rubeus
TA0003-Persistence | T1098.xxx-Account manipulation | Host delegation settings changed for potential abuse (any service, Kerberos only) | 4742 | Rubeus
TA0003-Persistence | T1098.xxx-Account manipulation | Host delegation settings changed for potential abuse (Kerberos only) | 4742 | Rubeus
TA0003-Persistence | T1098.xxx-Account manipulation | Low risk Skype/Lync/OCS group membership change | 4728,4756,4732 | 
TA0003-Persistence | T1098.xxx-Account manipulation | Medium risk Exchange group membership change | 4728,4756,4732 | 
TA0003-Persistence | T1098.xxx-Account Manipulation | Medium risk local-domain local group membership change | 4732 | 
TA0003-Persistence | T1098.xxx-Account manipulation | Medium risk Skype/Lync/OCS group membership change | 4728,4756,4732 | 
TA0003-Persistence | T1098.xxx-Account Manipulation | Member added and removed from a group by a user account in a short period of time  | 4728/29,4756/57,4732/33 | 
TA0003-Persistence | T1098.xxx-Account Manipulation | Member added to a group by the same account | 4728,4756,4732 | 
TA0003-Persistence | T1098.xxx-Account manipulation | Member added to DNSadmins group for DLL abuse | 4728,4756,4732 | DNS DLL abuse
TA0003-Persistence | T1098.xxx-Account manipulation | New admin (or likely) created by a non administrative account | 4720 | 
TA0003-Persistence | T1098.xxx-Account manipulation | SPN modification of a computer account (Directory Services) | 5136 | DCShadow
TA0003-Persistence | T1098.xxx-Account manipulation | SPN modification of a computer account | 4742 | 
TA0003-Persistence | T1098.xxx-Account manipulation | SPN modification of a computer account | 4742 | DCShadow
TA0003-Persistence | T1098.xxx-Account manipulation | SPN modification of a user account | 5136 | Kerberoasting
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: new member added to a database role | 33205 | 
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: new member added to server role | 33205 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User account created and/or set with reversible encryption detected | 4738 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User account marked as "sensitive and cannot be delegated" its had protection removed | 4738 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User account set to not require Kerberos pre-authentication | 4738 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User account set to use Kerberos DES encryption | 4738 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User account with password set to never expire detected | 4738 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User account with password set to not require detected | 4738 | 
TA0003-Persistence | T1098.xxx-Account manipulation | User password change using current hash password - ChangeNTLM | 4723 | Mimikatz
TA0003-Persistence | T1098.xxx-Account manipulation | User password change without previous password known - SetNTLM | 4724 | Mimikatz
TA0003-Persistence | T1098.xxx-Account Manipulation | User performing massive group membership changes on multiple differents groups | 4728,4756 | 
TA0003-Persistence | T1098-Account Manipulation | Computer account set for RBCD delegation | 5136 | 
TA0003-Persistence | T1098-Account Manipulation | Disabled guest or builtin account activated | 4722 | 
TA0003-Persistence | T1098-Account Manipulation | SPN added to an account (command) | 4688/1 | 
TA0003-Persistence | T1136.001-Create account-Local account | Hidden account creation (with fast deletion) | 4720/4726 | 
TA0003-Persistence | T1136.001-Create account-Local account | Local user account created on a single host | 4720 | 
TA0003-Persistence | T1136.001-Create account-Local account | SQL Server: disabled SA account enabled | 33205 | 
TA0003-Persistence | T1136.002-Create account-Domain account | Computer account created and deleted in a short period of time | 4741/4743 | 
TA0003-Persistence | T1136.002-Create account-Domain account | User account created and deleted in a short period of time | 4720/4726 | 
TA0003-Persistence | T1136.002-Create account-Domain account | User account creation disguised in a computer account | 4720/4781 | 
TA0003-Persistence | T1136-Create account | User creation via commandline | 4688 | 
TA0003-Persistence | T1505.001-SQL Stored Procedures | SQL lateral movement with CLR | 15457 | 
TA0003-Persistence | T1505.001-SQL Stored Procedures | SQL Server xp_cmdshell procedure activated | 18457 | 
TA0003-Persistence | T1505.001-SQL Stored Procedures | SQL Server: sqlcmd & ossql utilities abuse | 4688 | 
TA0003-Persistence | T1505.001-SQL Stored Procedures | SQL Server: started in single mode for password recovery | 4688 | 
TA0003-Persistence | T1505.002-Server Software Component: Transport Agent | Exchange transport agent injection via configuration file | 11 | 
TA0003-Persistence | T1505.002-Server Software Component: Transport Agent | Exchange transport agent installation artifacts | 1/6 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Encoded PowerShell payload deployed via service installation | 7045/4697 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Impacket SMBexec service registration (native) | 7045/4697 | SMBexec
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Mimikatz service driver installation detected | 7045/4697 | Mimikatz
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service abuse with backdoored "command failure" (PowerShell) | 800/4103/4104 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service abuse with backdoored "command failure" (registry) | 4688/1 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service abuse with backdoored "command failure" (service) | 4688/1 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service abuse with malicious ImagePath (PowerShell) | 800/4103/4104 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service abuse with malicious ImagePath (registry) | 4688/1 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service abuse with malicious ImagePath (service) | 4688/1 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service created for RDP session hijack | 7045/4697 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service creation (command) | 4688 | 
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service creation (PowerShell) | 800/4103/4104 | 
TA0003-Persistence | T1546.003-Windows Management Instrumentation Event Subscription | System crash behavior manipulation  (registry) | 13 | WMImplant
TA0003-Persistence | T1546.003-Windows Management Instrumentation Event Subscription | WMI registration (PowerShell) | 800/4103/4104 | 
TA0003-Persistence | T1546.003-Windows Management Instrumentation Event Subscription | WMI registration | 19,20,21 | 
TA0003-Persistence | T1546.007-Netsh Helper DLL | Netsh helper DLL command abuse | 4688 | 
TA0003-Persistence | T1546.007-Netsh Helper DLL | Netsh helper DLL registry abuse | 12/13 | 
TA0003-Persistence | T1546-Event Triggered Execution | AdminSDHolder container permissions modified | 5136 | 
TA0003-Persistence | T1546-Event Triggered Execution | Extended rights backdoor obfuscation (via localizationDisplayId) | 5136 | 
TA0003-Persistence | T1547.008-Boot or Logon Autostart Execution: LSASS Driver | Security package (SSP) loaded into LSA (native) | 4622 | 
TA0003-Persistence | T1574.002-DLL Side-Loading | DNS DLL "serverlevelplugindll" command execution | 1/13 | DNS DLL abuse
TA0003-Persistence | T1574.002-DLL Side-Loading | Failed DLL loaded by DNS server | 150 | DNS DLL abuse
TA0003-Persistence | T1574.002-DLL Side-Loading | Success DLL loaded by DNS server | 770 | DNS DLL abuse
TA0003-Persistence | T1574.010-Hijack execution flow: service file permissions weakness | Service permissions modified (registry) | 4688 | 
TA0003-Persistence | T1574.010-Hijack execution flow: service file permissions weakness | Service permissions modified (service) | 4688 | 
TA0004-Privilege Escalation | T1068-Exploitation for Privilege Escalation | Privilege SeMachineAccountPrivilege abuse | 4673 | CVE-2021-42278/42287 & SAM-the-admin
TA0004-Privilege Escalation | T1134.001- Access Token Manipulation: Token Impersonation/Theft | Anonymous login | 4624/4688 | RottenPotatoNG
TA0004-Privilege Escalation | T1134.002- Access Token Manipulation: Create Process with Token | Privilege escalation via runas (command) | 4688/4648/4624 | 
TA0004-Privilege Escalation | T1134.002- Access Token Manipulation: Create Process with Token | Privilege escalation via RunasCS | 4688 | 
TA0004-Privilege Escalation | T1134-Access Token Manipulation | New access rights granted to an account by a standard user | 4717 | 
TA0004-Privilege Escalation | T1134-Access Token Manipulation | User right granted to an account by a standard user | 4704 | 
TA0004-Privilege Escalation | T1484.001-Domain Policy Modification-Group Policy Modification | Modification of a sensitive Group Policy  | 5136 | 
TA0004-Privilege Escalation | T1543.003-Create or Modify System Process-Windows Service | PSexec service installation detected | 7045/4697 | 
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features | CMD executed by stickey key and detected via hash | 1 | Sticky key
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features | Sticky key called CMD via command execution | 4688/1 | Sticky key
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features | Sticky key failed sethc replacement by CMD | 4656 | Sticky key
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features | Sticky key file created from CMD copy | 11 | Sticky key
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features | Sticky key IFEO command for registry change | 4688 | Sticky key
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features | Sticky key IFEO registry changed | 12/13 | Sticky key
TA0004-Privilege Escalation | T1547.010-Port Monitors | Print spooler privilege escalation via printer added | 800/4103/4104 | PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
TA0004-Privilege Escalation | T1574.002-DLL Side-Loading | External printer mapped | 4688/4648 | PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
TA0004-Privilege Escalation | T1574.002-DLL Side-Loading | New external device added  | 6416 | PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
TA0004-Privilege Escalation | T1574.002-DLL Side-Loading | Printer spool driver from Mimikatz installed  | 808 / 354 / 321 | PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
TA0004-Privilege Escalation | T1574.002-DLL Side-Loading | Spool process spawned a CMD shell | 4688/1 | PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
TA0005-Defense Evasion | T1027-Obfuscated Files or Information | Payload obfuscated transfer via service name | 4688 | Tchopper
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Event log file(s) cleared | 104/1102 | 
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Tentative of clearing event log file(s) detected (command) | 4688 | 
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Tentative of clearing event log file(s) detected (PowerShell) | 800/4103/4104 | 
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Tentative of clearing event log file(s) detected (wmi) | 4688 | 
TA0005-Defense Evasion | T1070.006-Timestomp | System time changed | 4616 | 
TA0005-Defense Evasion | T1078.002-Valid accounts-Domain accounts | Login from a user member of a "special group" detected (special logon) | 4964 | 
TA0005-Defense Evasion | T1112-Modify registry | Impacket SMBexec service registration (registry) | 13 | SMBexec
TA0005-Defense Evasion | T1197-BITS job | Command execution related to a suspicious BITS activity detected | 4688 | 
TA0005-Defense Evasion | T1197-BITS job | Command execution related to a suspicious BITS activity detected | 800/4103/4104 | 
TA0005-Defense Evasion | T1197-BITS job | High amount of data downloaded via BITS | 60 | 
TA0005-Defense Evasion | T1207-Rogue domain controller | New fake domain controller registration | 5137 / 5141 | DCShadow
TA0005-Defense Evasion | T1207-Rogue domain controller | Sensitive attributes accessed | 4662 | DCShadow
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Computer account modifying AD permissions | 5136 | PrivExchange
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Network share permissions changed | 5143 | 
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | OCSP security settings changed | 5124(OCSP) | 
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Permissions changed on a GPO | 5136 | 
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Sensitive GUID related to "Replicate directory changes" detected  | 4662 | DCSync
TA0005-Defense Evasion | T1553.003- Subvert Trust Controls: SIP and Trust Provider Hijacking  | Suspicious SIP or trust provider registration | 12-13 | 
TA0005-Defense Evasion | T1562.001-Impair Defenses-Disable or modify tools | Defender: critical security component disabled (command) | 4688/1 | 
TA0005-Defense Evasion | T1562.001-Impair Defenses-Disable or modify tools | Defender: critical security component disabled (PowerShell) | 800/4103/4104 | 
TA0005-Defense Evasion | T1562.001-Impair Defenses-Disable or modify tools | Defender: default action set to allow any threat (PowerShell) | 800/4103/4104 | 
TA0005-Defense Evasion | T1562.001-Impair Defenses-Disable or modify tools | Defender: exclusion added (native) | 5007 | 
TA0005-Defense Evasion | T1562.001-Impair Defenses-Disable or modify tools | Defender: exclusion added (PowerShell) | 800/4103/4104 | 
TA0005-Defense Evasion | T1562.001-Impair Defenses-Disable or modify tools | Defender: service component status disabled (Registry via Sysmon) | 13 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | Audit policy disabled | 4719 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | Domain policy changed on one or multiple hosts | 4739 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | Membership of a special group updated | 4908 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | SQL Server: Audit object deleted | 33205 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | SQL Server: Audit object disabled | 33205 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | SQL Server: Audit specifications deleted | 33205 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | SQL Server: Audit specifications disabled | 33205 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | SQL Server: Database audit specifications deleted | 33205 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | SQL Server: Database audit specifications disabled | 33205 | 
TA0005-Defense Evasion | T1562.002-Impair Defenses: Disable Windows Event Logging  | Tentative of disabling or clearing audit policy by commandline | 4688 | 
TA0005-Defense Evasion | T1562.004-Disable or Modify System Firewall | Firewall deactivation (cmd) | 4688 | 
TA0005-Defense Evasion | T1562.004-Disable or Modify System Firewall | Firewall deactivation (firewall) | 2003/4950 | 
TA0005-Defense Evasion | T1562.004-Disable or Modify System Firewall | Firewall deactivation (PowerShell) | 800/4103/4104 | 
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | Any/any firewall rule created | 2004 | 
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | Firewall rule created by a suspicious command (netsh.exe, wmiprvse.exe) | 2004 | 
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | Firewall rule created by a user account | 2004 | 
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | OpenSSH server firewall configuration (command) | 4688/1 | SSH server
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | OpenSSH server firewall configuration (firewall) | 2004 | SSH server
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | OpenSSH server firewall configuration (PowerShell) | 800/4103/4104 | SSH server
TA0005-Defense Evasion | T1564.006-Hide Artifacts: Run Virtual Instance | WSL for Windows installation detected (command) | 4688 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS credential dump with LSASSY (kernel) | 4656/4663 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS credential dump with LSASSY (PowerShell) | 800/4103/4104 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS credential dump with LSASSY (process) | 4688/1 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS credential dump with LSASSY (share) | 5145 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS credentials dump via Task Manager (file) | 11 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS dump indicator via Task Manager access | 4688 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS process accessed by a non system account | 4656/4663 | 
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | SAM database user credential dump | 4661 | Mimikatz
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | Task manager used to dump LSASS process | 4663 | 
TA0006-Credential Access | T1003.002-Security Account Manager | Password dump over SMB ADMIN$ | 5145 | Secretdump
TA0006-Credential Access | T1003.002-Security Account Manager | SAM database access during DCshadow | 4661 | DCShadow
TA0006-Credential Access | T1003.003-NTDS | IFM created | 325/327 | 
TA0006-Credential Access | T1003.003-NTDS | IFM created from command line | 4688 | 
TA0006-Credential Access | T1003.003-OS Credential-Dumping NTDS | DSRM configuration changed (Reg via command) | 4688 | 
TA0006-Credential Access | T1003.003-OS Credential-Dumping NTDS | DSRM configuration changed (Reg via PowerShell) | 800/4103/4104 | 
TA0006-Credential Access | T1003.003-OS Credential-Dumping NTDS | DSRM password reset | 4794 | 
TA0006-Credential Access | T1003.006-DCSync | Member added to a Exchange DCsync related group  | 4728,4756,4732 | DCSync
TA0006-Credential Access | T1003-Credential dumping | Backdoor introduction via registry permission change through WMI (DAMP) | 4674 | DAMP
TA0006-Credential Access | T1003-Credential dumping | Diskshadow abuse | 4688 | 
TA0006-Credential Access | T1003-Credential dumping | Wdigest authentication enabled (Reg via command) | 4688 | 
TA0006-Credential Access | T1003-Credential dumping | Wdigest authentication enabled (Reg via Sysmon) | 12/13 | 
TA0006-Credential Access | T1040-Network sniffing | Windows native sniffing tool Pktmon usage | 4688 | 
TA0006-Credential Access | T1110.xxx-Brut force | Brutforce enumeration on Windows OpenSSH server with non existing user | 4625/4 | SSH server
TA0006-Credential Access | T1110.xxx-Brut force | Brutforce on Windows OpenSSH server with valid user | 4625/4 | SSH server
TA0006-Credential Access | T1110.xxx-Brut force | Kerberos brutforce enumeration with existing/unexsting users (Kerbrute) | 4771/4768 | 
TA0006-Credential Access | T1110.xxx-Brut force | Kerberos brutforce with not existing users | 4771/4768 | 
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source with different non existing accounts | 33205 | 
TA0006-Credential Access | T1552.004-Unsecured Credentials-Private Keys | Unknown application accessing certificate private key detected | 70(CAPI2) | Mimikatz
TA0006-Credential Access | T1555.003-Credentials from Password Stores: Credentials from Web Browsers | User browser credentials dump via network share | 5145 | DonPapi, Lazagne
TA0006-Credential Access | T1555.004-Windows Credential Manager | Credentials (protected by DPAPI) dump via network share | 5145 | DonPapi, Lazagne
TA0006-Credential Access | T1555.004-Windows Credential Manager | Vault credentials were read | 5382 | 
TA0006-Credential Access | T1555-Credentials from Password Stores | Suspicious Active Directory DPAPI attributes accessed | 4662 | 
TA0006-Credential Access | T1555-Credentials from Password Stores | User files dump via network share | 5145 | DonPapi, Lazagne
TA0006-Credential Access | T1557.001-MiM:LLMNR/NBT-NS Poisoning and SMB Relay | Discovery for print spooler bug abuse via named pipe | 5145 | 
TA0006-Credential Access | T1558.001-Golden Ticket | Kerberos TGS ticket request related to a potential Golden ticket | 4769 | Golden ticket
TA0006-Credential Access | T1558.001-Golden Ticket | SMB Admin share accessed with a forged Golden ticket | 5140/5145 | Golden ticket
TA0006-Credential Access | T1558.001-Golden Ticket | Success login impersonation with forged Golden ticket | 4624 | Golden ticket
TA0006-Credential Access | T1558.003-Kerberoasting | KerberOAST ticket (TGS) request detected (low encryption) | 4769 | Kerberoast
TA0006-Credential Access | T1558.004-Steal or Forge Kerberos Tickets: AS-REP Roasting | Kerberos AS-REP Roasting ticket request detected | 4768 | AS-REP Roasting
TA0006-Credential Access | T1558-Steal or Forge Kerberos Tickets | Kerberos ticket without a trailing $  | 4768-4769 | CVE-2021-42278/42287 & SAM-the-admin
TA0006-Credential Access | T1558-Steal or Forge Kerberos Tickets | Suspicious Kerberos proxiable ticket | 4768 | CVE-2021-42278/42287 & SAM-the-admin
TA0007-Discovery | T1016-System Network Configuration Discovery | Firewall configuration enumerated (command) | 4688 | 
TA0007-Discovery | T1016-System Network Configuration Discovery | Firewall configuration enumerated (PowerShell) | 800/4103/4104 | 
TA0007-Discovery | T1016-System Network Configuration Discovery | Tentative of zone transfer from a non DNS server detected | 6004(DNSserver) | 
TA0007-Discovery | T1018-Remote System Discovery | DNS hosts file accessed via network share | 5145 | 
TA0007-Discovery | T1046-Network Service Scanning | RDP discovery performed on multiple hosts | 4625/131 | 
TA0007-Discovery | T1046-Network Service Scanning | Suspicious anonymous login | 4624 | 
TA0007-Discovery | T1069.001-Discovery domain groups | Local domain group enumeration via RID brutforce | 4661 | CrackMapExec
TA0007-Discovery | T1069.001-Discovery local groups | Remote local administrator group enumerated | 4799 | SharpHound
TA0007-Discovery | T1069.002-Discovery domain groups | Domain group enumeration | 4661 | CrackMapExec
TA0007-Discovery | T1069.002-Discovery domain groups | Honeypot object (container, computer, group, user) enumerated | 4662 | SharpHound
TA0007-Discovery | T1069.002-Discovery domain groups | Massive SAM domain users & groups discovery | 4661 | 
TA0007-Discovery | T1069.002-Discovery domain groups | Sensitive SAM domain user & groups discovery | 4661 | 
TA0007-Discovery | T1069-Permission Groups Discovery | Group discovery via commandline | 4688 | 
TA0007-Discovery | T1069-Permission Groups Discovery | Group discovery via PowerShell | 800/4103/4104 | 
TA0007-Discovery | T1082-System Information Discovery | Audit policy settings collection | 4688 | 
TA0007-Discovery | T1087.002-Domain Account discovery | Active Directory PowerShell module called from a non administrative host | 600 | 
TA0007-Discovery | T1087.002-Domain Account discovery | Single source performing host enumeration over Kerberos ticket (TGS) detected | 4769 | SharpHound
TA0007-Discovery | T1087-Account discovery | SPN enumeration (command) | 4688/1 | Kerberoast
TA0007-Discovery | T1087-Account discovery | SPN enumeration (PowerShell) | 800/4103/4104 | 
TA0007-Discovery | T1087-Account discovery | User enumeration via commandline | 4688 | 
TA0007-Discovery | T1135-Network Share Discovery | Host performing advanced named pipes enumeration on different hosts via SMB | 5145 | SharpHound
TA0007-Discovery | T1135-Network Share Discovery | Network share discovery and/or connection via commandline | 4688 | 
TA0007-Discovery | T1135-Network Share Discovery | Network share manipulation via commandline | 4688 | 
TA0007-Discovery | T1201-Password Policy Discovery | Domain password policy enumeration | 4661 | CrackMapExec
TA0007-Discovery | T1201-Password Policy Discovery | Password policy discovery via commandline | 4688 | 
TA0007-Discovery | T1482-Domain Trust Discovery | Active Directory Forest PowerShell class called from a non administrative host | 800/4103/4104 | 
TA0008-Lateral Movement | T1021.001-Remote Desktop Protocol | Denied RDP login with valid credentials | 4825 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Admin share accessed via SMB (basic) | 5140/5145 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Impacket WMIexec execution via SMB admin share | 5145 | WMIexec
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Lateral movement by mounting a network share - net use (command) | 4688/4648 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Multiple failed attempt to network share | 5140/5145 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | New file share created on a host | 5142 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Psexec remote execution via SMB | 5145 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Remote service creation over SMB | 5145 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Remote shell execuction via SMB admin share | 5145 | 
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Shared printer creation | 5142 | PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
TA0008-Lateral Movement | T1021.003-DCOM | DCOM lateral movement (via MMC20) | 4104 | 
TA0008-Lateral Movement | T1021.003-DCOM | DCOMexec privilege abuse | 4674 | 
TA0008-Lateral Movement | T1021.003-DCOM | DCOMexec process abuse via MMC | 4688 | 
TA0008-Lateral Movement | T1021.004-Remote services: SSH | OpenSSH native server feature installation | 800/4103/4104 | SSH server
TA0008-Lateral Movement | T1021.004-Remote services: SSH | OpenSSH server for Windows activation/configuration detected | 800/4103/4104 | SSH server
TA0008-Lateral Movement | T1021.006-Windows Remote Management | WinRM listening service reconnaissance | 4656 | 
TA0008-Lateral Movement | T1550.002-Use Alternate Authentication Material: Pass the Hash | LSASS dump via process access | 10 | Mimikatz
TA0008-Lateral Movement | T1550.002-Use Alternate Authentication Material: Pass the Hash | Pass-the-hash login | 4624 | Mimikatz
TA0008-Lateral Movement | T1563.002-RDP hijacking | RDP session hijack via TSCON abuse command | 4688 | 
TA0009-Collection | T1125-Video capture | RDP shadow session started (registry) | 13 | 
TA0011-Command and control | T1572-Protocol tunneling | RDP tunneling configuration enabled for port forwarding | 4688 | 
TA0040-Impact | T1490-Inhibit System Recovery | VSS backup deletion (PowerShell) | 800/4103/4104 | 
TA0040-Impact | T1490-Inhibit System Recovery | VSS backup deletion (WMI) | 4688 | 
TA0040-Impact | T1490-Inhibit System Recovery | Windows native backup deletion | 4688 | 
TA0040-Impact | T1565-Data manipulation | DNS hosts file modified | 11 | 