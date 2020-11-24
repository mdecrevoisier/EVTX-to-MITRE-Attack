# EVTX to MITRE Att@ck

## Project purpose
**EVTX to MITRE Att@ck** is a *Security Information Management System* orientated project. It provides Windows IOCs indicators classified per Tactic and Technique in order to address different security scenarios with your SIEM:
* Measure your security coverage 
* Enhance your detection capacities
* Identify security gaps or uncovered threats
* Design new use cases

## How to use the IOCs
IOCs are provided in the EVTX format, the standard format established by Microsoft starting Windows Server 2008 and Windows Vista for event logs. Depending on the SIEM solution you utilize, you may need to make your agent (NXLog, Winlogbeat, Splunk UF, ArcSight, WinCollect, Snare, ...) pointing to the EVTX files and send the content to your SIEM in the adequate format.

## Microsoft log sources used:
* Windows Server 2012 R2 or higher
* Windows 10 or higher
* Active Directory Domain Services (ADDS)
* Active Directory Certification Services (ADCS / PKI) with online responder (OCSP)
* SQL Server 20014
* SYSMON v11 -- *in progress*
* Windows Defender -- *in progress*
* Exchange 2013 -- *planned*
* SharePoint -- *planned*
* Internet Information Services (IIS web server) -- *planned*

## Related and/or connected projects:
If you are interesting in external projects or articles involving topics like SIGMA, WHIDS, EVTX, ... I would like to mention the following ones:
* **EVTX-ATTACK** from @ sbousseaden: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
* **GENE** (*Go Evtx sigNature Engine*) from @qjerome: https://github.com/0xrawsec/gene
* **Mordor dataset**: https://mordordatasets.com/notebooks/small/windows/windows.html
* **Atomic RedTeam**: https://github.com/redcanaryco/atomic-red-team
* Export EVTX to Elastic with Winlogbeat: https://medium.com/@duzvik/import-evtx-collections-in-to-elastic-989b7f49b4b8 

## IOCs content

Att@ck Tactic	| Att@ck  Technique	| Description | 	Event IDs   |
|:-------------------------|:------------------|:-------------------------|:------------------|
TA0002-Execution | T1053.005-Scheduled Task | Command execution for schedule task creation detected | 4688
TA0002-Execution | T1053.005-Scheduled Task | Schedule task created and deleted in a short period of time | 4698-4699
TA0002-Execution | T1053.005-Scheduled Task | Schedule task created by a user account | 4698
TA0002-Execution | T1059.003-Windows Command Shell  | SQL Server payload injectection for reverse shell (MSF) | 4688
TA0002-Execution | T1569.002-Service execution | Host performing remote usage of PSEXEC over SMB | 5145
TA0003-Persistence | T1098.xxx-Account Manipulation  | Member added and removed from a group by a user account in a short period of time  | 4728/29,4756/57,4732/33
TA0003-Persistence | T1098.xxx-Account Manipulation  | Member added to a built-in or custom security domain group | 4728/29,4756/57
TA0003-Persistence | T1098.xxx-Account Manipulation  | Member added to a local group by a user account | 4732/4733
TA0003-Persistence | T1098.xxx-Account Manipulation  | User performing massive group membership changes on multiple differents groups | 4728/29,4756/57
TA0003-Persistence | T1098.xxx-Account manipulation | Computer account set with new SPN | 4742
TA0003-Persistence | T1098.xxx-Account Manipulation | Member added to a group by the same account | 4728/29,4756/57,4732/33
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: new member added to a database role | 33205
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: new member added to server role | 33205
TA0003-Persistence | T1098.xxx-Account manipulation | User account set with new SPN | 4738
TA0003-Persistence | T1136.001-Create account-Local account | Guest account (and support_388945a0) account activated | 4722
TA0003-Persistence | T1136.001-Create account-Local account | Local user account created on a single host | 4720
TA0003-Persistence | T1136.001-Create account-Local account | SQL Server: disabled SA account enabled | 33205
TA0003-Persistence | T1136.001-Create account-Local account | SQL Server: new local user created | 33205
TA0003-Persistence | T1136.002-Create account-Domain account | Account renamed to "admin" (or likely) | 4738
TA0003-Persistence | T1136.002-Create account-Domain account | Computer account created and deleted in a short period of time | 4741/4743
TA0003-Persistence | T1136.002-Create account-Domain account | New administrator account created (contains "admin" or likely) | 4720
TA0003-Persistence | T1136.002-Create account-Domain account | User account created and deleted in a short period of time | 4720/4726
TA0003-Persistence | T1136.002-Create account-Domain account | User account created to fake a computer account (ends with "$") | 4720
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server xp_cmdshell procedure activated | 18456
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Attempt to create a service detected (sc) | 4688
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Mimikatz service driver installation detected (mimidrv.sys) | 7045
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | New service installation by a user account detected | 7045
TA0004-Privilege Escalation | T1134.xxx-Access Token Manipulation | New access right granted to an account by a standard user | 4717
TA0004-Privilege Escalation | T1134.xxx-Access Token Manipulation | New user right granted to an account by a standard user | 4704
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Event log file(s) cleared | 104 / 1102
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Tentative of clearing event log file(s) detected | 4688
TA0005-Defense Evasion | T1070.001-Indicator Removal on Host | Tentative of clearing event log file(s) detected | 600 / 800
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | Domain policy changed on one or multiple hosts | 4739
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | Membership of a special group updated | 4908
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit object deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit object disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit specifications deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit specifications disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Database audit specifications deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Database audit specifications disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | System audit policy disabled on one or multiple hosts | 4719
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | Tentative of disabling audit policy detected | 4688
TA0005-Defense Evasion | T1078.002-Valid accounts-Domain accounts | Login from a user member of a "special group" detected (special logon) | 4964
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Network share permissions changed | 5143
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | OCSP security settings changed | 5124 (OCSP)
TA0006-Credential Access | T1003.003-OS Credential-Dumping NTDS | Command execution related to a suspicious DSRM activity detected | 4688
TA0006-Credential Access | T1003.003-OS Credential-Dumping NTDS | DSRM (Directory Service Restore Mode) password reset on one or many DCs | 4794
TA0006-Credential Access | T1003.006-DCSync | Sensitive GUID related to "Replicate directory changes" detected  | 4662
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source because of authentication restrictions (Kerberos/mixed) | 33205
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source with a disabled account | 33205
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source with different non existing accounts | 33205
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from multiple sources to a single target with a single user (wrong password) | 33205
TA0006-Credential Access | T1552.004-Unsecured Credentials-Private Keys | Unknown application accessing certificate private key detected | 70 (CAPI2)
TA0006-Credential Access | T1558.001-Golden Ticket  | Kerberos TGS ticket request related to a potential Kerberos ticket | 4769
TA0006-Credential Access | T1558.001-Golden Ticket  | Success login using a potential Golden ticket | 4624
TA0006-Credential Access | T1558.003-Kerberoasting  | KerberOAST ticket (TGS) request detected (low encryption) | 4769
TA0007-Discovery | T1087.002-Domain Account discovery | Command execution related to Kerberos SPN enumeration activity detected | 4688
TA0007-Discovery | T1087.002-Domain Account discovery | Honeypot object (container, computer, group, user) accessed | 4662/4624
TA0007-Discovery | T1087.002-Domain Account discovery | Single source performing host enumeration over Kerberos ticket (TGS) detected | 4769
TA0007-Discovery | T1135.xxx-Network Share Discovery | Host performing advanced named pipes enumeration on different hosts detected | 5145
TA0008-Lateral Movement | T1021.001-Remote Desktop Protocol | Denied RDP authentication with valid credentials | 4825
TA0008-Lateral Movement | T1021.002 -SMB Windows Admin Shares | Host performing access to ADMIN$ share | 5140/5145
TA0008-Lateral Movement | T1021.002 -SMB Windows Admin Shares | New file share created on a host | 5142
