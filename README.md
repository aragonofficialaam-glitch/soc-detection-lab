\# SOC Detection \& Response Lab



A hands-on Security Operations Center project simulating an Active Directory environment, executing real-world attack techniques against it, and building, validating, and documenting the detection rules that catch them.



This lab was built end-to-end — from infrastructure to attack simulation to detection engineering to incident investigation — to demonstrate practical, job-ready SOC Analyst skills, not just theoretical knowledge.



\## Project Overview



| | |

|---|---|

| \*\*Environment\*\* | `soclab.local` — Active Directory domain, isolated VirtualBox network (10.10.10.0/24) |

| \*\*SIEM\*\* | Splunk Enterprise 10.6 |

| \*\*Telemetry\*\* | Sysmon (SwiftOnSecurity config) + Windows Event Logs |

| \*\*Attack Techniques Executed\*\* | 10, mapped to MITRE ATT\&CK |

| \*\*Detection Rules Built\*\* | 10 (Sigma + SPL), all validated against real attack traffic |

| \*\*Investigation Reports\*\* | 3, written from a defensive analyst's perspective |



\## Architecture



!\[Lab Topology](docs/topology.jpg)



Four virtual machines on an isolated network:

\- \*\*Kali Linux\*\* — attacker host (Kerbrute, Impacket, Atomic Red Team)

\- \*\*WServer (DC01)\*\* — Windows Server 2022, Active Directory Domain Controller

\- \*\*W11\*\* — Windows 11, domain-joined endpoint (victim)

\- \*\*Ubuntu\*\* — Splunk Enterprise (SIEM, indexer, detection rules)



\## What's in This Repo



soc-detection-lab/

├── detections/

│ ├── sigma/ # 10 Sigma detection rules (YAML)

│ └── spl/ # Equivalent Splunk SPL queries

├── investigations/ # 3 full incident investigation reports (.docx)

├── scripts/

│ ├── ioc\_enrichment.py # IOC reputation lookup (AbuseIPDB + VirusTotal)

│ └── risk\_based\_alerting.py # Vulnerability-aware alert severity scoring

└── docs/

└── topology.jpg # Network architecture diagram



\## Attack Techniques \& Detections



\### Identity-Based Attacks Against Active Directory

Simulating an adversary who compromises one standard domain account and escalates to full domain compromise.



| Technique | MITRE ID | Detection Rule | Severity |

|---|---|---|---|

| Kerberos User Enumeration | T1589.002 | `kerberos-user-enum.yml` | Medium |

| Kerberos Password Brute Force | T1110.003 | `kerberos-brute-force.yml` | High |

| Domain Admin Privilege Escalation | T1136.001 / T1098.007 | `new-domain-admin.yml` | Critical |

| Remote Command Execution via Task Scheduler | T1053.005 | `task-scheduler-system-exec.yml` | High |

| DCSync Credential Extraction | T1003.006 | `dcsync-replication-abuse.yml` | Critical |



\*\*\[Full write-up →](investigations/Investigation1-Identity-Attacks-AD.docx)\*\*



\### Endpoint Attacks via Atomic Red Team

Simulating an already-compromised endpoint, using the Atomic Red Team framework to generate realistic, repeatable technique telemetry.



| Technique | MITRE ID | Detection Rule | Severity |

|---|---|---|---|

| Obfuscated PowerShell Execution | T1059.001 | `powershell-encoded-command.yml` | Medium |

| LSASS Memory Dump via comsvcs.dll | T1003.001 | `lsass-dump-comsvcs.yml` | Critical |

| Local Scheduled Task Creation | T1053.005 | `scheduled-task-local-creation.yml` | Medium |

| Registry Run Key Persistence | T1547.001 | `registry-run-key-persistence.yml` | Medium |

| RWX Process Injection (MockingJay-style) | T1055 | `process-injection-mockingjay-toolchain.yml` | High |



\*\*Notable finding:\*\* the Process Injection technique successfully evaded Sysmon's default process-injection telemetry (EventID 8/10) entirely. The deployed detection rule instead targets execution of the known injector binaries — a documented compensating control for a confirmed visibility gap.



\*\*\[Full write-up →](investigations/Investigation2-Endpoint-Attacks-AtomicRedTeam.docx)\*\*



\### External Dataset Investigation — Splunk BOTS v1

Unlike the two investigations above, this one analyzes telemetry I did not generate myself — Splunk's publicly released "Boss of the SOC v1" dataset — simulating the more common real-world SOC scenario of investigating an environment someone else instrumented.



Reconstructed a two-phase website compromise against a fictional target (`imreallynotbatman.com`): automated vulnerability scanning (Acunetix), followed by a scripted Python brute-force attack that recovered valid Joomla administrator credentials.



\*\*\[Full write-up →](investigations/Investigation3-BOTSv1-WebsiteCompromise.docx)\*\*



\## Automation



\*\*`ioc\_enrichment.py`\*\* — takes a list of IP addresses and enriches each one with reputation data from AbuseIPDB and VirusTotal, exporting results to CSV. Simulates the first triage step a SOC analyst performs on any new indicator.



\*\*`risk\_based\_alerting.py`\*\* — cross-references SOC alert severity against known vulnerability findings from a separate vulnerability management project (\[`vuln-mgmt-pipeline`](https://github.com/aragonofficialaam-glitch/vuln-mgmt-pipeline)), automatically escalating alert priority when the affected host has an associated KEV-listed critical vulnerability. Demonstrates risk-based alerting logic end-to-end, including an honestly-documented design decision for bridging two projects that don't share a common asset inventory.



\## How to Reproduce



Full step-by-step environment build instructions, attack commands, and detection queries are documented within each investigation report. At a high level:



1\. Build the `soclab.local` Active Directory lab (Domain Controller + domain-joined workstation)

2\. Install Sysmon (SwiftOnSecurity config) and the Splunk Universal Forwarder on both hosts

3\. Execute the identity-based attack chain from Kali using Kerbrute and Impacket

4\. Execute endpoint techniques from Atomic Red Team on the W11 host

5\. Deploy the 10 Sigma/SPL detection rules as scheduled Splunk alerts

6\. Run `scripts/ioc\_enrichment.py` and `scripts/risk\_based\_alerting.py` for automated triage and risk scoring



\## MITRE ATT\&CK Coverage



This project covers 10 techniques across 5 tactics: Discovery, Credential Access, Privilege Escalation, Persistence, Execution, and Defense Evasion. Full coverage mapping available via the MITRE ATT\&CK Navigator layer in this repo.



\## Author



\*\*Andres Aragon Molina\*\* — Computer Engineering student, Costa Rica. Pursuing a career as a SOC Analyst, with a long-term focus on Cloud Security.



\[GitHub](https://github.com/aragonofficialaam-glitch) · \[LinkedIn](https://www.linkedin.com/in/andres-aragon-molina-920729317/)

