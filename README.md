# 🧬 Ransomware‑Kill‑Chain‑Detection

This repository documents a full end‑to‑end ransomware campaign reconstructed from real Sysmon telemetry and detection engineering. The project demonstrates how attackers move from initial execution to full ransomware impact — and how each stage is detected using Sigma rules mapped to attacker behavior.

This lab is designed to mirror how SOC analysts, detection engineers, and threat hunters identify, correlate, and stop ransomware activity inside a Windows enterprise environment.

---

## 🧬 Ransomware Kill Chain Coverage

| Attack Stage | Techniques Detected |
|-------------|--------------------|
| Initial Access | mshta, PowerShell, certutil |
| Payload Staging | netcat, 7‑Zip |
| Persistence | RunOnce Registry, Service Hijack |
| Command & Control | netcat |
| Data Exfiltration | curl |
| Impact | Ransomware file encryption |



# 🔎 Indicators of Compromise (IOCs)

- huntmeplz.com  
- nc.exe  
- rev.exe  
- exfil.zip  
- .huntme file extension  
- update.hta  
- PowerUp.ps1  

---

# 🧰 Tools Used

The following defensive and analysis tools were used to collect telemetry, build detections, and validate ransomware activity throughout the investigation:

- **Sysmon** – Provides detailed Windows process, network, file, and registry telemetry used as the primary data source for detection engineering  
- **Sigma** – Open detection rule format used to create platform‑agnostic threat detection logic  
- **PowerShell** – Used to inspect system activity, extract artifacts, and simulate attacker behavior for testing detections  
- **Windows Event Logging** – Underlying telemetry pipeline that records all activity used in the investigation  

These tools reflect what a real SOC would rely on to detect and investigate ransomware activity at scale.

---

# 🧰 Utilities Observed in the Attack

The attacker relied entirely on built‑in or commonly available Windows utilities to conduct the ransomware operation:

- **mshta.exe** – Used to execute a malicious HTML Application payload during initial compromise  
- **certutil.exe** – Abused to download malicious binaries from attacker infrastructure  
- **netcat (nc.exe)** – Used to establish a reverse shell and maintain command‑and‑control  
- **7‑Zip** – Used to compress and stage sensitive data prior to exfiltration  
- **curl.exe** – Used to exfiltrate stolen data to an external server  
- **sc.exe** – Used to modify Windows service configurations for persistence  
- **reg.exe** – Used to modify RunOnce registry keys to ensure execution after reboot  

These utilities demonstrate how ransomware operators can fully compromise a system using only trusted Windows binaries.

---
# 🧬 Detection Case Studies

Each case includes:
- A real attack scenario
- Detection engineering intent
- Case study file
- Sigma rule

---

# 🧪 Attack Chain Narrative

A phishing email delivers a malicious HTA file to a workstation. The user opens the attachment, launching **mshta.exe**, which executes attacker‑controlled script code. This script downloads additional tools using **certutil** and **PowerShell**, deploys a **netcat** backdoor, compresses sensitive documents with **7‑Zip**, establishes persistence via **RunOnce** and **service hijacking**, exfiltrates data with **curl**, and finally encrypts files as part of a ransomware attack.

This repository detects every stage of that kill chain using Windows telemetry.

---
## 1️⃣ Malicious MSHTA Execution

**Scenario**  
The attack begins when a user executes a malicious `.hta` file delivered through phishing. The file is opened using `mshta.exe`, a signed Microsoft binary designed to run HTML Applications. Attackers abuse this LOLBIN to execute embedded JavaScript or VBScript payloads, bypassing traditional executable restrictions.

**Detection Objective**  
Detect mshta being used to execute HTA files from user-writable directories, which strongly indicates malicious payload execution rather than legitimate enterprise usage.

📄 Case study  
[Malicious_MSHTA_Execution.txt](Case-Studies/Malicious_MSHTA_Execution.txt)  
🛡 Sigma rule  
[Suspicious Mshta HTA Execution.yaml](Sigma_Rules/Suspicious Mshta HTA Execution.yaml)

---

## 2️⃣ Malicious Certutil Download

**Scenario**  
Once code execution is achieved, the attacker uses `certutil.exe` to download a malicious executable from an external server. Certutil is a native Windows certificate utility often abused to fetch malware without triggering download controls.

**Detection Objective**  
Detect certutil downloading files from remote URLs using `-urlcache -split -f`, a highly suspicious pattern rarely used in legitimate operations.

📄 Case study  
[Malicious_Certutil_Download.txt](Case-Studies/Malicious_Certutil_Download.txt)  
🛡 Sigma rule  
[Suspicious Certutil File Download.yaml](Sigma_Rules/Suspicious Certutil File Download.yaml)

---

## 3️⃣ PowerShell In-Memory Enumeration

**Scenario**  
PowerShell is used to download and execute reconnaissance scripts directly in memory, allowing attackers to gather system, user, and security information without writing files to disk.

**Detection Objective**  
Detect PowerShell using `DownloadString`, `Invoke-AllChecks`, and WebClient patterns indicating fileless script execution.

📄 Case study  
[PowerShell_Enumeration.txt](Case-Studies/PowerShell_Enumeration.txt)  
🛡 Sigma rule  
[Powershell Enumeration.yaml](Sigma_Rules/Powershell Enumeration.yaml)

---

## 4️⃣ Netcat Reverse Shell

**Scenario**  
The attacker launches a reverse shell using `nc.exe`, connecting back to their server and spawning `cmd.exe`, giving full interactive control over the compromised machine.

**Detection Objective**  
Detect netcat executing with `-e cmd.exe`, which is a hallmark of reverse shell activity.

📄 Case study  
[Netcat_Reverse_Shell.txt](Case-Studies/Netcat_Reverse_Shell.txt)  
🛡 Sigma rule  
[Netcat Reverse Shell Execution.yaml](Sigma_Rules/Netcat Reverse Shell Execution.yaml)

---

## 5️⃣ Data Staging with 7-Zip

**Scenario**  
Sensitive user files are collected and compressed into a password-protected ZIP archive using 7-Zip. This prepares the data for exfiltration and supports double-extortion tactics.

**Detection Objective**  
Detect 7-Zip creating encrypted archives inside user directories.

📄 Case study  
[Archive_Staging.txt](Case-Studies/Archive_Staging.txt)  
🛡 Sigma rule  
[Suspicious Archive.yaml](Sigma_Rules/Suspicious Archive.yaml)

---

## 6️⃣ RunOnce Registry Persistence

**Scenario**  
The attacker configures a malicious executable to run at the next system boot using the RunOnce registry key, ensuring persistence.

**Detection Objective**  
Detect `reg.exe` modifying `CurrentVersion\RunOnce`.

📄 Case study  
[RunOnce_Persistence.txt](Case-Studies/RunOnce_Persistence.txt)  
🛡 Sigma rule  
[RunOnce Persistence.yaml](Sigma_Rules/RunOnce Persistence.yaml)

---

## 7️⃣ Service Binary Hijacking

**Scenario**  
A legitimate Windows service is modified so it executes a malicious binary, granting persistent and high-privilege access.

**Detection Objective**  
Detect `sc.exe` modifying service `binPath` values.

📄 Case study  
[Service_Hijack.txt](Case-Studies/Service_Hijack.txt)  
🛡 Sigma rule  
[Service Binary Modification.yaml](Sigma_Rules/Service Binary Modification.yaml)

---

## 8️⃣ Curl Data Exfiltration

**Scenario**  
The staged ZIP archive is uploaded to an attacker-controlled server using `curl.exe`.

**Detection Objective**  
Detect HTTP POSTs using curl with ZIP files.

📄 Case study  
[Curl_Exfiltration.txt](Case-Studies/Curl_Exfiltration.txt)  
🛡 Sigma rule  
[Curl Data Exfiltration.yaml](Sigma_Rules/Curl Data Exfiltration.yaml)

---

## 9️⃣ Ransomware File Encryption

**Scenario**  
The ransomware encrypts files and appends a custom extension, marking the impact phase of the attack.

**Detection Objective**  
Detect mass file modifications with ransomware-style extensions using Sysmon Event ID 11.

📄 Case study  
[Ransomware_Encryption.txt](Case-Studies/Ransomware_Encryption.txt)  
🛡 Sigma rule  
[Ransomware File Encryption.yaml](Sigma_Rules/Ransomware File Encryption.yaml)

---
# 🧭 MITRE ATT&CK Coverage

- T1218.005 – Mshta  
- T1105 – Ingress Tool Transfer  
- T1059 – Command & Scripting Interpreter  
- T1560 – Archive Collected Data  
- T1547.001 – Registry Run Keys  
- T1543 – Service Hijack  
- T1041 – Exfiltration Over C2 Channel  
- T1486 – Data Encrypted for Impact  

---

# 🧠 Key Findings

The ransomware operator relied almost exclusively on Living‑Off‑the‑Land binaries (LOLBins) to execute the attack. This allowed them to blend into legitimate system activity while carrying out every phase of the kill chain, from initial execution to full encryption.

Each stage of the intrusion generated detectable Windows telemetry that can be captured and analyzed using Sysmon and SIEM‑based detection rules.

---

# 🛡 Recommendations Summary

- Restrict mshta and certutil from executing in user‑writable directories  
- Deploy behavior‑based detection for LOLBIN abuse  
- Monitor for reverse shell activity and outbound curl uploads  
- Alert on registry and service modifications  
- Enforce endpoint execution and persistence controls  

---

# 📘 Lessons Learned

- Ransomware does not require custom malware to succeed  
- Native Windows tools provide enough power to fully compromise an enterprise  
- Detection engineering must focus on **behavior and telemetry**, not file hashes  

---

# 🧾 Final Assessment

This project demonstrates a complete ransomware intrusion from initial access through encryption and data exfiltration. By reconstructing the full attack chain and mapping every action to Sysmon telemetry, this repository shows how modern ransomware campaigns can be detected even when attackers rely solely on trusted Windows binaries.

The Sigma rules developed here provide layered coverage across execution, persistence, command‑and‑control, exfiltration, and impact, enabling SOC teams to detect ransomware early, correlate activity across stages, and disrupt attacks before widespread damage occurs.

This lab reflects how real enterprise security teams design detection strategies against modern ransomware groups.

---

# 🔐 Case Closure

The ransomware campaign was fully reconstructed and all attacker actions were detected using telemetry‑driven detection engineering. The case demonstrates how a real SOC can identify, investigate, and contain ransomware before business‑critical systems are lost.
