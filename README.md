# 🚀 Splunk (SIEM) SOC Capstone Project

## 🎯 Objective

This project simulates a real-world Security Operations Center (SOC) environment using Splunk, SIEM tool.

This project covers **10 real-world cyber attack scenarios**, including:

- 🎣 Phishing Attacks  
- 💣 Ransomware Incidents  
- 🕵️ Insider Threats  
- 🎯 Advanced Persistent Threats (APT)  
- 🔓 Credential Compromise  
- 🌐 Command & Control Activity  
- 📤 Data Exfiltration  
- 🧬 Malware Execution  
- ⚠️ Privilege Escalation  
- 🚨 Suspicious Lateral Movement  

Each attack scenario further includes **10 detailed subcases** that simulate realistic investigation and detection workflows.

---

## 🧠 What Makes This Project Different

This is not a basic Splunk project.  
It replicates how security teams actually work:

- 🔍 Investigating alerts using SPL queries  
- 🧩 Correlating logs across multiple systems  
- 🧠 Building hypotheses and validating them  
- 📊 Reconstructing full attack timelines  
- 🛡️ Making incident response decisions  

👉 The focus is on thinking like a SOC analyst, not just writing queries.

---

## 🧠 Skills Demonstrated

* SIEM (Splunk) investigation
* Threat detection & analysis
* Log correlation across multiple sources
* Incident response workflow
* MITRE ATT&CK mapping

---

## 🧩 Project Structure

* Data ingestion from multiple log sources
* Detection engineering using SPL
* Step-by-step investigations
* Alerts configuration
* Incident reporting
* Dashboard creation

---

## 📊 Data Sources & Telemetry

This project simulates an enterprise environment using multiple log sources:

- 🖥️ Windows Logs – Process creation, registry changes, services  
- 🌐 Web Logs – User browsing and URL activity  
- 🌍 DNS Logs – Command & Control and data exfiltration  
- 📧 Email Logs – Phishing campaigns and attachments  
- 🔐 Authentication Logs – Login behavior and anomalies  
- ☁️ Cloud Logs – Data uploads and API activity  
- 📂 File Logs – File access and data movement  

---

## 🔥 Key Highlights

* More than 80 real-world attack scenarios covered
* 1000+ synthetic + realistic logs per case
* Multi-source correlation (Windows, DNS, Web, Email)
* Analyst-style investigation workflow

---

## 🛠️ Tools Used

* Splunk SIEM
* Python (synthetic log generation)
* GitHub (documentation)

---

## 🚀 Use Cases Covered

1. Phishing Attack
2. Web Application Attack
3. Insider Threat
4. Brute Force Attack
5. Ransomware
6. Command & Control
7. Privilege Escalation
8. Cloud Attack
9. Living-off-the-Land
10. Advanced Persistent Threat

---


## 🚀 Use Cases Covered

1. Phishing Attack
   * Subcase 1: Phishing Domain Identification
   * Subcase 2: Email Campaign Analysis
   * Subcase 3: User Click Behavior
   * Subcase 4: Malicious Attachment Execution
   * Subcase 5: Suspicious Process Creation
   * Subcase 6: PowerShell Abuse Detection
   * Subcase 7: Persistence Mechanism Identification
   * Subcase 8: DNS Callback Analysis
   * Subcase 9: Data Exfiltration Detection
   * Subcase 10: Full Attack Timeline Reconstruction

2. Web Application Attack
   * Subcase 1: Suspicious URL Pattern Detection
   * Subcase 2: SQL Injection Identification
   * Subcase 3: Cross-Site Scripting (XSS) Detection
   * Subcase 4: Directory Traversal Attempts
   * Subcase 5: Web Shell Upload Detection
   * Subcase 6: Unauthorized Access Attempts
   * Subcase 7: Privilege Abuse via Web App
   * Subcase 8: Data Extraction via Web Requests
   * Subcase 9: Anomalous Traffic Patterns
   * Subcase 10: Attack Timeline Reconstruction

3. Insider Threat
   * Subcase 1: Unusual Login Behavior
   * Subcase 2: Access to Sensitive Files
   * Subcase 3: Privilege Misuse Detection
   * Subcase 4: Data Download Anomalies
   * Subcase 5: USB Device Usage
   * Subcase 6: Off-Hours Activity Detection
   * Subcase 7: Suspicious Process Execution
   * Subcase 8: Data Exfiltration via Email
   * Subcase 9: Account Abuse Patterns
   * Subcase 10: Insider Activity Timeline

4. Brute Force Attack
   * Subcase 1: Failed Login Spike Detection
   * Subcase 2: Source IP Analysis
   * Subcase 3: Username Enumeration
   * Subcase 4: Successful Login After Failures
   * Subcase 5: Account Lockout Events
   * Subcase 6: Geographic Anomalies
   * Subcase 7: Credential Stuffing Patterns
   * Subcase 8: Multi-Account Targeting
   * Subcase 9: Persistence After Access
   * Subcase 10: Attack Timeline Reconstruction

5. Ransomware
   * Subcase 1: Suspicious File Execution
   * Subcase 2: Mass File Modification Detection
   * Subcase 3: Encryption Activity Patterns
   * Subcase 4: Shadow Copy Deletion
   * Subcase 5: Registry Changes for Persistence
   * Subcase 6: Network Spread Detection
   * Subcase 7: Command-Line Indicators
   * Subcase 8: C2 Communication Detection
   * Subcase 9: Data Exfiltration Indicators
   * Subcase 10: Full Incident Timeline

6. Command & Control
   * Subcase 1: Suspicious DNS Queries
   * Subcase 2: Beaconing Behavior Detection
   * Subcase 3: Known Malicious IP Communication
   * Subcase 4: Encrypted Traffic Anomalies
   * Subcase 5: Domain Generation Algorithm (DGA) Detection
   * Subcase 6: Unusual Port Usage
   * Subcase 7: Persistent Outbound Connections
   * Subcase 8: Data Transfer Patterns
   * Subcase 9: Endpoint Correlation
   * Subcase 10: C2 Timeline Reconstruction

7. Privilege Escalation
   * Subcase 1: Unauthorized Privilege Changes
   * Subcase 2: Suspicious Admin Logins
   * Subcase 3: Token Manipulation Detection
   * Subcase 4: Exploit Execution Indicators
   * Subcase 5: Service Creation Abuse
   * Subcase 6: Scheduled Task Abuse
   * Subcase 7: Credential Dumping Detection
   * Subcase 8: Lateral Movement Indicators
   * Subcase 9: Elevated Process Execution
   * Subcase 10: Escalation Timeline

8. Cloud Attack
   * Subcase 1: Suspicious API Calls
   * Subcase 2: Unauthorized Access Attempts
   * Subcase 3: IAM Role Abuse
   * Subcase 4: Data Exposure Events
   * Subcase 5: Unusual Resource Creation
   * Subcase 6: Geographic Access Anomalies
   * Subcase 7: Credential Leakage Detection
   * Subcase 8: Storage Access Patterns
   * Subcase 9: Data Exfiltration from Cloud
   * Subcase 10: Cloud Attack Timeline

9. Living-off-the-Land
   * Subcase 1: Legitimate Tool Abuse Detection
   * Subcase 2: PowerShell Misuse
   * Subcase 3: WMI Execution Analysis
   * Subcase 4: Scheduled Task Abuse
   * Subcase 5: Registry Manipulation
   * Subcase 6: Fileless Malware Indicators
   * Subcase 7: Command-Line Anomalies
   * Subcase 8: Lateral Movement via Native Tools
   * Subcase 9: Persistence via Built-in Utilities
   * Subcase 10: Activity Timeline Reconstruction

10. Advanced Persistent Threat
    * Subcase 1: Initial Access Detection
    * Subcase 2: Reconnaissance Activity
    * Subcase 3: Credential Harvesting
    * Subcase 4: Lateral Movement Detection
    * Subcase 5: Persistence Mechanisms
    * Subcase 6: Command & Control Communication
    * Subcase 7: Data Collection Activities
    * Subcase 8: Data Exfiltration Detection
    * Subcase 9: Long-Term Presence Indicators
    * Subcase 10: Full APT Timeline Reconstruction

---

## 🎯 Why This Project Matters

This project demonstrates real, job-ready cybersecurity skills:

* Thinking like a SOC analyst
* Investigating real-world attack scenarios
* Correlating data across systems
* Writing professional security reports

👉 It bridges the gap between learning Splunk and working in a real SOC environment.

## 📌 Outcome

By completing this project, I have developed:

- Hands-on SIEM investigation experience  
- Detection engineering capability  
- Strong understanding of attack behavior  
- Practical incident response skills  


## 👨‍💻 Author

**Varrun Vashisht**  

Cybersecurity | SOC Analyst | Threat Hunting | Detection Engineering


