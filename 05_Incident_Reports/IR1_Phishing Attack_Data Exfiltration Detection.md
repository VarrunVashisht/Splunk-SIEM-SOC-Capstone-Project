# 🛡️ Security Incident Report

---

## 1. Incident Overview

**Incident ID:** IR-2026-001
**Incident Title:** Phishing-Induced Data Exfiltration via DNS
**Date Detected:** 2026-04-01
**Reported By:** Splunk SIEM Alert
**Severity:** Critical
**Status:** Confirmed Incident

---

## 2. Executive Summary

A phishing campaign originating from `it-support@secure-login.com` targeted multiple users with a malicious macro-enabled attachment (`reset.docm`).

User interaction with the attachment resulted in endpoint compromise. Subsequently, infected systems initiated DNS queries to a suspicious domain (`data.exfil.evil.com`), transferring significant volumes of data externally.

Investigation confirms this as a **successful phishing attack leading to data exfiltration**, potentially involving sensitive financial data.

---

## 3. Scope of Impact

**Affected Users:**

* alice
* john.doe
* bob
* emma
* david

**Affected Systems:**

* Multiple internal endpoints (Windows-based)

**Data at Risk:**

* Financial documents (`finance.xlsx`)

---

## 4. Detection & Alert Details

**Detection Method:**
Splunk correlation rule detecting abnormal DNS traffic patterns

**Alert Name:**
High Volume DNS Data Transfer

**Trigger Conditions:**

* Repeated DNS queries to same domain
* High outbound data transfer (`bytes_out`)
* Multiple hosts communicating with suspicious domain

---

## 5. Indicators of Compromise (IOCs)

**Malicious Domain:**

* data.exfil.evil.com

**Phishing Sender:**

* [it-support@secure-login.com](mailto:it-support@secure-login.com)

**Malicious Attachment:**

* reset.docm

**Suspicious Activity:**

* High DNS data transfer
* Repeated outbound connections
* Large file access prior to exfiltration

---

## 6. Evidence & Log Analysis

### 📧 Email Logs

* Multiple phishing emails delivered with identical attachment
* Broad user targeting pattern from sender it-support@secure-login.com

Evidence Reference:
Sender: it-support@secure-login.com
Attachment: reset.docm

Evidence Snapshot:
<img width="1903" height="584" alt="image" src="https://github.com/user-attachments/assets/7424479b-515a-4456-9ec2-815bbefe2fb5" />

---

### 🌐 DNS Logs

* Continuous DNS requests to malicious domain
* Large `bytes_out` values indicating data exfiltration

Evidence Reference:
Domain: data.exfil.evil.com
High outbound DNS traffic observed

Evidence Snapshot:
<img width="1888" height="549" alt="image" src="https://github.com/user-attachments/assets/ad736537-60c1-415c-9bd9-9f918a3ba476" />

---

### 📁 File Access Logs

* Repeated access to `finance.xlsx`
* High data volume indicating potential staging before exfiltration

Evidence Reference:
File Accessed: finance.xlsx
User Activity: abnormal file access before DNS exfiltration

Evidence Snapshot:
<img width="1891" height="453" alt="image" src="https://github.com/user-attachments/assets/7a6688cd-a4a9-40b1-97aa-c3760517c366" />

---

## 7. Investigation Findings

1. Phishing emails were sent in bulk to multiple users.
2. Users opened macro-enabled attachment (`reset.docm`).
3. Malicious macro execution established outbound communication.
4. DNS-based exfiltration channel used (`data.exfil.evil.com`).
5. Sensitive file accessed and likely exfiltrated.
6. Multiple hosts exhibited similar behavior, indicating campaign-level compromise.

---

## 8. Attack Timeline

| Time        | Activity                          |
| ----------- | --------------------------------- |
| 08:25       | Phishing emails delivered         |
| 08:25–08:27 | Users receive and open attachment |
| 08:25+      | DNS exfiltration begins           |
| 08:41       | Sensitive file accessed           |
| 08:42+      | Continued data exfiltration       |


Evidence Snapshot:
<img width="1911" height="633" alt="image" src="https://github.com/user-attachments/assets/4e8876ff-7cb1-40d4-9998-8b9d14508174" />

---

## 9. MITRE ATT&CK Mapping

| Tactic            | Technique                    | ID        |
| ----------------- | ---------------------------- | --------- |
| Initial Access    | Phishing                     | T1566     |
| Execution         | User Execution (Macro)       | T1204     |
| Command & Control | DNS Tunneling                | T1071.004 |
| Exfiltration      | Exfiltration Over C2 Channel | T1041     |

---

## 10. Root Cause Analysis

The root cause of the incident was **successful phishing email delivery and user interaction with a malicious attachment**, combined with:

* Lack of macro restrictions
* Insufficient email filtering controls
* Absence of DNS anomaly detection thresholds

---

## 11. Impact Assessment

* Multiple endpoints compromised
* Sensitive financial data potentially exfiltrated
* Risk of regulatory and compliance violations
* Increased likelihood of further lateral movement

---

## 12. Response Actions Taken

* Blocked domain `data.exfil.evil.com`
* Isolated affected endpoints
* Disabled impacted user accounts
* Removed phishing emails from mailboxes
* Initiated full endpoint malware scans

---

## 13. Recommendations

**Short-Term:**

* Block all related domains and IPs
* Reset user credentials
* Perform forensic analysis on endpoints

**Long-Term:**

* Disable Office macros by default
* Implement email sandboxing
* Deploy DNS monitoring and anomaly detection
* Introduce Data Loss Prevention (DLP)
* Conduct regular phishing awareness training

---

## 14. Lessons Learned

* Users remain vulnerable to phishing attacks
* DNS exfiltration can bypass traditional security controls
* Early detection mechanisms must be improved

---

## 15. Appendices

### A. Splunk Queries Used

**Phishing Detection**

```spl
index=soc_project sourcetype= email.log
| stats count by sender, recipient, attachment
| where count > 5
```

**DNS Exfiltration Detection**

```spl
index=soc_project sourcetype= dns.log
| stats sum(bytes_out) as total_data by src_ip, query
| where total_data > 10000000
| sort - total_data
```

**Cross-Source Correlation**

```spl
index=soc_project
sourcetype=email.log OR sourcetype=dns.log OR sourcetype=file.log
| transaction user maxspan=30m
```

---

## 16. Analyst Notes

This incident demonstrates a complete attack chain from phishing to data exfiltration, highlighting the importance of cross-domain log correlation in detecting advanced threats.

---

## Author:
Varrun Vashisht
Cybersecurity Professional
