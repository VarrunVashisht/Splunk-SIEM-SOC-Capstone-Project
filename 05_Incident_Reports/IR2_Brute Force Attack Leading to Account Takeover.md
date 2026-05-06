# 🛡️ Security Incident Report

---

## 1. Incident Overview

**Incident ID:** IR-2026-002
**Incident Title:** Brute Force Attack Leading to Account Takeover
**Date Detected:** 2026-04-01
**Reported By:** Splunk SIEM Alert
**Severity:** High
**Status:** Confirmed Incident

---

## 2. Executive Summary

A brute force attack was identified targeting multiple user accounts through repeated login attempts from various internal IP addresses.

The attacker successfully gained access to one or more accounts after multiple failed login attempts, indicating credential compromise.

Post-authentication activity suggests potential unauthorized access and account takeover.

---

## 3. Scope of Impact

**Affected Users:**

* alice
* john.doe
* david
* bob

**Affected Systems:**

* Authentication systems (login infrastructure)

**Access Impact:**

* Unauthorized account access
* Potential misuse of valid credentials

---

## 4. Detection & Alert Details

**Detection Method:**
Splunk correlation detecting abnormal login behavior

**Alert Name:**
Multiple Failed Logins Followed by Successful Authentication

**Trigger Conditions:**

* High volume of login attempts
* Multiple source IPs targeting same user
* Successful login following repeated attempts

---

## 5. Indicators of Compromise (IOCs)

**Suspicious Behavior:**

* Rapid login attempts within short time window
* Multiple IP addresses used for same account
* Successful login after repeated failures

**Example Source IPs:**

* 192.168.1.25
* 192.168.1.15
* 192.168.1.30

---

## 6. Evidence & Log Analysis

### 🔐 Authentication Logs

**Objective:** Detect abnormal login patterns indicating brute force attempts.

**Splunk Query:**

```spl
index=soc_project sourcetype=auth.log
| stats count by user, src_ip
| where count > 7
| sort - count
```

**Expected Evidence:**

* Repeated login attempts for same user
* Multiple IPs attempting access

Evidence Snapshot:
<img width="1899" height="502" alt="image" src="https://github.com/user-attachments/assets/08940f8e-1344-48d9-b7f6-8b5f4f2b6569" />


---

### 🔎 Successful Login After Failures

**Objective:** Identify accounts successfully accessed after multiple attempts.

**Splunk Query:**

```spl
index=soc_project sourcetype=auth.log
| stats count(eval(status="failed")) as failed_attempts 
        count(eval(status="success")) as success_attempts 
        by user
| where failed_attempts > 5 AND success_attempts > 0
```

**Expected Evidence:**

* Accounts showing both failed and successful logins
* Indicates credential guessing succeeded


Evidence Snapshot:
<img width="1900" height="457" alt="image" src="https://github.com/user-attachments/assets/1eab3142-9ea6-42e4-9370-a2f4fc708b7e" />

---

### 🌍 Multi-IP Login Behavior

**Objective:** Detect potential credential stuffing or distributed brute force.

**Splunk Query:**

```spl
index=soc_project sourcetype=auth.log
| stats dc(src_ip) as unique_ips by user
| where unique_ips > 3
```

**Expected Evidence:**

* Same user accessed from multiple IPs
* Unusual login distribution pattern


Evidence Snapshot:
<img width="1899" height="588" alt="image" src="https://github.com/user-attachments/assets/7935ad1c-0764-4eff-8dcd-acf0107364b9" />

---

## 7. Investigation Findings

1. Multiple user accounts experienced repeated login attempts.
2. Attempts originated from different source IP addresses.
3. Attack pattern indicates brute force or credential stuffing.
4. At least one account showed successful login after multiple failures.
5. Successful authentication suggests attacker guessed or reused valid credentials.
6. No immediate lockout mechanism prevented access.

---

## 8. Attack Timeline

| Time        | Activity                                   |
| ----------- | ------------------------------------------ |
| 08:00       | Login attempts begin                       |
| 08:00–08:03 | Multiple login attempts across users       |
| 08:01+      | Repeated access attempts from multiple IPs |
| 08:02+      | Successful login observed                  |
| 08:03+      | Continued authenticated activity           |

---

## 9. MITRE ATT&CK Mapping

| Tactic            | Technique                | ID    |
| ----------------- | ------------------------ | ----- |
| Credential Access | Brute Force              | T1110 |
| Initial Access    | Valid Accounts           | T1078 |
| Persistence       | Account Access Retention | T1078 |

---

## 10. Root Cause Analysis

The root cause of the incident was:

* Weak password policies
* Lack of account lockout thresholds
* Absence of multi-factor authentication (MFA)
* No detection of abnormal login patterns in real time

---

## 11. Impact Assessment

* Unauthorized access to user accounts
* Risk of lateral movement
* Potential exposure of sensitive data
* Increased attack surface for further compromise

---

## 12. Response Actions Taken

* Forced password reset for affected users
* Temporarily locked compromised accounts
* Investigated login activity for suspicious behavior
* Blocked suspicious IP addresses

---

## 13. Recommendations

**Short-Term:**

* Enforce password resets across impacted users
* Enable account lockout after failed attempts
* Block suspicious IP ranges

**Long-Term:**

* Implement Multi-Factor Authentication (MFA)
* Deploy behavior-based login anomaly detection
* Enforce strong password policies
* Monitor login patterns continuously

---

## 14. Lessons Learned

* Brute force attacks can succeed without proper controls
* Credential-based attacks remain highly effective
* Detection must focus on behavior, not just signatures

---

## 15. Analyst Notes

This incident highlights a classic brute force attack evolving into a successful account takeover. 
It demonstrates the importance of correlating failed and successful authentication events to detect credential compromise effectively.

---

## Author:
Varrun Vashisht
Cybersecurity Professional
