# 🌐 Web Logs Documentation

## 🎯 Purpose

Web logs simulate user browsing behavior and act as the primary source for detecting phishing interactions, malicious downloads, and suspicious web activity.

---

## 📊 Log Format

```log
timestamp=<time> index=web user=<username> src_ip=<ip> url=<url> action=<allowed/blocked> method=<GET/POST> bytes_out=<size>
```

---

## 🔑 Fields Explanation

| Field     | Description            |
| --------- | ---------------------- |
| timestamp | Time of request        |
| user      | User performing action |
| src_ip    | Source IP address      |
| url       | Requested URL          |
| action    | Allowed or blocked     |
| method    | HTTP method            |
| bytes_out | Data transferred       |

---

## 🧪 Data Types Included

### 🟢 Baseline (Normal Behavior)

* Google, LinkedIn, internal domains
* Regular browsing patterns

### 🔴 Attack Simulation

* Phishing domain access
* Malicious file downloads
* Form submissions (credential theft)

### ⚪ Noise

* Random browsing activity
* Benign high-traffic domains

---

## 🔍 Use Cases in Project

* Phishing detection
* Rare domain identification
* User click analysis
* Data exfil via HTTP

---

## ⚠️ Analytical Value

Web logs help answer:

* Who accessed malicious domains?
* Which users interacted with phishing links?
* Was the activity normal or anomalous?

---

## 🔗 Correlation Usage

* Correlates with:

  * Email logs → phishing origin
  * Windows logs → execution after download
  * DNS logs → callback after infection

---

## 🚀 Outcome

Web logs act as the **entry point of the attack chain**, enabling identification of initial compromise.
