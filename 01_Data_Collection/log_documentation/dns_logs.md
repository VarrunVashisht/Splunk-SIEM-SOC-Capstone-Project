# 🌍 DNS Logs Documentation

## 🎯 Purpose

DNS logs simulate domain resolution activity and are crucial for detecting command & control communication and data exfiltration.

---

## 📊 Log Format

```log
timestamp=<time> index=dns src_ip=<ip> query=<domain> bytes_out=<size>
```

---

## 🔑 Fields Explanation

| Field     | Description      |
| --------- | ---------------- |
| src_ip    | Source system    |
| query     | Domain requested |
| bytes_out | Data transferred |

---

## 🧪 Data Types

### 🟢 Baseline

* Common domains (google.com, microsoft.com)

### 🔴 Attack Simulation

* C2 domains
* Data exfil domains

### ⚪ Noise

* Random DNS queries

---

## 🔍 Use Cases

* Detect DNS tunneling
* Identify exfiltration
* Spot malicious domains

---

## ⚠️ Analytical Value

DNS logs help answer:

* Is the system communicating externally?
* Are domains suspicious or rare?
* Is there data leakage?

---

## 🔗 Correlation Usage

* Windows logs → process initiating query
* Web logs → domain origin
* Email logs → phishing link

---

## 🚀 Outcome

DNS logs expose **hidden attacker communication channels**.
