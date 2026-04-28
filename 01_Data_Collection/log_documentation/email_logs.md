# 📧 Email Logs Documentation

## 🎯 Purpose

Email logs simulate phishing campaigns and are the primary source for identifying initial attack vectors.

---

## 📊 Log Format

```log
timestamp=<time> index=email sender=<email> recipient=<user> subject=<text> attachment=<file>
```

---

## 🔑 Fields Explanation

| Field      | Description   |
| ---------- | ------------- |
| sender     | Email sender  |
| recipient  | Target user   |
| subject    | Email subject |
| attachment | File attached |

---

## 🧪 Data Types

### 🟢 Baseline

* Internal communications
* Legitimate attachments

### 🔴 Attack Simulation

* Phishing emails
* Macro-enabled files (.docm)

### ⚪ Noise

* Newsletters, alerts

---

## 🔍 Use Cases

* Detect phishing campaigns
* Analyze email spread
* Identify malicious attachments

---

## ⚠️ Analytical Value

Email logs help answer:

* Who received phishing emails?
* Was it targeted or mass attack?
* What payload was delivered?

---

## 🔗 Correlation Usage

* Web logs → click behavior
* Windows logs → execution
* DNS logs → post-infection activity

---

## 🚀 Outcome

Email logs represent the **initial attack vector in most scenarios**.
