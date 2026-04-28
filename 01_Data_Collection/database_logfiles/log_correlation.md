# 🔎 SOC Log Correlation Cheat Sheet

A quick visual reference to understand **what data exists in each log source** and how to correlate them during investigations.

---

## 👤 Identity & Access (WHO)

### `auth.log`

```
user: alice
src_ip: 192.168.1.25
action: login
status: success
timestamp: 2026-04-01
```

### `email.log`

```
recipient: alice
sender: it-support@secure-login.com
attachment: reset.docm
timestamp: 2026-04-01
```

**Pivot Keys:** `user`, `recipient`, `src_ip`

---

## 💻 Endpoint Activity (WHAT RAN)

### `windows.log`

```
User: alice
ProcessName: chrome.exe
ParentProcess: explorer.exe
EventCode: 4688
```

**Pivot Key:** `User`

---

## 📁 Data Access (WHAT WAS TOUCHED)

### `file.log`

```
user: alice
file: finance.xlsx
bytes: 17472083
timestamp: 2026-04-01
```

**Pivot Key:** `user`

---

## 🌐 Network Activity (WHERE IT WENT)

### `dns.log`

```
src_ip: 192.168.1.25
query: data.exfil.evil.com
bytes_out: 15521908
timestamp: 2026-04-01
```

### `web.log`

```
user: alice
url: http://youtube.com
action: allowed
```

**Pivot Keys:** `src_ip`, `user`, `domain`

---

## ☁️ Data Movement (EXFIL / CLOUD)

### `cloud.log`

```
action: PutObject
bucket: external-data
bytes: 81821232
timestamp: 2026-04-01
```

**Pivot Key:** `bytes`

---

## 🔗 Attack Flow (Kill Chain)

```
email.log      → Phishing email (reset.docm)
      ↓
windows.log    → Process execution (possible macro)
      ↓
file.log       → finance.xlsx accessed
      ↓
dns.log        → data.exfil.evil.com queried
      ↓
cloud.log      → Large data upload (PutObject)
```

---

## 🎯 Correlation Quick Reference

```
USER  → alice
  auth | email | file | web | windows

IP    → 192.168.1.25
  auth | dns

BYTES → 17MB → 15MB → 81MB
  file → dns → cloud

TIME  → Align timestamps across all logs
```

---

## 💡 Usage Tips

* Start with **user or IP pivot**
* Build a **timeline using timestamps**
* Compare **bytes fields** to detect exfiltration
* Look for **suspicious domains + large transfers**
* Tie **email → execution → data access → exfil**

---

## 🚀 Optional Enhancements

* Convert into **Splunk / KQL queries**
* Build **timeline visualization**
* Create **alert rules for exfil patterns**

---
