# 🖥️ Windows Logs Documentation

## 🎯 Purpose

Windows logs simulate endpoint activity and are critical for detecting execution, persistence, and attacker behavior on compromised machines.

---

## 📊 Log Format

```log
EventCode=<code> index=windows User=<user> ParentProcess=<process> ProcessName=<process> CommandLine=<cmd>
```

---

## 🔑 Key Event Codes

| EventCode | Description           |
| --------- | --------------------- |
| 4688      | Process creation      |
| 4657      | Registry modification |
| 7045      | Service creation      |

---

## 🔑 Fields Explanation

| Field         | Description               |
| ------------- | ------------------------- |
| User          | Account executing process |
| ParentProcess | Parent process            |
| ProcessName   | Executed process          |
| CommandLine   | Full command              |

---

## 🧪 Data Types Included

### 🟢 Baseline

* Chrome, Outlook, Teams

### 🔴 Attack Simulation

* PowerShell execution
* Encoded commands
* Malware execution

### ⚪ Noise

* Normal applications (Notepad, Excel)

---

## 🔍 Use Cases

* Detect PowerShell abuse
* Identify process injection
* Track persistence mechanisms

---

## ⚠️ Analytical Value

Windows logs help answer:

* What executed on the system?
* Was it legitimate or malicious?
* How did the attacker maintain access?

---

## 🔗 Correlation Usage

* Web logs → download source
* DNS logs → callback behavior
* Email logs → infection origin

---

## 🚀 Outcome

Windows logs provide **deep visibility into attacker actions post-compromise**.
