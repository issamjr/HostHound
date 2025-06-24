<img src="https://raw.githubusercontent.com/issamjr/HostHound/refs/heads/main/img.jpg" >
# 🐾 HostHound - Advanced Shared Host Scanner Tool

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)

---

## 🧠 What is HostHound?

**HostHound** is a powerful and intelligent Python tool designed to discover **all domains hosted on the same server** as a given domain by scanning the `/24` subnet of the resolved IP address. It combines **reverse DNS lookups** with **port checking** to find active hosts.

---

## ✨ Features

- 🔍 Resolve the domain to IP address
- 📡 Scan `/24` IP range of the resolved address
- 🕵️‍♂️ Perform reverse DNS lookup
- 🌐 Check for open port 80 (HTTP)
- 💾 Save results to `results.txt`
- ⚡ Multithreaded scanning for high performance

---

## 📥 Installation

```bash
git clone https://github.com/issamjr/HostHound.git
cd HostHound
pip install -r requirements.txt
```

> 📝 Requirements: `colorama`, `requests`

You can also install them manually:

```bash
pip install colorama requests
```

---

## 🚀 Usage

```bash
python3 hosthound.py example.com
```

### Optional arguments:

- `--timeout` ➤ Network timeout in seconds (default: 2)
- `--threads` ➤ Max threads for scanning (default: 20)
- `--save` ➤ Save results to `results.txt`

### Example:

```bash
python3 hosthound.py example.com --threads 30 --timeout 3 --save
```

---

## 🧠 Example Output

```bash
[INFO] Resolved example.com to 93.184.216.34
[INFO] Scanning 254 hosts in subnet 93.184.216.0/24...
[+] Found domain: subdomain.example.org [port 80 open]
[✓] Scan complete: 5 domain(s) found in 12.45 seconds.
[+] Results saved to results.txt
```

---

## 👨‍💻 Author

**Code by: [Issam Junior](https://github.com/issamjr)**  
✉️ Cybersecurity & Python Developer

---

## 🛡️ License

This tool is licensed under the **MIT License**. Feel free to use and modify it for educational and ethical purposes.

---

## 📁 Repository Name

**Repository:** `HostHound`  
**Title:** `HostHound - Shared Host Scanner | Cyber Recon Tool`
