# 🛡️ Cybersecurity Bash Toolkit - Checker.sh

Created by: Yarin Maimon
A modular Bash-based cybersecurity toolkit for simulating attacks and validating SIEM/SOC alerting in authorized internal networks.

> ⚠️ **Disclaimer**: This tool is for **educational purposes** and **authorized environments only**. Unauthorized use is strictly prohibited.

---

## 📌 Features

- 🔐 Brute Force Attacks (Hydra)
- 🔍 Port Scanning & Service Detection (Nmap)
- 🧅 Man-in-the-Middle (Arpspoof + TShark)
- 📂 SMB/RDP/WinRM Enumeration (CrackMapExec)
- 💥 Denial of Service Attack (hping3)
- 🎲 Random Attack Selector
- 🧠 Intelligent Service Detection
- 📁 Comprehensive Logging
- 🧰 Dynamic IP Target Selection

---

📂 Functions Overview

🔐 BRUTE()
 - Hydra-based brute force attack.
 - User inputs username & password files and the target service.
 - Results are logged.

🔍 NMAP()
- Port scan using Nmap (-sV -sC).
- Parses detected services and offers conditional brute forcing (e.g., SSH).
- Saves results to ~/Checker/nmap.txt.

🧅 MiTM()
- Man-in-the-Middle via Arpspoof and packet capture via TShark.
- Runs for a user-defined time.
- Saves packets as .pcap file.

📂 SMBENUM()
- CrackMapExec enumeration for SMB, RDP, or WinRM.
- Supports credentialed or anonymous access.
- Option to enumerate shares.
- Auto-installs CrackMapExec if missing.

💥 DOS_ATTACK()
- SYN flood attack using hping3.
- Runs for 15 seconds.
- Logs outcome and warns the user beforehand.

📋 MENU()
- Interactive main menu.
- Option to run any module or random one.
- Auto-installs pv for nice echo effects.

📜 Logging
- All actions are logged with:
    ⏰ Timestamp
    📌 Attack type
    🎯 Target IP/service
    ✅ Status (Completed, Aborted, Failed)

🚀 Usage
chmod +x checker.sh
sudo ./checker.sh
You’ll be greeted with a menu of attack options. Choose one and follow the prompts.
* Use flags to skip prompts, --help and go from there

📁 Folder Structure
~/Checker/
├── nmap.txt
├── cme_smb.txt
├── MiTM.pcap
└── checker.log

👨‍💻 Author: Yarin Maimon
Built for educational & SOC validation purposes. Perfect for cybersecurity students, red teamers, or those looking to learn offensive tools in a controlled setup.

🧯 Legal Notice
The author is not responsible for any misuse or damage caused by this tool. Use only in environments where you have explicit permission.

🔗 GitHub
If this helped or inspired you, drop a ⭐ on the repo!

Let me know:
- If you want to include badges (like tools used, Bash version, etc.)
- If you'd like me to push this to a file and you can re-upload
- Or if you’d like a **LinkedIn post template** now that you’re almost ready to publish!

What’s next? 😎
