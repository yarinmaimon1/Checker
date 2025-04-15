Checker Toolkit
Created by: Yarin Maimon

Overview

This is a modular Bash-based cybersecurity toolkit designed to assist in auditing, monitoring, and testing security controls in internal network environments. It provides a user-friendly interface for performing a variety of attacks and checks, simulating malicious activity to validate SIEM/SOC alerting mechanisms.

Disclaimer: This tool is meant for educational purposes and authorized testing environments only. Unauthorized use is strictly prohibited.

Features

Brute Force Attack (via Hydra)

Port Scanning & Service Detection (via Nmap)

Man-in-the-Middle Attack (via Arpspoof & TShark)

SMB/RDP/WinRM Enumeration (via CrackMapExec)

Denial of Service Attack (via hping3)

Random Attack Selection

Dynamic Network Target Selector

Comprehensive Logging

Structure & Functionality

BRUTE()

Performs a brute force attack using Hydra.

Prompts the user for paths to a username and password file.

Optionally prompts for the service protocol (FTP, SSH, etc.).

Logs results to the toolkit's logfile.

NMAP()

Scans the target for open ports and service versions.

Uses nmap -sV -sC and stores output in ~/Checker/nmap.txt.

Automatically parses detected services.

Prompts the user to launch a brute force attack if SSH/FTP/Telnet is found.

MiTM()

Launches a Man-In-The-Middle attack.

Uses arpspoof to redirect traffic between target and router.

Captures packets using tshark.

User-defined duration.

Outputs .pcap file and logs status.

SMBENUM()

Enumerates Windows services using CrackMapExec.

Supports SMB, RDP, and WinRM.

Offers credentialed or anonymous scans.

Can enumerate shares if desired.

Auto-installs CrackMapExec if missing.

Logs scan results to ~/Checker/.

DOS_ATTACK()

Performs a SYN flood attack with hping3.

Asks for target IP and port.

15-second flood duration.

Logs attack outcome.

Displays warning before execution.

MENU()

Main user interface.

Offers six options (five attack types + random).

Automatically installs pv if missing.

Startup Logic

Creates ~/Checker directory.

Initializes logfile if missing.

Executes any set $RUN_* environment variables before showing the menu.

Logging

All actions are logged with:

Timestamp

Module name

Target IP and details

Execution status (Completed, Aborted, Failed)

Sample Execution

chmod +x Checker.sh
sudo ./Checker.sh

Legal Notice

Usage of this tool is strictly limited to environments where you have explicit authorization. The authors are not responsible for misuse or damages resulting from the use of this software.

Author

Developed as part of a cybersecurity toolkit project to simulate attacker techniques and validate defensive controls.