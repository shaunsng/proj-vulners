#!/bin/bash

# Text formatting options as variables for easier use.
GREEN='\e[32m'
CYAN='\e[36m'
RED='\e[31m'
YELLOW='\e[33m'
CLEAR='\e[0m'
BOLD='\e[1m'
LINED='\e[4m'
BLUE='\e[34m'
MAGENTA='\e[35m'


# Various files required for this script saved as FIXED variables.
# If user does not specfiy a passwordlist, script will look for below options in their machine.
# >> User may wish to change list to suit your context and time/rigour for the search.

# These lists are possible options chosen as relatively short lists (100+) with a  fair chance of existing on user system. 
# However, they still take up some time for weakpassword check, in particular for telnet.  
# As such they will be kept in 'cold storage' - for user's consideration.  

# PASS_DEF='/usr/share/seclists/Passwords/darkweb2017-top100.txt'
# USERS_DEF='/usr/share/seclists/Usernames/top-usernames-shortlist.txt'

# For project submission and to facilitate quick script processing, will retain these 'fake lists' - intended to return a 'Not found' result.
PASS_DEF='/usr/share/seclists/Passwords/TEMPFAKE'
USERS_DEF='/usr/share/seclists/Usernames/TEMPFAKE'

# If above lists can't be found, script wll generate user and password files/lists using below arrays.
# >> Arrays have been kept very short for testing/efficiency. Feel free to edit/add if needed. 

PASSW=("user" "msfadmin" "123456" "password" "qwerty")
USERS=("user" "msfadmin" "root")	

# Default output directory if user does not specify. 
# REMINDER -- change to $pwd in final submission.

# OUTPUT_DIR='/home/kali/pentest/proj/scan_1306'
OUTPUT_DIR=$(pwd)

# Various fixed strings for printing at different stages of script.

HUMAN="${CYAN}$(whoami)${CLEAR}"
UDP1="[1] UDP port scan - all ports."
TCP="[2] TCP scan with service version."
UDP2="[3] UDP scan with service version - open ports only."
WEAK="[4] Weak password check on detected login service."
NSE="[5] Nmmap vulnerabiity scan - vulners script."
SPLOIT="[6] Searchsploit potential vulnerabilities."
TAKETIME="${YELLOW}This may take 2 - 3 minutes...${CLEAR}"

## Functions

# Check if IP address input by user is 'valid'.  i.e. if  it matches ipv4 format. Namely, four sets of 3 digits between 0 - 255, separated with a period. 
 
check_ip() {
	local ip=$1
    local stat=1	
	ip_grep=$(echo $ip | grep -Eo '^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$')
	
	if [[ "$ip_grep" == "$ip" ]]; then
		stat=0
	fi
	return $stat
}

# Check/parse user input for choice of basic or full scan. Input validation to 'fix' results as only two options - basic or full in the variable $scan_type.
 
check_scan() {
	local type=$(echo $1 | tr '[:upper:]' '[:lower:]')
	if [[ $type == 'basic' || $type == '1' ]]; then
		echo "Preparing to run $type scan per user selection." 
		scan_type='basic'
	elif [[ $type == 'full' || $type == '2' ]]; then
		scan_type='full'
	else
		echo "User has input an invalid scan type. Defaulting to basic scan."
		scan_type='basic'
	fi 	
}

# This function is called if user does not specify a custom password. 
# Checks if default password list (as specified above) can be found. If not, to generate passwordlist/file.
check_pass() {
	if test -f $PASS_DEF; then
		echo -e "Alternative list detected on user machine. Scan will proceed with password list ${CYAN}$PASS_DEF${CLEAR}." 
		pass_list=$PASS_DEF
		echo
	else
		echo -e "Alternative list could not be found. Script will generate and use a default short password list."
		:> $out_dir/passwords.lst
		for pass in ${PASSW[@]};
		do
			echo $pass >> $out_dir/passwords.lst
		done
		pass_list=$out_dir/passwords.lst
		echo
	fi
}

# Function to conduct basic keyword search on results. 
# Provide option to exit/stop the search. Continues looping if not.

search_results() {
	echo -e "[-] Please enter a keyword to search. Results will open in a 'less' window -- Use Page Up/Page Down keys to scroll and ${MAGENTA}'q'${CLEAR} to exit." 
	echo -e "[?] If you wish to stop search and exit, enter ${MAGENTA}'n'${CLEAR} or ${MAGENTA}'q'${CLEAR}." 

	read keyword
	choice=$(echo $keyword | tr '[:upper:]' '[:lower:]')
	if 	[[ $choice == 'n' || $choice == 'no' || $choice == 'q' || $choice == 'quit' ]]; then
		echo "[-] Exiting search..."
		echo
	else
		echo -e "[-] Searching for keyword ${BOLD}$keyword${CLEAR} within results:"
		echo
		echo
		echo
		
		# By first cd to the output dir, only the filenames itself will be output in the grep search - instead of full path, which results in very cluttered output.  
		cd $out_dir 
		# Grepping/searching for keyword specified by user in the key output files.
		# -Hn flag to include filename and line number since searching across multiple file
		
		# First line to append all search to file for archiving.  
		grep --color=always -Hn -i -A 2 -B 2 $keyword *.nmap *.out >> search_$date_time.lst
		
		# Second line to pipe to less for immediate output to screen/user.  
		grep --color=always -Hn -i -A 2 -B 2 $keyword *.nmap *.out | less -R
		echo
		search_results
		echo
	fi 	
}

## Main body. Title/banner and welcome message. 
echo -e "[-] Vulnerability scan for CFC-130124 PT project. By: Shaun Sng (S17). Trainer: Kar Wei"
echo -e "[☺] Welcome, $HUMAN. Script is initialising..."
echo

# Ask user for IP address. Call check_ip function to validate.
echo -e "[?] Please enter an IP address for scanning (e.g. ${GREEN}192.168.130.24)${CLEAR}: "
read ip_addr
echo

# If invalid input, this script will exit. At this initial stage of the script, it is deemed fair for poor input to force a break/exit. 
# As the script progresses, we avoid doing an exit/break due to invalid input and use defaults where possible. 

if check_ip $ip_addr; then
    :
    echo -e "[+] $HUMAN has entered a valid IP ${CYAN}$ip_addr${CLEAR}. Script will scan this address. "
else
    echo -e "[x] $HUMAN has entered an invalid IP ${RED}$ip_addr${CLEAR}. This script will exit."
    exit
fi

echo

# Ask user for output directory

echo -e "[?] Please input the directory you wish to save scan results. (e.g. ${GREEN}/home/kali/pentest/proj${CLEAR} )"
read out_dir
echo

# Check if directory exists.

if [ -d $out_dir ]; then
	# If valid, user specified $out_dir can be used in later script.
	echo "[+] Directory is valid. Scan results will be saved here."
else
	echo -e "[x] Directory could not be found, or $HUMAN has entered invalid input. Results will be saved to the current working directory." 
	# If invalid, use default OUTPUT_DIR specified earlier. 
	out_dir=$OUTPUT_DIR  
fi

echo

# Ask user for scan type.
echo -e "[?] Please enter ${BLUE}${BOLD}'1'${CLEAR} for ${BLUE}'Basic'${CLEAR} scan or ${MAGENTA}${BOLD}'2'${CLEAR} for ${MAGENTA}'Full'${CLEAR} scan."
read scan_type
echo
check_scan $scan_type 


# Ask user if they wish to provide custom passwordlist. If not, call check_pass function to look for backup list or generate own passwordlist.

echo -e "[?] Does $HUMAN wish to specify your own password list in this scan? Enter 'Y' or 'Yes' if so. All other input will be taken as 'No' [Y/N]" 
read pass_choice
echo
choice=$(echo $pass_choice | tr '[:upper:]' '[:lower:]')
if [[ $choice == 'y' || $choice == 'yes' ]]; then
	echo -e "[-] Please input the filename with full path (e.g. ${GREEN}/home/kali/pentest/proj/password.lst${CLEAR})."
	read pass_list
	if test -f $pass_list; then
		echo "[+] File located. Scan will proceed using user selection."
	else
		echo "[x] File could not be found, or $HUMAN entered invalid input."
		check_pass
	fi
else
	check_pass
fi 

## Functions to do the core scanning work.
# Port scans with masscan and Nmap 

port_scan(){	
	# UDP scan with masscan. Speed/rate bumped up to 10k, and scan all ports. 
	
	echo -e "${BOLD}$UDP1${CLEAR} Starting..."   
	sudo masscan $ip_addr -pU:1-65535 --rate=10000 -oL $out_dir/1_massudp
	
	# Process the output from masscan to derive the list of open UDP ports. 
	# For Nmap to scan these specific UDP ports later. 
	
	udp_ports=$(cat $out_dir/1_massudp | awk '{print$3}'| grep '[0-9]' | paste -s -d, /dev/stdin)
	echo
	
	# TCP scan with nmap. We incorporate one optional $1 argument
	# Toggles between scanning default 1k ports for basic scan, and all ports for full scan. 
	
	echo -e "${BOLD}$TCP${CLEAR} Scanning $tcp_ports ports.$TAKETIME"
	nmap -oA $out_dir/2_nmap_tcp -sV -T5 $ip_addr $1		
	echo
	echo -e "${BOLD}$UDP2${CLEAR} Starting..."
	sudo nmap -oA $out_dir/3_nmap_udp -sU -sV $ip_addr -p $udp_ports
	
}

# Function to check for weak passwords.

weak_pass(){	 
	userlist=""

	# Check if default password list exist/can be found. Generate own list if not.
	if test -f $USERS_DEF; then
		userlist=$USERS_DEF
	else
		:> $out_dir/users.lst
		for user in ${USERS[@]};
		do
			echo $user >> $out_dir/users.lst
		done
		userlist=$out_dir/users.lst
	fi 

	# Process earlier nmap results to check if open ports detected on the four login services - ftp, ssh, rdp, telnet. Save to variable.
	 
	check_services=$(cat $out_dir/2_nmap_tcp.nmap $out_dir/3_nmap_udp.nmap | grep open | grep -Eo "ftp|ssh|rdp|telnet" | sort | uniq)
	echo	

	# For any login service detected from earlier scan, run weak password check for each. If none, inform user and skip stage. 
	
	echo -e "${BOLD}$WEAK${CLEAR} starting... "
	echo
	# This conditional check dependent whether check_services variable is empty.
	if [ -z "$check_services" ]; then
		echo "[x] No running login services (FTP, SSH, Telnet or RDP) detected. Skipping weak password checks."
		echo
	else
		# Core/key code - for each of the detected login services saved in variable $check_services, run hydra with the prepared password and user lists.
		for item in $check_services;
		do
			echo -e "[-] Checking weak password for ${CYAN}${BOLD}$item${CLEAR} service;"
			echo
			# Some brief performance optimisation was attempted by reducing -w to 10, instead of default.  
			hydra -L $userlist -P $pass_list -e ns -w 10 -o $out_dir/4_hydra.out -I $ip_addr $item
			echo
		done
	fi	
}


# Function to conduct the Nmap NSE scan and searchsploit search for Full scan option.
vuln_scan(){

	echo -e "${BOLD}$NSE Starting.${CLEAR} $TAKETIME"
	
	# Key Nmap command - run the vulners script and save to basic output format. 
	# >> T5 used to maximise performance. User may wish to adjust for your context if needed.  
		 
	nmap -oN $out_dir/5_nmap_vulners.out -T5 -sV --script vulners $ip_addr -p-
	
	# Key searchsploit commands - Use in built option to take in nmap xml files as input. 
	# Hence we use two commands as earlier nmap searches were done separately for TCP and UDP - producing two separate XML files. 
	# Combine both files in one '6_sploit_all.out' file for later search. 
		
	## Using metasploitable as test machine retrieves a large number of results. Noisy/difficult to know where to pay attention.  
	
	searchsploit --disable-colour -x --nmap $out_dir/2_nmap_tcp.xml > $out_dir/6_sploit_tcp.lst
	searchsploit --disable-colour -x --nmap $out_dir/3_nmap_udp.xml > $out_dir/6_sploit_udp.lst
	cat $out_dir/6_sploit_tcp.lst $out_dir/6_sploit_udp.lst > $out_dir/6_sploit_all.out	
}


# Check if basic or full scan needs to be done. Call the appropriate functions. 

if [[ $scan_type == 'basic' ]]; then
	tcp_ports='1000'
	echo -e "${BOLD}[-] Basic scan proceeding in these stages:${CLEAR}"
	echo $UDP1
	echo "$TCP Scanning $tcp_ports ports."
	echo $UDP2
	echo $WEAK
	echo
	
	port_scan 
	weak_pass
else
	tcp_ports='65,535'
	echo -e "${BOLD}[-] Full scan proceeding in these stages:${CLEAR}"
	echo $UDP1
	echo "$TCP Scanning $tcp_ports ports."
	echo $UDP2
	echo $WEAK
	echo $NSE
	echo $SPLOIT
	echo	
	
	port_scan -p-
	weak_pass
	vuln_scan
fi


# Reporting Stage. Prepare to summarise findings for user.
echo
echo
echo -e "${BOLD}${GREEN}[-] Scan complete.${CLEAR} ${BOLD}Organising results...${CLEAR}"
sleep 2
echo

# Quick processing of earlier results to count the number of open ports.
open_tcp=$(cat $out_dir/2_nmap_tcp.nmap | grep open | wc -l)
open_udp=$(cat $out_dir/3_nmap_udp.nmap | grep open | wc -l)


# At each stage, we prepare the user what info they will be seeing. 
echo "[-] Results for port scans from stages:"
echo --$UDP1
echo --$TCP
echo --$UDP2
echo

# Output the key messages of how many open ports were detected.
echo -e "[-] ${RED}${BOLD}$open_tcp${CLEAR} open ports on TCP were detected. Service and versions detected below:"
echo


# Extract/recap the main table of open ports & services from earlier nmap scans.   
cat $out_dir/2_nmap_tcp.nmap |  grep --color=never ^PORT && cat $out_dir/2_nmap_tcp.nmap | grep --color=never open
echo
echo -e "[-] ${RED}${BOLD}$open_udp${CLEAR} open ports on UDP were detected. Service and versions detected below:"
echo
cat $out_dir/3_nmap_udp.nmap |  grep --color=never ^PORT && cat $out_dir/3_nmap_udp.nmap | grep --color=never open
echo

echo "[!] User should consider closing ports for any unrequired service."
echo
sleep 5

# Moving on to next stage results for weak password checks...

echo $WEAK stage results:

# Checking and doing and appropriate output if no password checks was done.

if [ -z "$check_services" ]; then
	echo "[-] No weak password checks for login services were done. No results to report."
	# continue	
else
	echo "[-] Weak passwords (and corresponding matching user login IDs) were detected on the following ports & services:"
	echo
	# Extract and summarise just the key data from earlier hydra scan -i.e. which services/ports, user login and passwords were detected.
	grep login $out_dir/4_hydra.out | sort | uniq | awk '{print$1,$4,$5,$6,$7}'
	echo
	echo "[!] User should consider strengthening passwords or removing these login accounts."

fi
sleep 4
echo
echo

## Processing results from Nmap NSE scan. 

# Nmap NSE detected many results. The total/complete results from ExploitDB include many difference sources/reporters/vendors - many reports refer to the same CVE.
# As such you can say there is "double counting/duplicates". Still relevant to get a sense, but very noisy.

# We process the earlier nmap results to get first both the 'total vulnerabilities' and 'CVE' only. Output to text files for easier manipulation.
# The latter serves to avoid double counting to get a more manageable list/sense of the extent of vulnerability.

grep CVE $out_dir/5_nmap_vulners.out | awk '{print$2}' | sed 's/^[^:]*://' | sort | uniq | wc -l > $out_dir/cve_trim.lst
grep cve $out_dir/5_nmap_vulners.out | awk '{print$2,$3,$4}' | sort | uniq > $out_dir/cve_only.out


# Save numbers of total vulnerabilities and CVE only to variables for subsequent reporting to console/user.
num_all=$(cat $out_dir/5_nmap_vulners.out | grep -E "cve|CVE|SSV|OSV|PRION|packetstorm|securityvulns|1337DAY|github|EDB-ID|SAINT|EXPLOIT" | wc -l)
num_cve=$(grep cve $out_dir/5_nmap_vulners.out | awk '{print$2,$3,$4}' | sort | uniq | wc -l)

# Save /extract the total vulnerabilities and CVE results themselves subsequent reporting to console/user.
vul_table=$(grep ^'| vulners' -B 1 $out_dir/5_nmap_vulners.out | grep --color=never open)
vul_services=$(grep ^'| vulners' -B 1 $out_dir/5_nmap_vulners.out | grep --color=never open | awk '{print$3}' | sort | uniq)

grep ^'| vulners' -B 1 $out_dir/5_nmap_vulners.out | grep --color=never open | awk '{print$3}' | sort | uniq > $out_dir/6_vul_service.lst
num_services=$(cat $out_dir/6_vul_service.lst| wc -l)

## Reporting Nmap NSE results to user. 
echo $NSE stage results:
echo
echo -e "[-] Total matches: ${YELLOW}$num_all potential vulnerabilities${CLEAR} were detected. This counts ${LINED}all reports across multiple vendors and info sources${CLEAR}, and includes 'duplicate' entries referring to the same CVE." 
echo -e "[-] Affected services: Detected vulnerabilities were from the ${YELLOW}$num_services services${CLEAR} recapped in table below:" 
echo "$vul_table"
echo
echo

# Output to the top 10 CVEs list sorted by CVSS score. This was one approach to filter/extract the most key info for user. 
echo -e "[-] CVEs: To avoid 'double counting,' we focus on the CVEs detected. The scan detected ${RED}${BOLD}$num_cve CVEs${CLEAR}. The top 10 potentially most severe based on CVSS score are shown below:" 
echo
grep cve $out_dir/5_nmap_vulners.out | awk '{print$2,$3,$4}' | sort | uniq | sort -k 2 -r -n | head -n 10
echo
echo "[>] For more details and full results, see log file $out_dir/5_nmap_vulners.nmap"
echo
sleep 5

## Reporting Searchsploit results
echo $SPLOIT stage results:

# Processing searchsploit results. Saving numbers for reporting.  
num_sploit=$(grep -v 'No Results' $out_dir/6_sploit_all.out | grep ^[A-Za-z] | wc -l)
num_filter=$(grep -i -f $out_dir/6_vul_service.lst $out_dir/6_sploit_all.out | wc -l)

# As searchsploit yielded a large number of noisy results. We opted triangulate and filter using the Nmap NSE scan.
# The detected services from Nmap NSE are used as search/filter to filter down the searchsploit results. 
    
grep -i -f $out_dir/6_vul_service.lst $out_dir/6_sploit_all.out > $out_dir/6_sploit_priority.out

echo
echo -e "[-] Total matches: ${YELLOW}$num_sploit potential vulnerabilities${CLEAR} were detected in the full searchsploit results - see $out_dir/6_sploit_all.out." 

echo -e "[!] Priority: Filtering with the services detected in the Nmap NSE scan obtains a higher priority list of ${RED}$num_filter potential vulnerabilities${CLEAR}:"
echo

# Outputting the filter sploit to screen. 
cat $out_dir/6_sploit_priority.out
# grep -i -f $out_dir/6_vul_service.lst $out_dir/6_sploit_all.out
echo
echo -e "[-] Filtered/prioritised searchsploit results in $out_dir/6_sploit_priority.out."
echo
echo "[-] End of main scan." 
sleep 4

## Ask user if they want to search within results, and call keyword search function if so.

echo -e "[?] Would $HUMAN like to search within scan results now? Enter 'Y' for Yes or 'N' for No. [Y/N]"
read searchnow
choice=$(echo $searchnow | tr '[:upper:]' '[:lower:]')
echo $choice
if [[ $choice == 'y' || $choice == 'yes' ]]; then
	search_results
elif [[ $choice == 'n' || $choice == 'no' ]]; then
	echo "[-] Acknowledged. Skipping search."
else
	echo -e "[x] $HUMAN has entered an invalid option. Skipping search."
fi 	

echo

# Housekeeping - zipping up scan and search output.
# Saving datetime as variable to use as as suffix in zipfilename. Can differentiate between multiple runs/zips, avoid overwriting.
date_time=$(date +"%F_%H:%M")

# Create new 'zipped' child directory to store zipped package.
# "Raw' files produced in the script retained in the parent output directory. If not needed can use '-m' flag. 
# Retained for user to do immediate investigation instead of having to unzip.

mkdir -p $out_dir/zipped
zip -j $out_dir/zipped/"scan_s17_$date_time.zip" $out_dir/* -x \*.zip \*.sh
echo
echo "[-] Key results are saved in $out_dir/zipped/scan_s17_$date_time.zip"
echo "[-] This script will now exit. Have a nice day."

