# VULNERS

## Objective

This project entails drafting a script to automate scanning a network/host for vulnerabilities and should achieve the following functions:
- Incorporate and validate user input e.g.  choice of ‘Basic’ or ‘Full Scan’, specifying output directory and custom password list.
- Check for weak passwords in login services - SSH, RDP, FTP and Telnet. 
- Basic scan checks for open ports/services and weak passwords. Full scan additionally runs the Nmap vulners script and Searchsploit. 
- Allow user to search results.
- Save results in the Zip file. 

### Tools Used
- Nnmap with Nmap Scripting Engine (NSE) arguments 
- Hydra
- Bash scripting
