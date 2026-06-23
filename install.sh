#!/bin/bash
# Make executable: chmod +x install.sh
echo "[*] NJÓSNARI Deployment initiated..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-tk metasploit-framework
pip3 install -r requirements.txt --break-system-packages
echo "[+] Dependencies installed. Ready for launch."
