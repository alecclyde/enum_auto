#!/bin/bash

# Update package lists
sudo apt update

# Navigate to the /tmp directory
cd /tmp

# Install via pip
pip install colorama

# Install Google Chrome
curl -O https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb

# Install GoWitness
sudo mkdir -p /opt/gowitness/
wget https://github.com/sensepost/gowitness/releases/download/2.5.0/gowitness-2.5.0-linux-amd64 -O /tmp/gowitness-linux-amd64
sudo mv /tmp/gowitness-linux-amd64 /opt/gowitness/gowitness-linux-amd64
sudo chmod +x /opt/gowitness/gowitness-linux-amd64

# Install rdpscan
if [ -d /opt/rdpscan ]; then
    cd /opt/rdpscan
    git pull
    make
else
    sudo mkdir -p /opt/rdpscan
    git clone https://github.com/robertdavidgraham/rdpscan.git /opt/rdpscan
    cd /opt/rdpscan
    make
fi

# Install via apt
sudo apt install nmap tshark pipx -y

# Install crackmapexec using pipx
pipx install crackmapexec
