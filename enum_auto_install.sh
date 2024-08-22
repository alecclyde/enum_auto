#!/bin/bash

set -e

# Check if the user is root, exit if not
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# check and install necessary dependencies
sudo apt update

sudo apt install -y curl wget git make pip pipx libssl-dev
sudo apt install -y nmap tshark dnsenum enum4linux screen gowitness autorecon nuclei netexec

# Install Python packages
sudo pip install --upgrade pip
sudo pip install colorama netaddr

cd /tmp

# Install Google Chrome
if ! type google-chrome > /dev/null 2>&1; then
    echo "Installing Google Chrome..."
    curl -O https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    sudo dpkg -i google-chrome-stable_current_amd64.deb || sudo apt install -f -y
else
    echo "Google Chrome is already installed."
fi

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

# Install crackmapexec
pipx install git+https://github.com/byt3bl33d3r/CrackMapExec
