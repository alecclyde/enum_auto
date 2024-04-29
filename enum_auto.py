#!/usr/bin/env python

#TODO: DNS resolution with some variation of light ping arp, or ICMP - ping+paralell dns --- maybe combine it with nmap enumerator for large subnets?
#TODO: TCPdump commands - @ will provide those
#TODO: add a DNSenum or something
#TODO: Nuclei vuln scanner? Burp vuln scanner? maybe from nmap scan? @ will provide commands
#TODO: Remove NUC IP from scan - maybe DNS resolve?
#TODO: SUGGESTIONS!!

import os
import subprocess
import argparse
import logging
import ipaddress
from colorama import Fore, Style, init
from netaddr import IPSet, IPRange, IPAddress

def create_output_folder(base_folder):
    folder_name = base_folder
    counter = 1
    while os.path.exists(folder_name):
        folder_name = f"{base_folder}_{counter}"
        counter += 1
    os.makedirs(folder_name)
    return folder_name

def get_screen_name(command):
    parts = command.split()
    base_name = parts[0].split('/')[-1] if parts else 'defaultSession'
    screen_name = base_name
    counter = 2
    existing_sessions = subprocess.check_output("screen -ls | awk '/\\t/ {print $1}' | cut -d'.' -f2", shell=True).decode().split()
    while screen_name in existing_sessions:
        screen_name = f"{base_name}{counter}"
        counter += 1
    return screen_name

def run_command_in_screen(command, folder_name, log_enabled, log_directory):
    try:
        screen_name = get_screen_name(command)
        command_suffix = "; echo 'COMMAND COMPLETE'; exec bash"
        full_command = f"{command} {command_suffix}"
        if log_enabled:
            log_file_path = os.path.join(log_directory, f"{screen_name}_log.txt")
            screen_command = f"screen -L -Logfile {log_file_path} -dmS {screen_name} bash -c '{full_command}'"
            logging.info(f"Command launched successfully in screen [{screen_name}]. Output logged to {log_file_path}")
        else:
            screen_command = f"screen -dmS {screen_name} bash -c '{full_command}'"
        subprocess.run(screen_command, shell=True, check=True)
        print(Fore.YELLOW + f"Launching in screen [{screen_name}]: {command}" + (f" (logging to {log_file_path})" if log_enabled else "") + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error launching command {command}: {str(e)}")
        print(Fore.RED + f"Error launching command in screen [{screen_name}]: {str(e)}" + Style.RESET_ALL)

def get_local_ip():
    return subprocess.check_output("ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1", shell=True).decode().strip()

def parse_ips(ip_file):
    try:
        with open(ip_file, 'r') as file:
            raw_ips = file.read().splitlines()
            return validate_ips([ip.strip() for ip in raw_ips if ip.strip()])
    except Exception as e:
        logging.error(f"Error reading IP file {ip_file}: {str(e)}")
        raise

def exclude_ips(ips, exclusion_file):
    exclusion_ips = parse_ips(exclusion_file)
    ip_set = IPSet(ips)
    exclusion_set = IPSet(exclusion_ips)
    excluded_ips = ip_set - exclusion_set
    return [str(ip) for ip in excluded_ips]  # Convert each IPAddress to string

def expand_ip_range(ip_range):
    """ Expand shorthand IP ranges and return all IPs in the range as a list. """
    try:
        start_ip, end_ip = ip_range.split('-')
        # Handle cases where the end IP might be a shorthand notation
        if '.' not in end_ip:
            start_parts = start_ip.split('.')
            end_ip = '.'.join(start_parts[:-1] + [end_ip])
        ip_range = IPRange(start_ip, end_ip)
        return [str(ip) for ip in ip_range]
    except Exception as e:
        raise ValueError(f"Error parsing IP range {ip_range}: {e}")

def validate_ips(ips):
    valid_ips = []
    for ip in ips:
        if '-' in ip:  # Check if this is an IP range
            try:
                valid_ips.extend(expand_ip_range(ip))
            except ValueError as e:
                logging.error(str(e))
                raise
        else:
            try:
                # This will handle individual IPs and CIDRs
                ip_obj = ipaddress.ip_network(ip, strict=False)
                if ip_obj.num_addresses == 1:
                    valid_ips.append(str(ip_obj.network_address))
                else:
                    valid_ips.extend([str(ip_addr) for ip_addr in ip_obj])
            except ValueError as e:
                error_msg = f"Invalid IP address or CIDR format: {ip}. Error: {e}"
                logging.error(error_msg)
                raise ValueError(error_msg) from None
    return valid_ips


    return valid_ips

def execute_mode_large_subnets(ip_file_path, output_folder, log_enabled, log_directory):
    # List of multiple command placeholders
    commands = [
        f"echo 1 > test.large",
        f"command1 {ip_file_path} {output_folder}/output1 && some_post_process_command {output_folder}/output1",
        f"command2 {ip_file_path} {output_folder}/output2 && some_post_process_command {output_folder}/output2",
        f"command3 {ip_file_path} {output_folder}/output3 && some_post_process_command {output_folder}/output3",
        # Passive network listening
        f"above --interface eth0 --timer 120 > {output_folder}/above-out",
    ]

    # Running each command in its own screen session
    for command in commands:
        run_command_in_screen(command, output_folder, log_enabled, log_directory)

def execute_mode_quiet(ip_file_path, output_folder, log_enabled, log_directory):
    # List of multiple command placeholders
    commands = [
        f"echo 1 > test.quiet",
        f"command2 {ip_file_path} {output_folder}/output2 && some_post_process_command {output_folder}/output2",
        f"command3 {ip_file_path} {output_folder}/output3 && some_post_process_command {output_folder}/output3",
        # Passive network listening
        f"above --interface eth0 --timer 120 > {output_folder}/above-out",
    ]

    # Running each command in its own screen session
    for command in commands:
        run_command_in_screen(command, output_folder, log_enabled, log_directory)

def execute_mode_default(ip_file_path, output_folder, log_enabled, log_directory):
    # List of multiple command placeholders
    commands = [
        #f"responder -I eth0 --lm -v",
        # Nmap smb vuln scan
        f"nmap -Pn --script smb-vuln*,smb-os-discovery -p139,445 -vv --open -iL {ip_file_path} -oA {output_folder}/smb-enum-vuln && /opt/nmap-parse-output/nmap-parse-output {output_folder}/smb-enum-vuln.xml html-bootstrap > {output_folder}/smb-enum-vuln.html",
        # Nmap aggressive (OS detection, version detection, script scanning, and traceroute) of top 300 ports.
        f"nmap -A --top-ports 300 -vv -iL {ip_file_path} -oA {output_folder}/aggressive-quick && /opt/nmap-parse-output/nmap-parse-output {output_folder}/aggressive-quick.xml html-bootstrap > {output_folder}/aggressive-quick.html",
        # Nmap vuln scan
        f"nmap -Pn --script vuln -vv -iL {ip_file_path} -oA {output_folder}/vulnScan && /opt/nmap-parse-output/nmap-parse-output {output_folder}/vulnScan.xml html-bootstrap > {output_folder}/vulnScan.html",
        # Nmap all ports scan with version detection
        f"nmap -p- -sV -vv -iL {ip_file_path} -oA {output_folder}/portscan && /opt/nmap-parse-output/nmap-parse-output {output_folder}/portscan.xml html-bootstrap > {output_folder}/portscan.html",
        # Netexec null shares
        f"netexec --no-progress smb {ip_file_path} -u \"\" -p \"\" --shares --log {output_folder}/smbNullShare.txt",
        # Netexec null user enum
        f"netexec --no-progress smb {ip_file_path} -u \"\" -p \"\" --users --log {output_folder}/smbNullUsers.txt",
        # Netexec SMB relay list (hosts with SMB signing not required)
        f"netexec --no-progress smb {ip_file_path} --gen-relay-list {output_folder}/smbrelaylist",
        # Bluekeep vuln scan
        f"/opt/rdpscan/rdpscan --file {ip_file_path} > {output_folder}/rdpscan-out.txt",
        # GoWitness screenshot scan
        f"/opt/gowitness/gowitness-linux-amd64 scan -f {ip_file_path} --threads 200 --ports-small --screenshot-path {output_folder}/screenshots",
        # Network and domain information
        f"nmcli dev show eth0 > {output_folder}/network-info.txt",
        # Passive network listening
        f"above --interface eth0 --timer 120 > {output_folder}/above-out",
    ]

    # Running each command in its own screen session
    for command in commands:
        run_command_in_screen(command, output_folder, log_enabled, log_directory)

mode_executors = {
    'large-subnets': execute_mode_large_subnets,
    'quiet': execute_mode_quiet,
    'default': execute_mode_default
}

if __name__ == "__main__":
    init(autoreset=True)
    parser = argparse.ArgumentParser(description="Automated Enumeration Script")
    parser.add_argument("-f", "--file", required=True, help="Path to the target file")
    parser.add_argument("-e", "--exclude-file", required=True, help="File containing IPs to exclude")
    parser.add_argument("-m", "--mode", choices=['large-subnets', 'quiet', 'default'], default='default', help="Specify the operation mode")
    parser.add_argument("-l", "--logging", action="store_true", help="Enable logging for debugging purposes")
    args = parser.parse_args()

    output_folder = create_output_folder("AutoScript")
    log_directory = os.path.join(output_folder, "logs")
    if args.logging:
        os.makedirs(log_directory, exist_ok=True)  # Ensure log directory exists
        logging.basicConfig(filename=os.path.join(log_directory, 'autoscript.log'), level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')
    else:
        logging.basicConfig(level=logging.CRITICAL)  # Suppress all logging except CRITICAL errors

    local_ip = get_local_ip()
    ips = parse_ips(args.file)
    validated_ips = validate_ips(ips)
    exclusion_ips = parse_ips(args.exclude_file)
    if local_ip not in exclusion_ips:
        exclusion_ips.append(local_ip)

    ip_set = IPSet(validated_ips)
    exclusion_set = IPSet(exclusion_ips)
    excluded_ips = ip_set - exclusion_set
    final_ips = [str(ip) for ip in excluded_ips]

    ip_file_path = f"{output_folder}/validated_ips.txt"
    with open(ip_file_path, 'w') as ip_file:
        ip_file.write("\n".join(final_ips))

    # Retrieve and execute the mode-specific function
    mode_function = mode_executors.get(args.mode)
    if mode_function:
        mode_function(ip_file_path, output_folder, args.logging, log_directory)
    else:
        print(Fore.RED + "Invalid mode selected." + Style.RESET_ALL)

    print(Fore.GREEN + "Commands launched in screen sessions. Use 'screen -ls' to list and 'screen -r session_name' to attach to a session." + Style.RESET_ALL)
    if args.logging:
        logging.info("Script execution completed successfully.")
