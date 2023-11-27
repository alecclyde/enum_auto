#!/usr/bin/env python

#TODO - CrackMapExec requires [enter] keyboard input, find a way to work around that.
#TODO - Add a option for covert assessments

import os
import subprocess
import threading
import sys
import time
import termios
import tty
import signal
import glob
from colorama import Fore, Style, init

ascii_banner = """
                                                                
 ###### #    # #    # #    #           ##   #    # #####  ####  
 #      ##   # #    # ##  ##          #  #  #    #   #   #    # 
 #####  # #  # #    # # ## #         #    # #    #   #   #    # 
 #      #  # # #    # #    #         ###### #    #   #   #    # 
 #      #   ## #    # #    #         #    # #    #   #   #    # 
 ###### #    #  ####  #    #         #    #  ####    #    ####  
                             #######                            
"""

keyboard_interrupt_occurred = False
completed_threads = 0

def keyboard_interrupt_handler(signum, frame):
    global keyboard_interrupt_occurred
    keyboard_interrupt_occurred = True
    print(Fore.RED + "\nScript halted due to keyboard interrupt. Wait while script performs cleanup." + Style.RESET_ALL)

def run_command(command, folder_name, thread_num, total_threads):
    global completed_threads
    try:
        output_file = os.path.join(folder_name, f"{command.split(' ')[0]}.txt")
        start_time = time.time()
        print(Fore.YELLOW + f"Running [{thread_num}/{total_threads}]: {command}" + Style.RESET_ALL)
        with open(output_file, 'w') as output:
            process = subprocess.Popen(command, shell=True, stdout=output, stderr=subprocess.STDOUT, text=True)
            
            # Create a thread to monitor the command
            monitor_thread = threading.Thread(
                target=monitor_command,
                args=(process, command, folder_name, thread_num, total_threads)
            )
            monitor_thread.start()

            process.wait()
            monitor_thread.join()  # Ensure the monitor thread has finished
            
            if keyboard_interrupt_occurred:
                print(Fore.RED + f"{command} was halted due to a keyboard interrupt." + Style.RESET_ALL)
            else:
                end_time = time.time()
                elapsed_time = end_time - start_time
                completed_threads += 1
                print(Fore.GREEN + f"Completed [{completed_threads}/{total_threads}]: {command} successfully in {elapsed_time:.2f} seconds." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error running {command}: {str(e)}" + Style.RESET_ALL)

def monitor_command(process, command, folder_name, thread_num, total_threads):
    ongoing_time = 0
    while process.poll() is None:  # while the process is still running
        time.sleep(10)  # check every 10 seconds to reduce CPU usage
        ongoing_time += 10
        if ongoing_time % 120 == 0:
            elapsed_time = time.strftime("%H:%M:%S", time.gmtime(ongoing_time))
            print(
                Fore.YELLOW + f"[{thread_num}/{total_threads}] {command} is still running after {elapsed_time}." + Style.RESET_ALL
            )
            if "crackmapexec" in command:
                print(
                    Fore.CYAN + f"Reminder: For command [{thread_num}/{total_threads}] {command}, you may need to click 'Enter' for it to complete." + Style.RESET_ALL
                )

def create_output_folder(base_folder):
    folder_name = base_folder
    counter = 1
    while os.path.exists(folder_name):
        folder_name = f"{base_folder}{counter}"
        counter += 1
    os.makedirs(folder_name)
    return folder_name

def remove_empty_files(folder_name):
    deleted_files = []
    for filename in os.listdir(folder_name):
        file_path = os.path.join(folder_name, filename)
        if os.path.getsize(file_path) == 0:
            os.remove(file_path)
            deleted_files.append(filename)
    if deleted_files:
        print("The following files were empty and have been removed (this may mean output was captured in a separate file):")
        for filename in deleted_files:
            print(f"{filename}")

def rename_executables(folder_path):
    files = os.listdir(folder_path)
    for filename in files:
        if filename.startswith('gowitness') and filename.endswith('amd64'):
            if filename != "gowitness-linux-amd64":
                full_path = os.path.join(folder_path, filename)
                new_filename = os.path.join(folder_path, 'gowitness-linux-amd64')
                os.rename(full_path, new_filename)
                print(f'Renamed {filename} to gowitness-linux-amd64')

def second_set_of_commands(input_file, output_folder):
    global completed_threads
    completed_threads = 0
    print(Fore.CYAN + "\nInitiating the second set of commands..." + Style.RESET_ALL)
    commands = [
        #### Put commands that should happen after first set here ####
    ]
    
    # Find all .xml files within the output folder
    xml_files = glob.glob(f"{output_folder}/*.xml")
    for xml_file in xml_files:
        xml_filename = os.path.basename(xml_file)
        html_command = f"/opt/nmap-parse-output/nmap-parse-output {xml_file} html-bootstrap > {output_folder}/{xml_filename}.html"
        commands.append(html_command)
    
    total_threads = len(commands)
    threads = []
    for idx, command in enumerate(commands, start=1):
        thread = threading.Thread(target=run_command, args=(command, output_folder, idx, total_threads))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    
def change_permissions(folder):
    try:
        subprocess.run(["chmod", "-R", "777", folder], check=True)
        print(Fore.GREEN + f"Permissions changed for {folder}" + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Failed to change permissions for {folder}: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    init(autoreset=True)
    signal.signal(signal.SIGINT, keyboard_interrupt_handler)
    if len(sys.argv) != 2:
        print(Fore.RED + "Usage: python enumAuto.py /path/to/target-file" + Style.RESET_ALL)
        sys.exit(1)
    
    print(ascii_banner)

    input_file = sys.argv[1]

    print(Fore.CYAN + "You may have to click 'enter' to complete crackmapexec threads."  + Style.RESET_ALL)

    if not os.path.isfile(input_file):
        print(Fore.CYAN + f"Input file '{input_file}' does not exist." + Style.RESET_ALL)
        sys.exit(1)

    output_folder = create_output_folder("AutoScript")
    rename_executables('/opt/gowitness/')

    commands = [
        f"nmap -Pn --script smb-vuln* -p139,445 --open -iL {input_file} -oA {output_folder}/smb-enum-vuln",
        #f"nmap -nvv -sS -sV -sC -O -p- --open -iL {input_file} -oA {output_folder}/full-scan-allports",
        f"nmap -A --top-ports 200 -iL {input_file} -oA {output_folder}/aggressive-quick",
        #f"nmap -nvv -sU -sV -sC -p- -O --open -iL {input_file} -oA {output_folder}/udp-full-allports",
        f"nmap -Pn --script vuln -iL {input_file} -oA {output_folder}/vulnScan",
        f"nmap --top-ports 300 -iL {input_file} -oA {output_folder}/portscan",
        f"crackmapexec smb {input_file} -u '' -p '' --shares > {output_folder}/smbNullShare.txt",
        f"crackmapexec smb {input_file} -u '' -p '' --users > {output_folder}/smbNullUsers.txt",
        f"crackmapexec smb {input_file} --gen-relay-list {output_folder}/smbrelaylist.txt",
        f"/opt/rdpscan/rdpscan --file {input_file} > {output_folder}/rdpscan-out.txt",
        f"/opt/gowitness/gowitness-linux-amd64 scan -f {input_file} --threads 30 --ports-small --screenshot-path {output_folder}/screenshots",
        f"tshark -c 2000 -i eth0 -w {output_folder}/2000_packet.pcap",
    ]

    original_settings = termios.tcgetattr(sys.stdin)
    tty.setcbreak(sys.stdin.fileno())
    total_threads = len(commands)
    threads = []
    for idx, command in enumerate(commands, start=1):
        thread = threading.Thread(target=run_command, args=(command, output_folder, idx, total_threads))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    second_set_of_commands(input_file, output_folder)
    remove_empty_files(output_folder)
    termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, original_settings)

    if keyboard_interrupt_occurred:
        print(Fore.RED + "Script was halted due to a keyboard interrupt." + Style.RESET_ALL)
    else:
        change_permissions(output_folder)
        print(Fore.GREEN + "All commands completed." + Style.RESET_ALL)
        
