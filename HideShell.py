#!/usr/bin/env python

import base64
import sys
import re
import os
from colorama import init, Fore, Style

init(autoreset=True)


def powershell_encode(data):
    # blank command will store our fixed unicode variable
    blank_command = ""
    powershell_command = ""
    # Remove weird chars that could have been added by ISE
    n = re.compile(u'(\xef|\xbb|\xbf)')
    # loop through each character and insert null byte
    for char in (n.sub("", data)):
        # insert the nullbyte
        blank_command += char + "\x00"
    # assign powershell command as the new one
    powershell_command = blank_command
    # base64 encode the powershell command
    powershell_command = base64.b64encode(powershell_command.encode())
    return powershell_command.decode("utf-8")


def usage():
    # Print usage information
    print(Fore.YELLOW + "Version: 0.1")
    print(Fore.YELLOW + "PSEncoder - Encode a PowerShell script into a Base64 string")
    print(Fore.YELLOW + "Usage: python psencoder.py\n")
    sys.exit(0)


def get_available_filename(filename):
    # Check if the filename already exists
    if os.path.isfile(filename):
        counter = 2
        base_name, extension = os.path.splitext(filename)
        # Find an available filename by incrementing a counter
        while os.path.isfile(f"{base_name}{counter}{extension}"):
            counter += 1
        return f"{base_name}{counter}{extension}"
    else:
        return filename


def main():
    if len(sys.argv) > 1:
        # If there are command-line arguments, display the usage information
        usage()

    print(Fore.CYAN + '''
    __  ___     __    _____ __         ____
   / / / (_)___/ /__ / ___// /_  ___  / / /
  / /_/ / / __  / _ \\__ \/ __ \/ _ \/ / / 
 / __  / / /_/ /  __/__/ / / / /  __/ / /  
/_/ /_/_/\__,_/\___/____/_/ /_/\___/_/_/         
  HideShell - Encode a PowerShell script into a Base64                                  
=========================================================
        Evade Anti-Virus like a Sicario\n
''')

    try:
        script_file = input(Fore.WHITE + "Enter the path to the PowerShell script: ")

        if not os.path.isfile(script_file):
            print(Fore.RED + "The specified PowerShell script does not exist.")
            sys.exit(1)

        with open(script_file, 'r') as file:
            ps_script = file.read()
            encoded_script = powershell_encode(ps_script)

            output_file = get_available_filename("powershell.txt")
            with open(output_file, 'w') as output:
                output.write("$encodedScript = '{}'".format(encoded_script))
                output.write("\n")
                output.write(
                    "$decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript))")
                output.write("\n")
                output.write("Invoke-Expression -Command $decodedScript")

            print("\n" + Fore.GREEN + f"Encoded PowerShell script has been saved to {output_file}")

    except KeyboardInterrupt:
        print("\n" + Fore.YELLOW + "Keyboard interrupt received. Exiting gracefully...")
        sys.exit(0)


if __name__ == "__main__":
    main()
