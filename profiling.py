# This is meant to be a more active recon to make the passive output more helpful

import os
import json


#TODO 

    # Obtain the IP addresses and perform a port scan for the top 100 ports
    # Generate a list of the IP's [ (IP: port, port2) (IP2: port, port2) ] with each port scanned IP. 
    # If port 80, 8080, 443 open a connection with an old user agent
    # Investigate 


def read_passive_recon(domain):
    # Define the file path
    file_path = os.path.join(domain, 'passive_recon.json')

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return

    # Read the JSON file

    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except json.JSONDecodeError as e:
        print(f"Error reading JSON file {file_path}: {e}")
        return

def print_recon_data(data):
    if not data:
        print("No data to display.")
        return

    # Print the contents of the JSON file
    print(json.dumps(data, indent=2))

if __name__ == "__main__":
    domain = input("Enter the domain: ")
    recon_data = read_passive_recon(domain)
    print_recon_data(recon_data)
