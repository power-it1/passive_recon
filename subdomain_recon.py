import os
import json
import argparse
import subprocess
import re
from tqdm import tqdm
import yaml
import asyncio

async def load_config(config_file):
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config
    except FileNotFoundError:
        print(f"Config file {config_file} not found.")
        exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML config file: {e}")
        exit(1)

async def perform_whois(domain):
    command = ['whois', domain]
    result = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = await result.communicate()
    if result.returncode != 0:
        return {}
    return {"whois_data": stdout.decode()}

async def run_dnsrecon(domain):
    command = ['dnsrecon', '-d', domain]
    result = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = await result.communicate()
    if result.returncode != 0:
        return {}
    
    dns_records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "CNAME": [],
        "TXT": [],
        "NS": [],
        "DNSSEC": False
    }
    
    # Regex patterns for each DNS record type
    a_pattern = re.compile(r'A\s+.*?\s+(\d+\.\d+\.\d+\.\d+)')
    aaaa_pattern = re.compile(r'AAAA\s+.*?\s+([a-fA-F0-9:]+)')
    mx_pattern = re.compile(r'MX\s+.*?\s+(\S+)')
    cname_pattern = re.compile(r'CNAME\s+.*?\s+(\S+)')
    txt_pattern = re.compile(r'TXT\s+.*?\s+\"(.*?)\"')
    ns_pattern = re.compile(r'NS\s+.*?\s+(\S+)')
    dnssec_pattern = re.compile(r'DNSSEC')

    for line in stdout.decode().splitlines():
        if a_pattern.search(line):
            dns_records["A"].append(a_pattern.search(line).group(1))
        elif aaaa_pattern.search(line):
            dns_records["AAAA"].append(aaaa_pattern.search(line).group(1))
        elif mx_pattern.search(line):
            dns_records["MX"].append(mx_pattern.search(line).group(1))
        elif cname_pattern.search(line):
            dns_records["CNAME"].append(cname_pattern.search(line).group(1))
        elif txt_pattern.search(line):
            dns_records["TXT"].append(txt_pattern.search(line).group(1))
        elif ns_pattern.search(line):
            dns_records["NS"].append(ns_pattern.search(line).group(1))
        elif dnssec_pattern.search(line):
            dns_records["DNSSEC"] = True

    return dns_records

async def fetch_sources(target, sources, pbar):
    subdomains = set()
    ipv4 = set()
    ipv6 = set()
    asns = set()
    emails = set()
    subdomain_regex = rf'[\w\.\*-]+\.{re.escape(target)}'
    ipv6_regex = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b')
    a_record_regex = re.compile(r'([a-zA-Z0-9.-]+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for source in sources:
        command = ['theHarvester', '-d', target, '-b', source]
        result = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = await result.communicate()

        if result.returncode != 0:
            continue

        stdout = re.sub(r'cmartorella@edge-security\.com', '', stdout.decode())

        found_subdomains = re.findall(subdomain_regex, stdout)
        found_ipv4 = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', stdout)
        found_ipv6 = ipv6_regex.findall(stdout)
        found_asn = re.findall(r'AS\d{1,10}', stdout)
        found_email = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', stdout)

        subdomains.update(found_subdomains)
        ipv4.update(found_ipv4)
        ipv6.update(found_ipv6)
        asns.update(found_asn)
        emails.update(found_email)

        for match in a_record_regex.findall(stdout):
            subdomains.add(match[0])
            ipv4.add(match[1])
        
        # Update the progress bar after each source is processed
        pbar.update(1)

    return subdomains, ipv4, ipv6, asns, emails

async def main():
    print("""
        \n

        ┏┓  ┓  ┓       •    ┳┓       
        ┗┓┓┏┣┓┏┫┏┓┏┳┓┏┓┓┏┓  ┣┫┏┓┏┏┓┏┓
        ┗┛┗┻┗┛┗┻┗┛┛┗┗┗┻┗┛┗  ┛┗┗ ┗┗┛┛┗                            
 +--^----------,--------,-----,--------^-,
 | |||||||||   `--------'     |          O
 `+---------------------------^----------|
   `\_,---------,---------,--------------'
     / XXXXXX /'|       /'
    / XXXXXX /  `\    /'
   / XXXXXX /`-------'
  / XXXXXX /
 / XXXXXX /
(________(                
 `------'             

    """)

    parser = argparse.ArgumentParser(description="Run theHarvester tool on target domains.")
    parser.add_argument('--target', '-t', type=str, help="Single target domain")
    parser.add_argument('--target_file', '-f', type=str, help="JSON file with a list of target domains")
    args = parser.parse_args()

    if args.target:
        targets = [args.target]
    elif args.target_file:
        try:
            with open(args.target_file, 'r') as file:
                targets = json.load(file)
        except FileNotFoundError:
            print(f"Target file {args.target_file} not found.")
            exit(1)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON target file: {e}")
            exit(1)
    else:
        print("You must provide a target domain or a target file.")
        exit(1)

    config_file = "config.yaml"
    config = await load_config(config_file)
    sources = config.get('sources', [])

    total_tasks = len(targets) * (len(sources) + 2)  # +2 for whois and dnsrecon per target

    with tqdm(total=total_tasks, desc='Working', ncols=100) as pbar:
        for target in targets:
            subdomains, ipv4, ipv6, asns, emails = await fetch_sources(target, sources, pbar)

            whois_info = await perform_whois(target)
            pbar.update(1)

            dnsrecon_output = await run_dnsrecon(target)
            pbar.update(1)

            output_data = {
                target: {
                    "subdomains": {
                        "wildcard": [],
                        "third_level_domain": [],
                        "multilevel": list(subdomains)  # Modify classification as needed
                    },
                    "ip_addresses": {
                        "ipv4": list(ipv4),
                        "ipv6": list(ipv6)
                    },
                    "dns": {
                        "nameservers": dnsrecon_output.get("NS", []),
                        "records": {
                            "A": dnsrecon_output.get("A", []),
                            "AAAA": dnsrecon_output.get("AAAA", []),
                            "MX": dnsrecon_output.get("MX", []),
                            "CNAME": dnsrecon_output.get("CNAME", []),
                            "TXT": dnsrecon_output.get("TXT", [])
                        },
                        "DNSSEC": dnsrecon_output.get("DNSSEC", False)
                    },
                    "emails": list(emails),
                    "properties": {
                        "whois_info": whois_info
                    }
                }
            }

            os.makedirs(target, exist_ok=True)
            output_file = os.path.join(target, 'subdomain_recon.json')

            with open(output_file, 'w') as json_file:
                json.dump(output_data, json_file, indent=2)

            print(f"Results saved in {output_file}")

    print("""
        \n

        ┏┓  ┓  ┓       •    ┳┓       
        ┗┓┓┏┣┓┏┫┏┓┏┳┓┏┓┓┏┓  ┣┫┏┓┏┏┓┏┓
        ┗┛┗┻┗┛┗┻┗┛┛┗┗┗┻┗┛┗  ┛┗┗ ┗┗┛┛┗                            
 +--^----------,--------,-----,--------^-,
 | |||||||||   `--------'     |          O_ _ _ _ _ _ _ _ _ _ _ _ _ 
 `+---------------------------^----------|               \XXXX0XXX/
   `\_,---------,---------,--------------'                \XXX1XX/
     / XXXXXX /'|       /'                                 \XX0X/     
    / XXXXXX /  `\    /'                                    \XX/                    
   / XXXXXX /`-------'                                       ''
  / XXXXXX /                                                 
 / XXXXXX /
(________(                
 `------'                   

    """)

if __name__ == "__main__":
    asyncio.run(main())
