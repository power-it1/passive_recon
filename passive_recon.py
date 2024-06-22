import subprocess
import re
import yaml
import json
import argparse
import os
from tqdm import tqdm


def load_config(config_file):
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

def perform_whois(domain):
    command = ['whois', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running whois for domain: {domain}")
        print(result.stderr)
        return {}
    return {"whois_data": result.stdout}

def google_dork(domain):
    command = ['oxdork', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running oxdork for domain: {domain}")
        print(result.stderr)
        return []
    return result.stdout.splitlines()

def internetdb_query(ip):
    command = ['curl', f'https://internetdb.shodan.io/{ip}']
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error querying InternetDB for IP: {ip}")
        print(result.stderr)
        return {}
    return json.loads(result.stdout)

def run_dnsrecon(domain):
    command = ['dnsrecon', '-d', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running dnsrecon for domain: {domain}")
        print(result.stderr)
        return {}
    return result.stdout

def main():
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
    config = load_config(config_file)
    sources = config.get('sources', [])

    for target in targets:
        subdomains = set()
        ipv4 = set()
        ipv6 = set()
        asns = set()
        emails = set()

        print(f'Working on target: {target}')
        subdomain_regex = rf'[\w\.\*-]+\.{re.escape(target)}'
        a_record_regex = re.compile(r'([a-zA-Z0-9.-]+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        with tqdm(total=len(sources), desc='Sources') as pbar:
            for source in sources:
                command = ['theHarvester', '-d', target, '-b', source]
                result = subprocess.run(command, capture_output=True, text=True)

                if result.returncode != 0:
                    print(f"Error running theHarvester for source: {source}")
                    print(result.stderr)
                    continue

                found_subdomains = re.findall(subdomain_regex, result.stdout)
                found_ipv4 = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result.stdout)
                found_ipv6 = re.findall(r'\b((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6}))|(:((:[0-9A-Fa-f]{1,4}){1,7}|:))|(::([0-9A-Fa-f]{1,4}){0,7}(:[0-9A-Fa-f]{1,4}){0,1})|(::([0-9A-Fa-f]{1,4}){0,6}(:[0-9A-Fa-f]{1,4}){0,2})|(::([0-9A-Fa-f]{1,4}){0,5}(:[0-9A-Fa-f]{1,4}){0,3})|(::([0-9A-Fa-f]{1,4}){0,4}(:[0-9A-Fa-f]{1,4}){0,4})|(::([0-9A-Fa-f]{1,4}){0,3}(:[0-9A-Fa-f]{1,4}){0,5})|(::([0-9A-Fa-f]{1,4}){0,2}(:[0-9A-Fa-f]{1,4}){0,6})|(::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,7})|(::))\b', result.stdout)
                found_asn = re.findall(r'AS\d{1,10}', result.stdout)
                found_email = re.findall(r'(?!(?:^|[^@\w.])cmartorella@edge-security\.com\b)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', result.stdout)

                subdomains.update(found_subdomains)
                ipv4.update(found_ipv4)
                ipv6.update(found_ipv6)
                asns.update(found_asn)
                emails.update(found_email)

                for match in a_record_regex.findall(result.stdout):
                    subdomains.add(match[0])
                    ipv4.add(match[1])

                pbar.update(1)

        whois_info = perform_whois(target)

        google_dork_results = google_dork(target)

        internetdb_results = []
        with tqdm(total=len(ipv4), desc='InternetDB Queries') as pbar:
            for ip in ipv4:
                internetdb_results.append(internetdb_query(ip))
                pbar.update(1)

        dnsrecon_output = run_dnsrecon(target)

        output_data = {
            "subdomains": list(subdomains),
            "ipv4_addresses": list(ipv4),
            "ipv6_addresses": list(ipv6),
            "asns": list(asns),
            "emails": list(emails),
            "whois_info": whois_info,
            "google_dork_results": google_dork_results,
            "internetdb_results": internetdb_results,
            "dnsrecon_output": dnsrecon_output
        }

        # Create directory for the target
        os.makedirs(target, exist_ok=True)
        output_file = os.path.join(target, "passive_recon.json")

        with open(output_file, "w") as json_file:
            json.dump(output_data, json_file, indent=2)

        total_subdomains = len(subdomains)
        print(f"\nSubdomains for {target}: {total_subdomains}")
        total_ipv4 = len(ipv4)
        print(f"\nIPv4 Addresses for {target}: {total_ipv4}")
        total_ipv6 = len(ipv6)
        print(f"\nIPv6 Addresses for {target}: {total_ipv6}")
        total_asn = len(asns)
        print(f"\nASN for {target}: {total_asn}")
        total_email = len(emails)
        print(f"\nEmails for {target}: {total_email}")

if __name__ == "__main__":
    main()
