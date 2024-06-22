# Passive Recon

This tool receives a domain or a list of domains in json and performs an automated search and parse of theHarvester and generates a json file with basic Attack Surface: Emails, Subdomains, ASN's, IPv4 addresses, IPv6 addresses, and vulnerabilities (to be added). 
The results are saved on {domain.com} directory. 
While there are many tools that obtain entries from sources in an automated way, theHarvester was chosen because new modules can be added easily. The output of such modules will still be parsed and aggregated by this tool.  

# DNS server probing as OSINT. 

While technically probing the DNS servers directly is considered active, basic probing for nameservers and records is still a legitimate use case. 
DNS attacks will be covered on another module

# Usage 

- Create a virtual environment with the requirements 
- python3 passive_recon.py --target {domain | domains.json}

# Issues 

- IPv6 is not parsed correctly


To be added:
- Iterate the IP list over [internet.db ](https://internetdb.shodan.io)
- Google dorking.
- DNS handling: determine nameservers and obtain all record types. DNS Sources might need to be parsed differently.     
- Perform whois query. 
- Proxy support, being able to perform the entire queries and DNS querying from another server and retrieving the results. 