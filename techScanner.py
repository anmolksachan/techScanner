import os
import datetime
import json
import sys
import warnings
from wappalyzer import Wappalyzer, WebPage
import requests
from urllib.parse import urlencode
from tabulate import tabulate
from termcolor import colored
import csv
import argparse

def print_banner():
    """Prints the ASCII art banner for the tool."""
    banner = r"""
  _          _    ___                            
 | |_ ___ __| |_ / __| __ __ _ _ _  _ _  ___ _ _ 
 |  _/ -_) _| ' \\__ \/ _/ _` | ' \| ' \/ -_) '_|
  \__\___\__|_||_|___/\__\__,_|_||_|_||_\___|_|  
                                                 
    Asset Technology Scanner v1.0
    Author: Anmol K Sachan @FR13ND0x7F
    Description: A tool to scan assets for technologies using WhatRuns and Wappalyzer APIs.
    """
    print(colored(banner, "cyan"))

def get_whatruns_technologies(domain):
    """Fetches technologies using the WhatRuns API."""
    url = "https://www.whatruns.com/api/v1/get_site_apps"
    data = {"data": {"hostname": domain, "url": domain, "rawhostname": domain}}
    data = urlencode({k: json.dumps(v) for k, v in data.items()})
    data = data.replace('+', '')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        loaded = json.loads(response.content)
        apps = json.loads(loaded.get('apps', '{}'))
    except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
        print(colored(f"[!] WhatRuns API Error for {domain}: {e}", "red"))
        return []
    if not apps:
        print(colored(f"[*] No applications detected via WhatRuns for {domain}.", "yellow"))
        return []
    entries = []
    for nuance in apps:
        for app_type, values in apps[nuance].items():
            for item in values:
                dt = datetime.datetime.fromtimestamp(item['detectedTime'] / 1000)
                ldt = datetime.datetime.fromtimestamp(item['latestDetectedTime'] / 1000)
                entries.append({
                    'Asset': domain,
                    'Source': 'WhatRuns',
                    'Type': app_type,
                    'Name': item['name'],
                    'Detected': dt,
                    'Last_Detected': ldt,
                    'Version': 'N/A'  # Add Version field for consistency
                })
    return entries

def get_wappalyzer_technologies(domain):
    """Uses the Wappalyzer Python library to detect technologies."""
    # Suppress warnings from Wappalyzer
    warnings.filterwarnings("ignore", category=UserWarning)
    # Try both HTTP and HTTPS
    protocols = ["http", "https"]
    for protocol in protocols:
        url = f"{protocol}://{domain}"
        try:
            webpage = WebPage.new_from_url(url, verify=False)
            wappalyzer = Wappalyzer.latest()
            techs = wappalyzer.analyze_with_versions_and_categories(webpage)
            break  # Stop if successful
        except Exception as e:
            if protocol == "https":
                print(colored(f"[!] Error analyzing technologies for {domain}: {e}", "red"))
                return []
    entries = []
    for tech, details in techs.items():
        categories = details.get('categories', [])
        versions = details.get('versions', [])
        category_names = ', '.join(categories) if categories else "Unknown"
        version_info = ', '.join(versions) if versions else "N/A"
        entries.append({
            'Asset': domain,
            'Source': 'Wappalyzer',
            'Type': category_names,
            'Name': tech,
            'Detected': 'N/A',
            'Last_Detected': 'N/A',
            'Version': version_info
        })
    return entries

def save_to_csv(data, filename):
    """Saves the results to a CSV file."""
    # Define all possible fieldnames
    fieldnames = ['Asset', 'Source', 'Type', 'Name', 'Detected', 'Last_Detected', 'Version']
    # Ensure all entries have all fieldnames, filling missing keys with 'N/A'
    for entry in data:
        for field in fieldnames:
            entry.setdefault(field, 'N/A')
    # Create scandata folder if it doesn't exist
    os.makedirs('scandata', exist_ok=True)
    filepath = os.path.join('scandata', filename)
    # Write to CSV
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def main():
    # Print the banner
    print_banner()

    parser = argparse.ArgumentParser(description="Scan assets for technologies.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', help="Path to the file containing assets (one per line).")
    group.add_argument('--asset', help="Single asset to scan.")
    parser.add_argument('--wf', required=True, help="Filename to save the scan results (CSV format).")
    args = parser.parse_args()

    assets = []
    if args.file:
        # Read assets from the file
        try:
            with open(args.file, 'r') as f:
                assets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(colored(f"[!] File not found: {args.file}", "red"))
            sys.exit(1)
        if not assets:
            print(colored("[!] No assets found in the file.", "yellow"))
            sys.exit(1)
    elif args.asset:
        # Use the single asset provided
        assets = [args.asset]

    print(colored(f"[*] Scanning {len(assets)} assets...", "green"))

    all_data = []
    for asset in assets:
        print(colored(f"\n[*] Scanning {asset} with WhatRuns & Wappalyzer...\n", "green"))
        # Fetch technologies from WhatRuns
        whatruns_data = get_whatruns_technologies(asset)
        # Fetch technologies from Wappalyzer
        wappalyzer_data = get_wappalyzer_technologies(asset)
        # Combine results
        all_data.extend(whatruns_data + wappalyzer_data)

    if all_data:
        print(tabulate(all_data, headers='keys'))
        # Save results to CSV
        save_to_csv(all_data, args.wf)
        print(colored(f"\n[*] Results saved to scandata/{args.wf}", "green"))
    else:
        print(colored("[*] No technologies detected.", "yellow"))

if __name__ == "__main__":
    main()
