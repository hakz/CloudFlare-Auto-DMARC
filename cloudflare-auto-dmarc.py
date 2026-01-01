#!/usr/bin/env python3

##########################
#   Administrative Data  #
##########################
__title__       = "CloudFlare Auto DMARC"
__description__ = "Quickly check and update your DMARC and SPF records on thousands of parked domains."
__author__      = "Robert G. Jamison"
__copyright__   = "Copyright 2026"

__license__     = '''"MIT License" - Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'''
__version__     = "0.0.1"
__status__      = "Testing"

##########################
#        LIBRARIES       #
##########################

import csv
import getopt
import os
import requests
import re
import sys

# TODO: Add technique for detecting DKIM

##########################
#         CLASSES        #
##########################
class Demarcator:
    def __init__(self, autofix, file, api_token, vuln_only):
        # set class variables
        self.width = os.get_terminal_size()[0]
        self.autofix = autofix
        self.output_file = file or "dmarc_audit_report.csv"
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.zones = []
        self.domains = []
        self.vulnerable_domains = []

        # Begin logic
        self.get_all_zones()
        self.audit_records(autofix)
        if file != None:
            self.write_to_csv(vuln_only)

    def msg(self, message):
        print()
        print("=" * self.width)
        print(message)
        print("=" * self.width)
        print()
        return

    def get_all_zones(self):
        """Fetches a list of all zones (domains) in the account, handling pagination."""
        page = 1
        print("Fetching domain list...", end="", flush=True)

        while True:
            try:
                response = requests.get(
                    f"{self.base_url}/zones",
                    headers = self.headers,
                    params = {"per_page": 50, "page": page}
                )
                response.raise_for_status()
                data = response.json()

                if not data['success']:
                    print(f"\nError fetching zones: {data['errors']}")
                    sys.exit(1)

                current_batch = data['result']
                if not current_batch:
                    break

                self.zones.extend(current_batch)
                print(".", end="", flush=True)
                page += 1

            except requests.exceptions.RequestException as e:
                print(f"\nAPI Connection Error: {e}")
                sys.exit(1)

        self.msg(f"Found {len(self.zones)} domains.")

    def write_new_dns_record(self, zone_id, payload):
        url = f"{self.base_url}/zones/{zone_id}/dns_records"
        response = requests.post(url, headers=self.headers, json=payload)
        # Check for success
        if response.status_code in [200, 201]:
            return "Created"
        else:
            return "Failure"

    def update_existing_dns_record(self, zone_id, record_id, payload):
        url = f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}"
        # PUT replaces the entire record
        response = requests.put(url, headers=self.headers, json=payload)
        # Check for success
        if response.status_code in [200, 201]:
            return "Updated"
        else:
            return "Failure"

    def get_dmarc_record(self, zone_id, zone_name):
        """Fetches the _dmarc TXT record for a specific zone."""
        try:
            # DMARC records are always at _dmarc.yourdomain.com
            dmarc_name = f"_dmarc.{zone_name}"
            response = requests.get(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                headers = self.headers,
                params = {"type": "TXT", "name": dmarc_name}
            )
            response.raise_for_status()
            records = response.json()['result']

            # Look for the record starting with v=DMARC1
            for record in records:
                content = record['content']
                if "v=DMARC1" in content.strip():
                    return content, record['id']
            return None, None
        except Exception as e:
            return f"Error: {str(e)}"

    def parse_dmarc_policy(self, dmarc_content):
        """Extracts the 'p=' value from the DMARC string."""
        if not dmarc_content:
            return "MISSING"

        # regex to find p=value; or p=value (end of string)
        match = re.search(r"p\s*=\s*([a-zA-Z0-9]+)", dmarc_content)
        if match:
            return match.group(1).lower()
        return "UNKNOWN"

    def fix_dmarc_record(self, zone_id, zone_name, dmarc_policy, dmarc_content, record_id):
        """
        Creates a new _dmarc record or updates an existing one.
        """
        record_name = "_dmarc"
        full_record_name = f"_dmarc.{zone_name}"

        try:
            if dmarc_policy == "MISSING":
                # sign up for DMARC Analytics with CloudFlare
                payload = {
                    "type": "TXT",
                    "name": record_name,
                    "content": "v=DMARC1; p=reject;",
                    "ttl": 3600,  # 1 hour TTL
                    "comment": "Created via Hakz DMARC Audit Script"
                }

                return self.write_new_dns_record(zone_id, payload)

            elif dmarc_policy == "quarantine" or dmarc_policy == "none":
                # modify the existing record to "reject"
                if record_id != None:
                    payload = {
                        "type": "TXT",
                        "name": record_name,
                        "content": dmarc_content.replace("p=quarantine", "p=reject").replace("p=none", "p=reject"),
                        "ttl": 3600,  # 1 hour TTL
                        "comment": "Updated via Hakz DMARC Audit Script"
                    }
                    return "DMARC: " + self.update_existing_dns_record(zone_id, record_id, payload)
                else:
                    return "DMARC: Error - Record ID Missing"
            else:
                return f"DMARC: No Change"
        except Exception as e:
            return f"DMARC: Error - {str(e)}"

    def get_spf_record(self, zone_id, zone_name):
        """Fetches the _spf TXT record for a specific zone."""
        try:
            spf_name = f"{zone_name}"
            response = requests.get(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                headers = self.headers,
                params = {"type": "TXT", "name": spf_name}
            )
            response.raise_for_status()
            records = response.json()['result']

            # Look for the record starting with v=spf1
            for record in records:
                content = record['content']
                if "v=spf1" in content.strip():
                    return content, record["id"]
            return None, None
        except Exception as e:
            return f"Error: {str(e)}", None

    def parse_spf_policy(self, spf_content):
        """Extracts the 'p=' value from the DMARC string."""
        if not spf_content:
            return "MISSING"
        # regex to find p=value; or p=value (end of string)
        match = re.search(r"include*:*([a-zA-Z0-9]+)", spf_content)
        if match and "-all" in spf_content:
            return "reject"
        if match and "~all" in spf_content:
            return "quarantine"
        if match and "+all" in spf_content:
            return "allow"
        return "UNKNOWN"

    def fix_spf_record(self, zone_id, zone_name, spf_policy, spf_content, record_id):
        """
        Creates a new spf record or updates an existing one.
        """
        try:
            if spf_policy == "quarantine" or spf_policy == "allow":
                # modify the existing record to "reject"
                if record_id != None:
                    payload = {
                        "type": "TXT",
                        "name": zone_name,
                        "content": spf_content.replace(" +all", " -all").replace(" ~all", " -all"),
                        "ttl": 3600,  # 1 hour TTL
                        "comment": "Updated via Hakz DMARC Audit Script"
                    }
                    return self.update_existing_dns_record(zone_id, record_id, payload)
                else:
                    return "SPF: Error - Record ID missing"
            else:
                return "SPF: No Change"
        except Exception as e:
            return f"SPF: Error - {str(e)}"

    def audit_records(self, autofix=False):
        self.msg("Auditing DMARC, SPF, and DKIM Records")

        print(f"{'DOMAIN':<30} | {'DMARC Policy':<16} | {'SPF Policy':<16} | {'DMARC Status':<20} | {'SPF Status':<20}")
        print("-" * self.width)

        for zone in self.zones:
            name = zone['name']
            zone_id = zone['id']
            dmarc_result = None
            spf_result = None

            dmarc_content, dmarc_record_id = self.get_dmarc_record(zone_id, name)
            dmarc_policy= self.parse_dmarc_policy(dmarc_content)
            if autofix and dmarc_policy != "reject":
                dmarc_result = self.fix_dmarc_record(zone_id, name, dmarc_policy, dmarc_content, dmarc_record_id)

            spf_content, spf_record_id = self.get_spf_record(zone_id, name)
            spf_policy = self.parse_spf_policy(spf_content)
            if autofix and (spf_policy != "reject" or spf_policy != "MISSING"):
                spf_result = self.fix_spf_record(zone_id, name, spf_policy, spf_content, spf_record_id)

            domain = {
                "name": name,
                "dmarc status": dmarc_policy,
                "spf status": spf_policy,
                "dmarc record": dmarc_content or "No Record Found",
                "spf record": spf_content or "No Record Found",
                "dmarc result": dmarc_result or "DMARC: No Change",
                "spf result": spf_result or "SPF: No Change"
            }

            self.domains.append(domain)

            # Logic: We want to flag anything that is NOT 'reject'
            if dmarc_policy != "reject" or (spf_policy != "reject" and spf_policy != "MISSING"):
                self.vulnerable_domains.append(domain)

            # Print as we go so you see progress
            print(f"{name:<30} | {dmarc_policy.upper():<16} | {spf_policy.upper():<16} | {domain['dmarc result']:<20} | {domain['spf result']:<20}")

    def write_to_csv(self, vuln_only):
        self.msg(f"Writing to file '{self.output_file}'")

        # Open CSV file for writing
        with open(self.output_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            # Write Header Row
            writer.writerow(['Domain Name', 'DMARC Rule', 'SPF Rule', 'Raw DMARC Record', 'Raw SPF Record'])

            if vuln_only: domains = self.vulnerable_domains
            else: domains = self.domains

            for domain in domains:
                # Write row to CSV
                writer.writerow(
                    [
                        domain["name"],
                        domain["dmarc status"],
                        domain["spf status"],
                        domain["dmarc record"] or "No Record Found",
                        domain["spf record"] or "No Record Found"
                    ]
                )

            self.msg(f"DONE.\n{len(self.vulnerable_domains)} domains have DMARC or SPF misconfigured.\nCheck {self.output_file} for the full list.")

##########################
#       ENTRY POINT      #
##########################

def main(argv):
    """Don't forget to set your CLOUDFLARE_API_TOKEN env variable!!!"""
    auto = False # prevents autoupdates
    file = None
    api_token = None
    vuln_only = False
    orange = '\033[38;5;202m'
    reset = '\033[0m'

    banner_cloudflare = """
    ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ███████╗██╗      █████╗ ██████╗ ███████╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║█████╗  ██║     ███████║██████╔╝█████╗
    ██║     ██║     ██║   ██║██║   ██║██║  ██║██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝██║     ███████╗██║  ██║██║  ██║███████╗
    ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
"""
    banner_dmarc = """    █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███╗   ███╗ █████╗ ██████╗  ██████╗
    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔════╝
    ███████║██║   ██║   ██║   ██║   ██║    ██║  ██║██╔████╔██║███████║██████╔╝██║
    ██╔══██║██║   ██║   ██║   ██║   ██║    ██║  ██║██║╚██╔╝██║██╔══██║██╔══██╗██║
    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██████╔╝██║ ╚═╝ ██║██║  ██║██║  ██║╚██████╗
    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝

"""

    help  = "Usage:  " + sys.argv[0] + " [-a | -h | -v] [-e VARIABLE] [-t TOKEN] [-o FILE]"

    advanced_help  ="""
-a, --autofix

    Auto-secure DMARC records after the audit.

-e VARIABLE, --env=VARIABLE

    The environmental variable where you've stored your CloudFlare API Token.
    Don't forget to run 'export KEY=VALUE'!

-h, --help

    Get this help message.

-t TOKEN, --token=TOKEN

    Pass your CloudFlare API token as an argument before running

-o FILE, --output=FILE

    This is where you will save your CSV report.

-v, --vulnerable-only

    Output file will only include vulnerable domains in the results
"""

    try:
        # Define short and long options
        short_options = "hae:t:o:v"
        long_options = ["help", "autofix", "env=", "token=", "output=", "vulnerable-only"]
        opts, args = getopt.getopt(argv, short_options, long_options)
    except getopt.GetoptError:
        print(help)
        sys.exit(1)
    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            print(orange + banner_cloudflare + reset + banner_dmarc + help + advanced_help)
            sys.exit(0)
        elif opt in ('-a', '--autofix'):
            auto = True
        elif opt in ('-e', '--env'):
            try:
                api_token = os.environ[arg]
            except KeyError:
                print(f"Error: {arg} environment variable not set.")
                sys.exit(1)
        elif opt in ('-o', '--output'):
            file = arg
            if file[-4:] != ".csv":
                print("Error: output file must end in '.csv'")
                sys.exit(1)
        elif opt in ('-t', '--token'):
            api_token = arg
        elif opt in ('-v', '--vulnerable-only'):
            vuln_only = True

    if api_token == None:
        print("Error: You must provide a CloudFlare API Token using the '-e <token>' or '-k <token>' argument")
        sys.exit(1)

    Demarcator(auto, file, api_token, vuln_only)

if __name__ == "__main__":
    main(sys.argv[1:])