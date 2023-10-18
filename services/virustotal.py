import requests
import json
import re
import sys
import os
import time

from termcolor import colored
from services.engine import Engine
from data import settings
import tools

CONFIG_FILE = 'data/config.json'

class VirusTotal(Engine):
    def __init__(self):
        Engine.__init__(self)
        #reading virustotal key from config files
        self.userID = tools.get_config_entry('VirusTotalAPIKey')
        if self.userID:
            self.set_api_key(self.userID)
        else:
            #if the key is not set in config file, read secops key from Azure Keyvault
            self.get_key()

    def set_api_key(self, key):
        self.virustotal_key = key

    def get_key(self):
        print('Reading SecOps VirusTotal API key from keyvault, PLEASE CONFIGURE YOUR API KEY')
        if sys.platform == 'win32':
            self.virustotal_key = self.get_secret('virustotal-key')
        else:
            from linux_tools import load_keys
            load_keys()
            self.virustotal_key = os.environ.get('VIRUSTOTAL-KEY')

    def get_data(self, domain):
        # HTTP headers to query VT API
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "x-apikey": self.virustotal_key
        }
        
        # Handle the domain can be an IP or a Domain
        entry_type = ""
        if re.findall("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", domain):
            entry_type = "ip_addresses"
        else:
            entry_type = "domains"

        # Make API query and sleep/retry if status != 200
        retry = 0

        while retry < settings.virustotal_retry:
            self.response = requests.get("https://www.virustotal.com/api/v3/%s/%s" % (entry_type, domain), headers=headers)
            self.status_code = self.response.status_code
            if self.status_code == 200:
                break
            else:
                if self.status_code != 404:
                    print("[VirusTotal] HTTP ERROR, retry ... (domain='%s' status=%d, text=%s)" % (domain, self.status_code, self.response.text), end = "")
                retry += 1
                time.sleep(settings.virustotal_throttling)

        self.data = self.response.json()
    
    def check(self, domain):
        print("[VT]", end=" ")
        self.get_data(domain)
        self.categories_whitelisted = []

        # If after retrying, still an error, give up and print error
        if self.status_code != 200:
            print(colored(f"ERROR {str(self.status_code)}", 'yellow'), end=", ")
            return

        try:
            resp_json = json.loads(self.response.text)
        except:
            print(f"Failed to parse the response (domain={domain}, response={self.response.text})", end = "")
        
        # Catch VT Error messages
        if "error" in resp_json:
            error_message = resp_json["error"]["message"]
            print(f"Error in response (domain={domain}, error={error_message})", end = "")
            return
        
        # Get the VT result stats
        stats = None
        try:
            stats = resp_json["data"]["attributes"]["last_analysis_stats"]
        except Exception as e:
            print(f"Exception (domain={domain}, exception={e})", end = "")

        for cat in resp_json["data"]["attributes"]["categories"].values():
            if ',' in cat:
                cat = cat.split(',')
                for c in cat:
                    self.categories.append(c)
            else:
                self.categories.append(cat)

        # Check for malicious/suspicious
        if stats['malicious'] == 0 and stats['suspicious'] == 0:
            self.dangerous = False
        else:
            for engine in resp_json["data"]["attributes"]["last_analysis_results"]:
                result = resp_json["data"]["attributes"]["last_analysis_results"][engine]["category"]
                if result == "malicious" or result == "suspicious":
                    self.detections.append(engine)
            self.dangerous = True

        # Check for blacklisted categories
        for entry in self.categories:
            if (entry.lower() in settings.virustotal_category_whitelist):
                self.categories_whitelisted.append(entry)
            else:
                self.categories_blacklisted.append(entry)
                self.legit = False

        # Print results
        if self.legit:
            if not self.dangerous:
                #categories ok and not malicious
                print(colored('Safe', 'green'), end = ", ")
            else:
                #categories ok but malicious
                print(colored(f"Detections: {self.detections}",'red'), end=", ")
            if len(self.categories) == 0:
                #no categories
                print(colored('No Categories', 'yellow'), end=" ")
            else:
                #categories > 0
                print(colored(f"({str(len(self.categories_whitelisted))} Categories OK)",'green'), end=" ")
        else:
            #example winzir.ph
            if self.dangerous:
                print(colored(f"Detections: {self.detections}",'red'), end=", ")
            print(colored(f"{str(len(self.categories_blacklisted))}/{str(len(self.categories))}:",'red'), colored(self.categories_blacklisted, 'red'), end=", ")

        self.calculate_score()
        sys.stdout.flush()

if __name__ == "__main__":
    if len(sys.argv) == 2:

        import pprint

        #adding this line to fix import if run directly
        sys.path.append(".")
        d = sys.argv[1]
        print('checking',d)
        virustotal = VirusTotal()
        virustotal.get_data(d)
        pprint.pprint(virustotal.data)