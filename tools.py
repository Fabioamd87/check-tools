import os
import json
import dns.resolver
import keyring
import requests

#from azure.keyvault.secrets import SecretClient
#from azure.identity import DefaultAzureCredential

from urllib.parse import urlparse
from termcolor import colored
from data import settings

CONFIG_FILE = 'data/config.json'

def get_secret(key):
    #Get password from Windows Keyring
    secret = keyring.get_password(f'CheckTools-{key}',key)
    if not secret:
        #Get password from Azure Key Vault
        keyVaultName = ""
        KVUri = f"https://{keyVaultName}.vault.azure.net"
        credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        client = SecretClient(vault_url=KVUri, credential=credential)
        secret =  client.get_secret(key).value
        if secret:
            keyring.set_password(f'CheckTools-{key}', key, secret)
    return secret

#given an URL we extract the domain
def get_domain(url):
    domain = urlparse(url).netloc
    try:
        if domain == "":
            domain = urlparse(url).path
        if "/" in domain:
            domain = domain.split("/")[0]
        if len(domain) == 0:
            print("[tools.py] Error parsing url: ", url)
            return False
        else:
            return domain
    except TypeError:
        return False

#check if a domain is valid
def domain_valid(domain):
       
    #check if a domain resolve to an IP address
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8']
    try:
        my_resolver.resolve(domain)
        return True
    except:
        return False
    
#Get the key from config json file
def get_config_entry(key):
    if os.path.exists(CONFIG_FILE) and os.path.getsize(CONFIG_FILE) > 0:
        with open(CONFIG_FILE) as json_data_file:
            config = json.load(json_data_file)
            if key in config:
                value = config[key]
            else:
                value = False
        json_data_file.close()
    else:
        value = False
    return value

#Storing the key to config json file
def set_config_entry(entry):
    if os.path.exists(CONFIG_FILE) and os.path.getsize(CONFIG_FILE) > 0:
        with open(CONFIG_FILE) as json_data_file:
            data = json.load(json_data_file)
        json_data_file.close()
        data.update(entry)
        with open(CONFIG_FILE, 'w') as json_data_file:
            json.dump(data, json_data_file, indent=4)
        json_data_file.close()
    else:
        with open(CONFIG_FILE, "w") as outfile:
            json.dump(entry, outfile)
        outfile.close()