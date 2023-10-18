from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

import keyring

"""
#this class is a generic engine, and is eredited by other class as a template
#the main function are declared here
"""
class Engine:
    def __init__(self):
        self.init()

    def get_secret(self, key):
        #Get password from Windows Keyring
        secret = keyring.get_password(f'CheckTools-{key}',key)
        if not secret:
            #Get password from Azure Key Vault
            keyVaultName = "secopskeyvault01"
            KVUri = f"https://{keyVaultName}.vault.azure.net"
            credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
            client = SecretClient(vault_url=KVUri, credential=credential)
            secret =  client.get_secret(key).value
            if secret:
                #"caching" the key into Windows Keyring
                keyring.set_password(f'CheckTools-{key}', key, secret)
        return secret
    
    def calculate_score(self):
        #We give 10 points if no detection, or remove 10 point for every detection
        #Works for VirusTotal and Apivoid
        if not self.dangerous:
            self.score = 0
        else:
            self.score = -10 * len(self.detections)

        #if there are any categories whitelisted or blacklisted the score change.
        #Works for VirusTotal and WebShrinker
        self.score = self.score -5*(len(self.categories_blacklisted)) + len(self.categories_whitelisted)

    def init(self):
        #common parameters between various engine
        self.categories_whitelisted = []
        self.categories_blacklisted = []
        self.categories = []
        #by default the website is legit, if we find at least one blocked category we consider not legit
        self.detections = []
        self.legit = True 
        self.dangerous = False
        self.secret_name = False
        self.score = 0
        #used only by APIVoid subclass
        self.error = False
        self.no_IP = False