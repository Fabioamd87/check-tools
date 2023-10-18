import requests
import sys
import os
from base64 import urlsafe_b64encode

from termcolor import colored

from .engine import Engine

sys.path.append("..")
from data import settings

class Webshrinker(Engine):
    def __init__(self):
        Engine.__init__(self)

        if sys.platform == 'win32':
            self.webshrinker_api_key = self.get_secret('webshrinker-api-key')
            self.webshrinker_api_secret = self.get_secret('webshrinker-api-secret')
        else:
            from linux_tools import load_keys
            load_keys()
            self.webshrinker_api_key = os.environ.get('WEBSHRINKER_API_KEY')
            self.webshrinker_api_secret = os.environ.get('WEBSHRINKER_API_SECRET')

    def get_all_categories(self):
        self.api_url = "https://api.webshrinker.com/categories/v3"
        self.response = requests.get(self.api_url, auth=(self.webshrinker_api_key, self.webshrinker_api_secret))
        self.status_code = self.response.status_code
        self.data = self.response.json()

    def get_data(self, domain):
        # Get domain categories
        self.api_url = "https://api.webshrinker.com/categories/v3/%s" % urlsafe_b64encode(domain.encode()).decode('utf-8')
        self.response = requests.get(self.api_url, auth=(self.webshrinker_api_key, self.webshrinker_api_secret))
        self.status_code = self.response.status_code
        self.data = self.response.json()

    def check(self, domain):
        print("[WS]", end = " ")
        #calling webshrinker API
        self.get_data(domain)

        if 'result' in locals():
            print('result already exist')
            
        if "error" in self.data:
            print(self.data)

        entry = {"label" : ""} # in case of not 200 response code

        if self.status_code == 200:
            try:
                self.categories = self.data['data'][0]['categories']
            except:
                self.categories = []
                self.legit = False

            for entry in self.categories:
                if entry["id"] in settings.webshrinker_categories_blacklist:
                    self.categories_blacklisted.append(entry["label"])
                    self.legit = False
                else:
                    self.categories_whitelisted.append(entry["label"])

        elif self.status_code == 202:
            print(colored('Categorizing','yellow'), end=" ")
            sys.stdout.flush()
            return
        else:
            print('status code: ', self.status_code, end ="")
            self.legit = False

        if self.legit:
            if len(self.categories_whitelisted) > 0:
                print(colored(f"({str(len(self.categories_whitelisted))} Categories OK)",'green'), end =" ")
            else:
                print(colored('No Categories', 'yellow'), end = " ")
        else:
            print(colored(f"{str(len(self.categories_blacklisted))}/{str(len(self.categories))}",'red'), end=": ")
            print(colored(self.categories_blacklisted,'red'), end=" ")

        self.calculate_score()
        sys.stdout.flush()

    def check_verbose(self, domain):
        # Get domain categories
        api_url = "https://api.webshrinker.com/categories/v3/%s" % urlsafe_b64encode(domain.encode()).decode('utf-8')
        response = requests.get(api_url, auth=(settings.webshrinker_api_key, settings.webshrinker_api_secret))
        status_code = response.status_code
        data = response.json()
        if "error" in data:
            print(data)
        entry = {"label" : ""} # in case of not 200 response code
        if status_code == 200:
            print(data)
            self.categories = data['data'][0]['categories']
        else:
            print("[Webshrinker] error : %s" % status_code)

if __name__ == "__main__":
    if len(sys.argv) == 2:

        import pprint

        d = sys.argv[1]
        print('checking ',d)
        webshrinker = Webshrinker()
        webshrinker.get_data(d)
        pprint.pprint(webshrinker.data)
    
    if len(sys.argv) == 1:

        import pprint

        print('getting all categories')
        webshrinker = Webshrinker()
        webshrinker.get_all_categories()
        pprint.pprint(webshrinker.data)