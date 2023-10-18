import requests
import sys
import time

from termcolor import colored

#import custom modules
import tools
from data import settings
from .engine import Engine

class APIVoid(Engine):
    def __init__(self):
        Engine.__init__(self)

        self.category_data = []
        self.detections_number = 0
        self.error = False
        self.no_IP = False
        self.credit_finished = False

        self.apivoid_key = tools.get_config_entry('ApivoidAPIKey')

    def get_data(self, domain):
        # Get domain categories
        self.api_url = f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={self.apivoid_key}&host={domain}"

        print("[AV]", end = " ")

        #return to disable the real check
        return

        # Make API query and sleep/retry if status != 200
        retry = 0
        while retry < settings.apivoid_retry:
            self.response = requests.get(self.api_url)
            self.status_code = self.response.status_code
            self.data = self.response.json()

            try:
                self.report = self.data['data']['report']
                self.server = self.report['server']
            except KeyError:
                print(self.data)
                try:
                    self.error_message = self.data['error']
                    if self.error_message == 'You have 0 credits remained':
                        self.credit_finished = True
                        break
                except:
                    break

            if self.status_code == 200 and not self.credit_finished :
                if self.server['ip'] != "":
                    break
                else:
                    time.sleep(1)
                    retry +=1

        self.risk_score = 'N/A'
        

    def check(self, domain):
        # Get domain categories
        self.get_data(domain)

        if not self.credit_finished:
            try:
                self.report = self.data['data']['report']
                self.blacklists = self.report['blacklists']
                self.server = self.report['server']
                self.detections_number = self.blacklists['detections']
                self.engines = self.blacklists['engines']
                self.risk_score = self.report['risk_score']['result']

                for e in self.engines.keys():
                    engine = self.engines[e]['engine']
                    detected = self.engines[e]['detected']
                    if detected:
                        self.detections.append(engine)
            except:
                self.error = True
                print(colored('Error!', 'red'))
                return #we stop the function

            if self.server['ip'] == "":
                self.no_IP = True

            if self.status_code == 200:
                if self.detections_number:
                    print(colored(f'Detections: {self.detections}', 'red'), end=' ')
                    self.dangerous = True
                else:
                    print(colored('Safe', 'green'), self.data['credits_remained'], end = " ")

            else:
                self.error = True
                str = "Error!", str(self.status_code), self.status_description[self.status_code]
                print(colored(self.server['ip'], 'yellow'),'OK',end = " ")
        else:
            print(colored(self.error_message,'red'), end=" ")
        self.calculate_score()
        sys.stdout.flush()

if __name__ == "__main__":
    if len(sys.argv) == 2:

        import pprint

        d = sys.argv[1]
        print('checking',d)
        apivoid = APIVoid()
        apivoid.get_data(d)
        pprint.pprint(apivoid.data)