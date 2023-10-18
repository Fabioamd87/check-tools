#!/usr/bin/env-python3
import os
import sys
import tools

from platform import python_version

from packaging import version

#from services.webshrinker import Webshrinker
from services.virustotal import VirusTotal
from services.apivoid import APIVoid

from tools import get_domain, domain_valid, get_config_entry, set_config_entry

from termcolor import colored

#Loading all the static variables
DEFAULT_URLS_FILE_PATH = 'data/URLs.txt'

#Autofilling config file
SAFETY_TRASHOLD = get_config_entry("SafetyThreshold")
if not SAFETY_TRASHOLD:
    set_config_entry({'SafetyThreshold': 4})
    SAFETY_TRASHOLD = 4

def check_domain(domain, vt=None, av=None):
    #We check a single domain, print the output and calculate the score.
    safety_score = 0
    vt_score = None
    av_score = None
    ws_score = None

    #Virustotal
    if vt:
        vt_score = True
        vt.check(domain)
        safety_score = safety_score + vt.score

    #APIVoid
    if av:
        av_score = True
        av.check(domain)
        safety_score = safety_score + av.score
        
        #If the domain have no ip we skip the check to save API requests
        if av.error:
            #We return a 0 safety score, otherwise uncategorized script crash:
            #TypeError: '>' not supported between instances of 'NoneType' and 'int'
            return 0

    #Safety score calculation (av_score + ws_score + vt_score)
    if vt_score:
        print(f'VT:{vt.score}', end=' ')
    if av_score:
        print(f'AV:{av.score}', end=',')
    #if ws_score:
    #    print(f'WS:{ws.score}', end=',')

    print('tot:', end="")

    #print verditct
    if safety_score > SAFETY_TRASHOLD:
        print(colored(f'{safety_score} Legit ','green'))
    elif safety_score < 0:
        print(colored(f'{safety_score} Warning ','red'))
    else:
        print(safety_score)

    return safety_score

def analyze(path, vt, av):
    #for multiple line files:
    with open(path,'r') as urls:
        lines = urls.readlines()

    #removing duplicates
    n1= len(lines)
    lines = list(dict.fromkeys(lines))

    n2= len(lines)
    if (n1 - n2 > 0):
        print(f'removed {n1 - n2} duplicates')
    i=1

    try:
        for url in lines:
            url = url.rstrip("\n")
            domain = get_domain(url)
            if domain:
                print(str(i) + "/" + str(n2), domain)
                if domain_valid(domain):
                    check_domain(domain, vt, av)
                    for x in [vt, av]:
                        if x:
                            x.init()
                else:
                    print(colored('No IP','red'))
            i+=1
    except KeyboardInterrupt:
        "aborting..."
        sys.exit(2)

def validate(url):
    #validate input domain, in case we receive a file instead of a domain
    if '.txt' in url:
        print('WARNING: To scan a file digit check_urls.py -f filename')
        sys.exit(2)

if __name__ == "__main__":
    if len(sys.argv) > 3:
        #wrong usage message
        print("usage:\ncheck_urls.py -f <file>\ncheck_urls.py <url>")
        sys.exit(2)
    else:
        #loading the engines
        vt = VirusTotal()
        av = APIVoid()        
        #ws = Webshrinker()

        if len(sys.argv) == 1:
            #Check if files exists
            if os.path.isfile(DEFAULT_URLS_FILE_PATH):
                analyze(DEFAULT_URLS_FILE_PATH, vt, av)
        elif len(sys.argv) == 2:
            #reading single URL
            url = sys.argv[1]
            validate(url)
            domain = get_domain(url)
            if domain:
                if domain_valid(domain):
                    print(domain)
                    check_domain(domain, vt, av)
                else:
                    print(colored('No IP','red'))
        else:
            match sys.argv[1]:
                case '-f':
                    #reading custom file
                    request = sys.argv[2]
                    analyze(request, vt, av)
                #using a single engine
                case 'virustotal':
                    import pprint

                    d = sys.argv[2]
                    print('checking',d)
                    virustotal = VirusTotal()
                    virustotal.get_data(d)
                    pprint.pprint(virustotal.data)

                case 'apivoid':
                    import pprint

                    d = sys.argv[2]
                    print('checking',d)
                    apivoid = APIVoid()
                    apivoid.get_data(d)
                    pprint.pprint(apivoid.data)

                case 'webshrinker':
                    import pprint

                    d = sys.argv[2]
                    print('checking',d)
                    webshrinker = Webshrinker()
                    webshrinker.get_data(d)
                    pprint.pprint(webshrinker.data)