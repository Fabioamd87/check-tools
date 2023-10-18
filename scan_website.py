import sys

from bs4 import BeautifulSoup
from urllib.request import Request, urlopen

from tools import get_domain, domain_valid

def scan(req):

    req = Request(
        url=req,
        headers={'User-Agent': 'Mozilla/5.0'}
    )

    html_page = urlopen(req)
    soup = BeautifulSoup(html_page, "lxml")

    #grabs all links
    links = []
    for link in soup.findAll('a'):
        links.append(link.get('href'))

    #convert to domains
    domains = []
    for l in links:
        domain = get_domain(l)
        if not domain_valid(domain):
            continue
        if domain not in domains:
            domains.append(domain)

    #writing domains to file
    url_file = open('data/domains.txt', 'w')
    for d in domains:
        url_file.write(d+'\n')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage : python scan_url.py <url>")
        sys.exit(2)
    else:
        print("getting all domains from a website")
        req = sys.argv[1]
        scan(req)
        print('\ndomains stored in data/domains.txt')