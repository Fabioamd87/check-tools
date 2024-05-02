# Prerequisites
```pip install -r requirements.txt```

Convention used in this HOWTO:
- <> for mandatory paraneters
- [] for optional parameters

# Configuration
set VirusTotal key:

python3 tools.py set_virustotal_key <virustotal_key>

# Usage

## Check
To check a URL/domain
```sh
python check_urls.py [engine] <URL/domain>
```
you can also pass a single engine to scan (optional):

- virustotal
- apivoid
- webshrinker

To check a file list of URLs/domains
```sh
python check_urls.py -f <URL/domain>
```
whitout argument it will check in data\URLs.txt

# Other tools
To get all the domain from a website
```sh
python scan_website.py [-f] [URL]
```
