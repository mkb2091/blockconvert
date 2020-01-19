import urllib
import json
import re
import os

import requests

import build_regex


def url_to_path(url):
    return os.path.join('data', urllib.parse.urlencode({'': url})[1:])


r = requests.get('https://dbl.oisd.nl/notinuse.html')

notinuse = re.findall('(https?://[^<]+)(?:<br>)?', r.text)

urls = set()
with open('urls.txt') as file:
    file.readline()
    for line in file:
        line.strip()
        data = json.loads(line)
        urls.add(data[1])

skipped = sorted(urls.intersection(notinuse))

with open('dbl.txt') as file:
    dbl = set(file.read().splitlines())

with open('output/domains.txt') as file:
    blocked = set(file.read().splitlines())

dbl_unblocked = blocked.difference(dbl)

per_filterlist = {}
potential = {}
for url in skipped:
    with open(os.path.join(url_to_path(url), 'blacklist.txt')) as file:
        now = set(file.read().splitlines())
        now.intersection_update(dbl_unblocked)
        per_filterlist[url] = now
        print(url, len(now))
        for domain in now:
            potential[domain] = potential.get(domain, 0) + 1
print('Total potential false positive length:', len(potential))
with open('potential_fp.txt', 'w') as file:
    for (_, domain) in sorted([(potential[i], i)
                               for i in potential], reverse=True):
        file.write(domain + '\n')
