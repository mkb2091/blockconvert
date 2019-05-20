import requests
import urllib
import time
import json
import os

import blockconvert

def copy_whitelist_and_clean():
    if not os.path.exists(os.path.join('data', 'whitelist')):
        os.mkdir(os.path.join('data', 'whitelist'))
    with open('whitelist.txt') as file1:
        with open(os.path.join('data', 'whitelist', 'whitelist.txt'), 'w') as file2:
            file2.write(file1.read())


def fetch_new_tld():
    req = urllib.request.Request('https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
                                 data=None,
                                 headers={'User-Agent':'BlockListConvert'})
    if os.path.exists('tld_list.txt'):
        if (time.time() - os.stat('tld_list.txt').st_mtime) / (60 * 60 * 11.5) > 1:
            with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())
        else:
             with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())
def fetch_new_subdomains():
    req = urllib.request.Request('https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000',
                                 data=None,
                                 headers={'User-Agent':'BlockListConvert'})
    if os.path.exists('subdomain_list.txt'):
        if (time.time() - os.stat('subdomain_list.txt').st_mtime) / (60 * 60 * 11.5) > 1:
            with urllib.request.urlopen(req) as response:
                with open('subdomain_list.txt', 'wb') as file:
                    file.write(response.read())
    else:
        with urllib.request.urlopen(req) as response:
            with open('subdomain_list.txt', 'wb') as file:
                file.write(response.read())
if not os.path.exists('blacklist'):
    os.mkdir('blacklist')
if not os.path.exists('whitelist'):
    os.mkdir('whitelist')
copy_whitelist_and_clean()
fetch_new_tld()
fetch_new_subdomains()

def get_status(url):
    base = os.path.join('data', urllib.parse.urlencode({'':url})[1:])
    if os.path.exists(base):
        try:
            with open(os.path.join(base, 'metadata.json')) as file:
                metadata = json.load(file)
            last_modified = metadata['last_modified']
            last_checked = metadata['last_checked']
            etag = metadata['etag']
        except FileNotFoundError:
            last_modified = 0
            last_checked = 0
            etag = ''
    else:
        last_modified = 0
        last_checked = 0
        etag = ''
    return last_modified, last_checked, etag

def set_status(url, last_modified, last_checked, etag):
    base = os.path.join('data', urllib.parse.urlencode({'':url})[1:])
    if not os.path.exists(base):
        os.mkdir(base)
    with open(os.path.join(base, 'metadata.json'), 'w') as file:
        json.dump({'last_modified':last_modified, 'last_checked':last_checked, 'etag':etag}, file)

class DownloadManager():
    def __init__(self, **kwargs):
        self.bl = blockconvert.BlockList(**kwargs)
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'BlocklistConvert' + str(int(time.time()))
    def add_url(self, url, whitelist, expires):
        last_modified, last_checked, old_etag = get_status(url)
        if last_modified < (time.time() - expires) and last_checked < (time.time()  - (11.5 * 60 * 60)):
            r = self.session.get(url, stream=True)
            try:
                new_etag = r.headers['ETag']
            except KeyError:
                new_etag = ''
            try:
                lm_header = time.mktime(time.strptime(r.headers['Last-Modified'], '%a, %d %b %Y %H:%M:%S GMT'))   
            except (KeyError, ValueError):
                lm_header = 0
            set_status(url, (last_modified if last_modified != 0 else time.time()), time.time(), new_etag)
            if (new_etag != '' and new_etag != old_etag) or (lm_header != 0 and lm_header > last_checked):
                self.bl.clear()
                self.bl.add_file(r.content.decode('utf-8', 'ignore'), whitelist)
                self.bl.clean()
                base = os.path.join('data', urllib.parse.urlencode({'':url})[1:])
                with open(os.path.join(base, 'blacklist.txt'), 'w') as file:
                    file.write('\n'.join(sorted(self.bl.blacklist)))
                with open(os.path.join(base, 'whitelist.txt'), 'w') as file:
                    file.write('\n'.join(sorted(self.bl.whitelist)))
            
