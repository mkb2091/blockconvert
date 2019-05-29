import requests
import urllib
import time
import json
import os

import blockconvert

def copy_whitelist_and_clean():
    if not os.path.exists(os.path.join('data', 'whitelist')):
        os.mkdir(os.path.join('data', 'whitelist'))
    with open('whitelist.txt') as file:
        data = '\n'.join(sorted(file.read().split()))
    with open('whitelist.txt', 'w') as file:
        file.write(data)
    with open(os.path.join('data', 'whitelist', 'whitelist.txt'), 'w') as file:
        file.write(data)


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
if not os.path.exists('data'):
    os.mkdir('data')
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
        except (FileNotFoundError, json.JSONDecodeError):
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
        json.dump({'last_modified':int(last_modified), 'last_checked':int(last_checked), 'etag':etag}, file)

class DownloadManager():
    def __init__(self, **kwargs):
        self.bl = blockconvert.BlockList(**kwargs)
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'BlocklistConvert' + str(int(time.time()))
        self.paths = []
    def add_url(self, url, is_whitelist, match_url, do_reverse_dns, expires):
        base = os.path.join('data', urllib.parse.urlencode({'':url})[1:])
        self.paths.append(base)
        check_frequency = expires
        last_modified, last_checked, old_etag = get_status(url)
        if last_modified < (time.time() - expires) and last_checked < (time.time()  - check_frequency):
            headers = {}
            if old_etag != '':
                headers['If-None-Match'] = old_etag
            if last_modified != 0:
                headers['If-Modified-Since'] = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(last_modified))
            r = self.session.get(url, headers=headers)
            try:
                new_etag = r.headers['ETag']
            except KeyError:
                new_etag = ''
            try:
                lm_header = time.mktime(time.strptime(r.headers['Last-Modified'], '%a, %d %b %Y %H:%M:%S GMT'))   
            except (KeyError, ValueError):
                lm_header = 0
            set_status(url, lm_header, time.time(), new_etag)
            print(url)
            if r.status_code == 200:
                print('Changed')
                self.bl.clear()
                self.bl.add_file(r.text, is_whitelist=is_whitelist,
                                 match_url=match_url)
                self.bl.clean(do_reverse_dns)
                with open(os.path.join(base, 'blacklist.txt'), 'w') as file:
                    file.write('\n'.join(sorted(self.bl.blacklist)))
                with open(os.path.join(base, 'whitelist.txt'), 'w') as file:
                    file.write('\n'.join(sorted(self.bl.whitelist)))
            elif r.status_code == 304:
                print('Not modified')
    def clean(self):
        for path in os.listdir('data'):
            path = os.path.join('data', path)
            if path not in self.paths + [os.path.join('data', 'whitelist')]:
                print('Removing: %s' % path)
                for f in ('blacklist.txt', 'whitelist.txt', 'metadata.json'):
                    now = os.path.join(path, f)
                    if os.path.exists(now):
                        os.remove(now)
                os.rmdir(path)
            
