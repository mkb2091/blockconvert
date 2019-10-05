import requests
import urllib
import time
import json
import os

import blockconvert


def url_to_path(url):
    return os.path.join('data', urllib.parse.urlencode({'': url})[1:])


def copy_whitelist_and_clean():
    with open('whitelist.txt') as file:
        data = '\n'.join(sorted(set(file.read().split())))
    with open('whitelist.txt', 'w') as file:
        file.write(data)
    with open('blacklist.txt') as file:
        data = '\n'.join(sorted(set(file.read().split())))
    with open('blacklist.txt', 'w') as file:
        file.write(data)


def fetch_new_tld():
    req = urllib.request.Request(
        'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
        data=None,
        headers={
            'User-Agent': 'BlockListConvert'})
    if os.path.exists('tld_list.txt'):
        if (time.time() - os.stat('tld_list.txt').st_mtime) / (60 * 60 * 11.5) > 1:
            with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())
        else:
            with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())


if not os.path.exists('data'):
    os.mkdir('data')
copy_whitelist_and_clean()
fetch_new_tld()


def get_status(url):
    base = url_to_path(url)
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
    base = url_to_path(url)
    if not os.path.exists(base):
        os.mkdir(base)
    with open(os.path.join(base, 'metadata.json'), 'w') as file:
        json.dump({'last_modified': int(last_modified),
                   'last_checked': int(last_checked), 'etag': etag}, file)


class DownloadManager():
    def __init__(self, **kwargs):
        self.bl = blockconvert.BlockList(**kwargs)
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'BlocklistConvert' + \
            str(int(time.time()))
        self.paths = []

    def add_url(self, url, is_whitelist, match_url, do_reverse_dns, expires):
        base = url_to_path(url)
        self.paths.append(base)
        check_frequency = max(expires, 12 * 60 * 60)
        last_modified, last_checked, old_etag = get_status(url)
        if last_modified < (
            time.time() -
            expires) and last_checked < (
            time.time() -
                check_frequency):
            headers = {}
            if old_etag != '':
                headers['If-None-Match'] = old_etag
            if last_modified != 0:
                headers['If-Modified-Since'] = time.strftime(
                    '%a, %d %b %Y %H:%M:%S GMT', time.localtime(last_modified))
            try:
                r = self.session.get(url, headers=headers, timeout=5)
            except Exception as error:
                print('Encountered error: "%s" for url: "%s"' % (error, url))
                return
            try:
                new_etag = r.headers['ETag']
            except KeyError:
                new_etag = ''
            try:
                lm_header = time.mktime(
                    time.strptime(
                        r.headers['Last-Modified'],
                        '%a, %d %b %Y %H:%M:%S GMT'))
            except (KeyError, ValueError):
                lm_header = 0
            set_status(url, lm_header, time.time(), new_etag)
            print(url)
            if r.status_code == 200:
                print('Changed')
                self.bl.clear()
                self.bl.add_file(r.text, is_whitelist=is_whitelist,
                                 match_url=match_url)
                self.bl.basic_clean(do_reverse_dns)
                with open(os.path.join(base, 'blacklist.txt'), 'w') as file:
                    file.write('\n'.join(sorted(self.bl.blacklist)))
                with open(os.path.join(base, 'whitelist.txt'), 'w') as file:
                    file.write('\n'.join(sorted(self.bl.whitelist)))
            elif r.status_code == 304:
                print('Not modified')

    def clean(self):
        for path in os.listdir('data'):
            path = os.path.join('data', path)
            if path not in self.paths:
                print('Removing: %s' % path)
                for f in ('blacklist.txt', 'whitelist.txt', 'metadata.json'):
                    now = os.path.join(path, f)
                    if os.path.exists(now):
                        os.remove(now)
                os.rmdir(path)
