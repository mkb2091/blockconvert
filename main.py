import argparse
import json
import os

import download
import blockconvert
    

def main():
    if not os.path.exists('data'):
        os.mkdir('data')
    urls = []
    with open('urls.txt') as file:
        for line in file.read().splitlines():
            (list_type, url, expires, list_license) = json.loads(line)
            urls.append((list_type, url, expires, list_license))
    with open('urls.txt', 'w') as file:
        file.write('\n'.join(sorted([json.dumps(i) for i in urls])))
    manager = download.DownloadManager()
    for (whitelist, url, expires, list_license) in urls:
        manager.add_url(url, whitelist, expires)
    print('Downloaded needed files')
    blocklist = blockconvert.BlockList()
    for path in os.listdir('data'):
        path = os.path.join('data', path)
        for (f, is_whitelist) in (('blacklist.txt', False), ('whitelist.txt', True)):
            try:
                with open(os.path.join(path, f)) as file:
                    blocklist.add_file(file.read(), is_whitelist)
            except FileNotFoundError:
                pass
    print('Consolidated lists')
    blocklist.clean()
    print('Cleaned list')
    for (path, func) in [('domains.txt', blocklist.to_domain_list),
                         ('adblock.txt', blocklist.to_adblock),
                         ('hosts.txt', blocklist.to_hosts),
                         ('PrivacyBadger.json', blocklist.to_privacy_badger)]:
        with open(os.path.join('output', path), 'w') as file:
            file.write(func())

if __name__ == '__main__':
    main()
