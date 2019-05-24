import argparse
import json
import time
import os

import download
import blockconvert
    

def main():
    if not os.path.exists('data'):
        os.mkdir('data')
    urls = []
    with open('urls.txt') as file:
        for line in file.read().splitlines():
            (list_type, match_url, *do_reverse_dns, url, expires, list_license) = json.loads(line)
            if do_reverse_dns == []:
                do_reverse_dns = match_url
            else:
                do_reverse_dns = do_reverse_dns[0]
            urls.append((list_type, match_url, do_reverse_dns, url, expires, list_license))
    with open('urls.txt', 'w') as file:
        file.write('\n'.join(sorted(set([json.dumps(i) for i in urls]))))
    start = time.time()
    manager = download.DownloadManager()
    manager.bl.add_file('\n'.join(url for (_, _, _, url, _, _) in urls),
                       is_whitelist=True, match_url=True)
    with open('whitelist.txt') as file:
        manager.bl.add_file(file.read(), is_whitelist=True, match_url=True)
    with open('whitelist.txt', 'w') as file:
        file.write('\n'.join(sorted(manager.bl.whitelist)))
    download.copy_whitelist_and_clean()
    for (whitelist, match_url, do_reverse_dns, url, expires, list_license) in urls:
        manager.add_url(url, whitelist, match_url, do_reverse_dns, expires)
    manager.clean()
    print('Downloaded needed files(%ss)' % (time.time() - start))
    start = time.time()
    blocklist = manager.bl
    blocklist.clear()
    for path in os.listdir('data'):
        path = os.path.join('data', path)
        for (f, is_whitelist) in (('blacklist.txt', False), ('whitelist.txt', True)):
            try:
                with open(os.path.join(path, f)) as file:
                    blocklist.add_file(file.read(), is_whitelist)
            except FileNotFoundError:
                pass
    blocklist.add_file('\n'.join(url for (_, _, _, url, _, _) in urls),
                       is_whitelist=True, match_url=True)
    print('Consolidated lists(%ss)' % (time.time() - start))
    start = time.time()
    blocklist.clean()
    print('Cleaned list(%ss)' % (time.time() - start))
    start = time.time()
    for (path, func) in [('domains.txt', blocklist.to_domain_list),
                         ('adblock.txt', blocklist.to_adblock),
                         ('hosts.txt', blocklist.to_hosts),
                         ('PrivacyBadger.json', blocklist.to_privacy_badger),
                         ('domains.rpz', blocklist.to_rpz),
                         ]:
        with open(os.path.join('output', path), 'w') as file:
            file.write(func())
    print('Generated output(%ss)' % (time.time() - start))

if __name__ == '__main__':
    main()
