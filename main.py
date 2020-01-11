import argparse
import json
import time
import os

import download
import blockconvert
import generate_readme


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--update", help="increase output verbosity",
                        action="store_true")
    args = parser.parse_args()
    config = {}
    try:
        with open('config.json') as file:
            config = json.load(file)
    except FileNotFoundError:
        print('config.json not found')
    except json.JSONDecodeError:
        print('config.json not valid JSON')
    if not os.path.exists('data'):
        os.mkdir('data')
    if not os.path.exists('db'):
        os.mkdir('db')
    urls = []
    with open('urls.txt') as file:
        for line in file.read().splitlines():
            try:
                (title, url, author, expires, list_license, is_whitelist,
                 match_url, do_reverse_dns) = json.loads(line)
                urls.append(
                    (title,
                     url,
                     author,
                     expires,
                     list_license,
                     is_whitelist,
                     match_url,
                     do_reverse_dns))
            except json.JSONDecodeError:
                pass
    urls.sort(key=json.dumps, reverse=True)
    with open('urls.txt', 'w') as file:
        file.write(
            'Title|URL|Author|Expires|License|Is Whitelist|match url|perform reverse dns\n')
        file.write('\n'.join([json.dumps(i) for i in urls]))
    start = time.time()
    blocklist = blockconvert.BlockList(config=config, update=args.update)
    manager = download.DownloadManager(blocklist)
    blocklist.add_file('\n'.join(url for (_, url, _, _, _, _, _, _) in urls),
                       is_whitelist=True, match_url=True)
    with open('whitelist.txt') as file:
        blocklist.add_file(file.read(), is_whitelist=True, match_url=True)
    with open('whitelist.txt', 'w') as file:
        file.write('\n'.join(sorted(blocklist.whitelist)))
    download.copy_whitelist_and_clean()
    for (
        title,
        url,
        author,
        expires,
        list_license,
        is_whitelist,
        match_url,
            do_reverse_dns) in urls:
        manager.add_url(url, is_whitelist, match_url, do_reverse_dns, expires)
    manager.clean()
    print('Downloaded needed files(%ss)' % (time.time() - start))
    print()
    start = time.time()
    blocklist.clear()
    for (_, url, _, _, _, _, _, _) in urls:
        path = download.url_to_path(url)
        for (
                f, is_whitelist) in (
                ('blacklist.txt', False), ('whitelist.txt', True)):
            try:
                with open(os.path.join(path, f)) as file:
                    blocklist.add_file(file.read(), is_whitelist)
            except FileNotFoundError:
                pass
    with open('whitelist.txt') as file:
        blocklist.add_file(file.read(), True)
    with open('blacklist.txt') as file:
        blocklist.add_file(file.read())
    print('Consolidated lists(%ss)' % (time.time() - start))
    print()
    start = time.time()
    blocklist.clean(True)
    print('Cleaned list(%ss)' % (time.time() - start))
    start = time.time()
    blocklist.title = 'BlockConvert'
    blocklist.expires = '1 days'
    blocklist.homepage = 'https://github.com/mkb2091/blockconvert'
    blocklist.license = 'GPL-3.0'
    blocklist.bitcoin = '1MJZRsWS12oX68iGfedrabxQyacGUiGVwv'
    for (path, func) in [('domains.txt', blocklist.to_domain_list),
                         ('adblock.txt', blocklist.to_adblock),
                         ('hosts.txt', blocklist.to_hosts),
                         ('domains.rpz', blocklist.to_rpz),
                         ('ip_blocklist.txt', blocklist.to_ip_blocklist),
                         ('ip_blocklist.ipset', blocklist.to_ipset_blocklist),
                         ('whitelist_domains.txt', blocklist.to_domain_whitelist),
                         ('whitelist_adblock.txt', blocklist.to_adblock_whitelist),
                         ]:
        with open(os.path.join('output', path), 'w') as file:
            file.write(func())
    generate_readme.generate_readme(urls, len(blocklist.blacklist))
    print('Generated output(%ss)' % (time.time() - start))


if __name__ == '__main__':
    main()
    exit()
