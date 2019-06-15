TITLE = '# BlockConvert'

DESCRIPTION = '''
Generated blocklist in a variety of formats.

Advantages of using this list:
- Conversion of list types. As well as supporting many common filter list formats, \
it also supports Privacy Badger data file, which uses algorithms to detect trackers \
allowing newly created trackers to be quickly detected and added to this blocklist \
without a human needing to spot the tracker.

- Reverse DNS and passive DNS on malware IP addresses. This allows finding all the \
domains which a malware IP blacklist suggests could be dangerous to be found and \
blocked. This allows blocking of malware domains that haven't yet been added to \
other malware domain lists.

- Use of a whitelist. Using a hosts file doesn't allow whitelisting, and many \
DNS-based blockers don't have great support of whitelists. This list has it's \
own whitelist, as well as using a few others to try to reduce false positives. \
This list supports "*" in subdomain and tld to aid in easily fixing many false \
positives at once. (If you do find a false positive(domain that shouldn't be \
blocked), then please make an issue and I will remove it)

- Use of DNS to check if domains still exist. Many lists contain domains that \
have expired and no longer exist. This makes those lists larger than needed \
which wastes bandwidth, space and can slow blocking.
'''

PROCESS = '\n\n'.join((
    '## The Process',
    '1. Download file',
    '2. Extract domains into whitelist and blacklist',
    '3. Use passive dns and reverse dns on all of the ip addresses in the whitelist and blacklist',
    '4. For any domains which have "\*" in tld field replace it with every tld in downloaded list',
    '5. For each domain which starts with "www" or "m" add a copy of that domain without the subdomain',
    '6. For each domain with "\\*" as subdomain replace it with every subdomain in top 1000 subdomains file, and add a copy without any subdomain',
    '7. For every domain in the whitelist, remove it from the blacklist',
    '8. For all remaining domains in blacklist, use dns to check if the domain is still registered, remove those that are not',
    '9. Remove all invalid domains'))

LINKS = '\n\n'.join((
    '## Links',
    'Adblock Plus style blocklist:  https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/adblock.txt',
    'Hosts file style blocklist: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/hosts.txt',
    'List of blocked domains: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt',
    'DNS Response Policy Zone file: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.rpz',
    'URLs used to build lists: https://github.com/mkb2091/blockconvert/blob/master/urls.txt',
    ))

ENDING = '''## Last Commit Infomation

Theres are {rule_count} blocked domains in each of the generated filter lists

## Sources

For static sources 100 days is put, and for sources with unknown expires, 1 days is put.

The files in data/ are all modified versions generated from the below sources:

{url_table}

## Credits

enemyofarsenic(Reddit): Many very useful suggestions such as whitelist, passive dns, and many lists

'''

FORMAT = '\n\n'.join([TITLE, DESCRIPTION, PROCESS, LINKS, ENDING])

def generate_readme(urls, rule_count):
    url_table = [['Title', 'URL', 'Author', 'Expires', 'Type', 'License'],
                 [':---:',':---:', ':---:', ':---:', ':---:', ':---:']]
    for (title, url, author, expires, list_license, is_whitelist, match_url, do_reverse_dns) in urls:
        if expires >= 24 * 60 * 60:
            expires = '%s days' % (round(expires / 24 / 60 / 60, 1))
        elif expires >= 60 * 60:
            expires = '%s hours' % (round(expires / 60 / 60, 1))
        elif expires >= 60:
            expires = '%s minute' % (round(expires / 60, 1))
        else:
            expires = '%s seconds' % expires
        url_table.append([title, url, author, expires, list_license, ('Whitelist' if is_whitelist else 'Blacklist')])
    url_table = '\n'.join('|'.join(line) for line in url_table)
    with open('README.md', 'w') as file:
        file.write(FORMAT.format(**locals()))
