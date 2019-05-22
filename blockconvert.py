import argparse
import time
import json
import os
import re

import dns_check
import build_regex

class BlockList():
    def __init__(self, do_dns_check=True, dns_check_threads=40):
        self.blacklist = set()
        self.whitelist = set()
        self.REGEX = build_regex.REGEX
        self.DOMAIN_REGEX = build_regex.DOMAIN_REGEX
        self.IP_REGEX = build_regex.IP_REGEX
        self.TLDS = build_regex.TLDS
        self.do_dns_check = do_dns_check
        self.dns_check_threads = dns_check_threads
        with open('subdomain_list.txt') as file:
            self.SUBDOMAINS = file.read().splitlines()

    def add_file(self, contents, is_whitelist=False):
        data = contents.lower()
        try:
            data = json.loads(data)
            if ('action_map' in data and isinstance(data['action_map'], dict)
                and 'snitch_map' in data and isinstance(data['snitch_map'], dict)):
                self.parse_privacy_badger(data)
        except json.JSONDecodeError:
            whitelist = self.whitelist
            if is_whitelist:
                blacklist = whitelist
            else:
                blacklist = self.blacklist
            for line in data.splitlines():
                if line.startswith('@@'):
                    match = self.REGEX.fullmatch(line[2:])
                    if match:
                        whitelist.update(filter(bool, match.groups()))
                else:
                    match = self.REGEX.fullmatch(line)
                    if match:
                        blacklist.update(filter(bool, match.groups()))
    def parse_privacy_badger(self, data):
        temp_whitelist = set()
        for x in data['snitch_map']:
            temp_whitelist.update(data['snitch_map'][x])
        for i in data['action_map']:
            if self.DOMAIN_REGEX.fullmatch(i):
                if isinstance(data['action_map'][i], dict) and 'heuristicaction' in data['action_map'][i]:
                    if data['action_map'][i]['heuristicaction'] == 'block':
                        if i not in temp_whitelist:
                            self.blacklist.add(i)
                    elif data['action_map'][i]['heuristicaction'] == 'cookieblock':
                        self.whitelist.add(i)
    def clean(self, is_malware=False):
        dns = dns_check.DNSChecker()
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            ips = []
            for item in list(filter_list):
                if self.IP_REGEX.fullmatch(item):
                    ips.append(item)
                    filter_list.remove(item)
            if ips:
                found = dns.mass_reverse_lookup(ips)
                filter_list.update(found)
                print('Added %s rules via reverse dns(%ss)' % (len(found), time.time() - last))
        last = time.time()
        print('Started with %s rules' % len(self.blacklist))
        for filter_list in [self.blacklist, self.whitelist]:
            for url in list(filter_list):
                if url.endswith('*'):
                    filter_list.remove(url)
                    for tld in self.TLDS:
                        filter_list.add(url[:-1]+tld)
        print('Expanded .* TLD to %s rules(%ss)' % (len(self.blacklist), time.time() - last))
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            for url in list(filter_list):
                if url.split('.')[0] in ('m', 'www'):
                    filter_list.add('.'.join(url.split('.')[1:]))
        print('Expanded to %s rules(%ss)' % (len(self.blacklist), time.time() - last))
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            for url in list(filter_list):
                if url.startswith('*.'):
                    filter_list.remove(url)
                    filter_list.add(url[2:])
                    for subdomain in self.SUBDOMAINS:
                        filter_list.add(subdomain + '.' + url[2:])
        print('Expanded *. subdomain to %s rules(%ss)' % (len(self.blacklist), time.time() - last))
        last = time.time()
        for i in self.whitelist:
            try:
                self.blacklist.remove(i)
            except KeyError:
                pass
        print('Cleaned to %s rules(%ss)' % (len(self.blacklist), time.time() - last))
        last = time.time()
        if self.do_dns_check:
            last = time.time()
            result = dns.mass_check(self.blacklist, self.dns_check_threads)
            print('Performed lookups(%ss)' % (time.time() - last))
            last = time.time()
            for domain in result:
                if not result[domain]:
                    self.blacklist.remove(domain)
            print('Trimmed to %s rules(%ss)' % (len(self.blacklist), time.time() - last))
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            for url in list(filter_list):
                if not self.REGEX.match(url):
                    print('Removing: %s' % url)
                    filter_list.remove(url)
        if is_malware:
            for filter_list in [self.blacklist, self.whitelist]:
                ips = set()
                result = dns.mass_check(filter_list, self.dns_check_threads)
                for domain in result:
                    if result[domain] not in '1':
                        ips.add(result[domain])
                old_len = len(filter_list)
                found = dns.mass_reverse_lookup(ips)
                filter_list.update(found)
                print('Added %s rules via reverse dns of malware' % (len(filter_list) - old_len))
                self.clean(False)
    def to_domain_list(self):
        return '\n'.join(sorted(self.blacklist))
    def to_adblock(self):
        return '\n'.join(['||%s^' % i for i in sorted(self.blacklist)])
    def to_hosts(self):
        return '\n'.join(['0.0.0.0 ' + i for i in sorted(self.blacklist)])
    def to_privacy_badger(self):
        base = '{"action_map":{%s},"snitch_map":{%s}, "settings_map":{}}'
        url_string = '"%s":{"heuristicAction":"block"}'
        return base % (',\n'.join([url_string % i for i in sorted(self.blacklist)]),
                       ',\n'.join(['"%s":["1","2","3"]' % (i) for i in sorted(self.blacklist)]))
    def to_rpz(self):
        return '\n'.join(['%s CNAME .' % i for i in sorted(self.blacklist)])
    def clear(self):
        self.blacklist = set()
        self.whitelist = set()

