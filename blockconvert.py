import argparse
import time
import json
import os
import re

import dns_check

class BlockList():
    def __init__(self, do_dns_check=True, dns_check_threads=40):
        self.blacklist = set()
        self.whitelist = set()
        self.generate_domain_regex()
        self.generate_host_regex()
        self.generate_adblock_regex()
        self.generate_dns_reponse_policy_zone_regex()
        self.generate_master_regex()
        self.do_dns_check = do_dns_check
        self.dns_check_threads = dns_check_threads
        with open('subdomain_list.txt') as file:
            self.SUBDOMAINS = file.read().splitlines()

    def generate_domain_regex(self):
        with open('tld_list.txt') as file:
            self.TLDS = [tld for tld in file.read().lower().splitlines() if '#' not in tld]
        tlds = self.TLDS.copy()
        tlds.append(r'*')
        tld_dict = dict()
        for tld in tlds:
            try:
                tld_dict[tld[0]].append(tld[1:])
            except KeyError:
                tld_dict[tld[0]] = [tld[1:]]
        tld_regex = []
        for first_letter in sorted(tld_dict, key=lambda x:len(tld_dict[x]), reverse=True):
            now = '|'.join(['(?:%s)' % re.escape(i) for i in sorted(tld_dict[first_letter], key=len, reverse=True)])
            tld_regex.append('(?:%s(?:%s))' % (re.escape(first_letter), now))
        tld_regex = '(?:%s)' % '|'.join(tld_regex)
        ip_v4 = '[12]?[0-9]{,2}[.][12]?[0-9]{,2}[.][12]?[0-9]{,2}[.][12]?[0-9]{,2}'
        ip_v6 = '[0-9a-f]{,4}(?:[:][0-9a-f]{,4}){2,8}'
        ip = '(?:{ip_v4}|{ip_v6})'.format(**locals())
        self.IP_REGEX = re.compile(ip)
        segment = r'(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)'
        self.DOMAIN_STRING =  '[.]?((?:(?:\*[.])?{segment}(?:[.]{segment})*[.]{tld_regex})|{ip})[.]?'.format(**locals())
        self.DOMAIN_REGEX = re.compile(self.DOMAIN_STRING)
    def generate_host_regex(self):
        ips = ['0.0.0.0', '127.0.0.1', '::1']
        ip_string = '(?:%s)' % '|'.join('(?:%s)' % re.escape(ip) for ip in ips)
        domain_string = self.DOMAIN_STRING
        self.HOSTS_STRING = r'{ip_string}\s+{domain_string}\s*(?:\#.*)?'.format(**locals())
    def generate_adblock_regex(self):
        domain_string = self.DOMAIN_STRING
        url_string = r'(?:(?:(?:http(?:s|\*)?)?[:])(?:(?:\/\/)|\*))?{domain_string}\/?'.format(**locals())
        start = r'(?:\|?\|)?\*?'
        options = ['popup', r'first\-party', r'\~third\-party', r'third\-party']
        options_noop = ['important', r'domain\=\2']
        options_string = '(?:%s)' % '|'.join('(?:%s)' % i for i in options)
        options_other = '(?:%s)' % '|'.join('(?:%s)' % i for i in ['[a-z~-]+'] + options_noop)
        options_full = r'\$(?:(?:(?:{options_other}[,])*{options_string}(?:[,]{options_other})*)|%s)'.format(**locals())
        options_full%= '|'.join('(?:%s)' % i for i in options_noop)
        ending = r'[*]?\|?\^?(?:{options_full})?(?:\s+(?:(?:\!.*)|(?:\#.*))?)?'.format(**locals())
        href_element_hiding = r'\#\#\[href\^?\=\"{url_string}\"\]'.format(**locals())
        self.ADBLOCK_STRING = r'(?:{start}{url_string}{ending})|(?:{href_element_hiding})'.format(**locals())
    def generate_dns_reponse_policy_zone_regex(self):
        domain_string = self.DOMAIN_STRING
        self.RPZ_STRING = r'{domain_string}\s+cname\s+[.]\s*(?:[;].*)?'.format(**locals())
        
    def generate_master_regex(self):
        self.REGEX_STRING = '(?:%s)|(?:%s)|(?:%s)' % (self.HOSTS_STRING, self.ADBLOCK_STRING, self.RPZ_STRING)
        self.REGEX = re.compile(self.REGEX_STRING)

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
    def clean(self):
        dns = dns_check.DNSChecker()
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            ips = []
            for item in list(filter_list):
                if self.IP_REGEX.fullmatch(item):
                    ips.append(item)
                    filter_list.remove(item)
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

