import argparse
import json
import os
import re

import dns_check

class BlockList():
    def __init__(self):
        self.blocked_hosts = set()
        self.whitelist = set()
        self.generate_domain_regex()
        self.generate_host_regex()
        self.generate_adblock_regex()
        self.generate_master_regex()

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
        self.DOMAIN_STRING =  '(?:\*?[.])?([a-z0-9_-]+(?:[.][a-z0-9_-]+)*[.]%s)[.]?' % tld_regex
        self.DOMAIN_REGEX = re.compile(self.DOMAIN_STRING)
    def generate_host_regex(self):
        ips = ['0.0.0.0', '127.0.0.1', '::1']
        ip_string = '(?:%s)' % '|'.join('(?:%s)' % re.escape(ip) for ip in ips)
        domain_string = self.DOMAIN_STRING
        self.HOSTS_STRING = rf'{ip_string}\s+{domain_string}\s*(?:\#.*)?'
    def generate_adblock_regex(self):
        domain_string = self.DOMAIN_STRING
        url_string = rf'(?:(?:(?:https?)?[:])\/\/)?{domain_string}\/?'
        start = f'(?:\|?\|)?'
        options = ['popup', r'first\-party', r'\~third\-party', r'third\-party']
        options_noop = ['important', r'domain\=\2']
        options_string = '(?:%s)' % '|'.join('(?:%s)' % i for i in options)
        options_other = '(?:%s)' % '|'.join('(?:%s)' % i for i in ['[a-z-]+'] + options_noop)
        options_full = rf'\$(?:(?:(?:{options_other}[,])*{options_string}(?:[,]{options_other})*)|%s)'
        options_full%= '|'.join('(?:%s)' % i for i in options_noop)
        ending = rf'[*]?\|?\^?(?:{options_full})?\s*(?:\!.*)?'
        href_element_hiding = rf'\#\#\[href\^?\=\"{url_string}\"\]'
        self.ADBLOCK_STRING = rf'(?:{start}{url_string}{ending})|(?:{href_element_hiding})'
    def generate_master_regex(self):
        self.REGEX_STRING = '(?:%s)|(?:%s)' % (self.HOSTS_STRING, self.ADBLOCK_STRING)
        self.REGEX = re.compile(self.REGEX_STRING)

    def add_file(self, path):
        with open(path) as file:
            data = file.read().lower()
        try:
            data = json.loads(data)
            if ('action_map' in data and isinstance(data['action_map'], dict)
                and 'snitch_map' in data and isinstance(data['snitch_map'], dict)):
                self.parse_privacy_badger(data)
        except json.JSONDecodeError:
            for line in data.splitlines():
                if line.startswith('@@'):
                    match = self.REGEX.fullmatch(line[2:])
                    if match:
                        self.whitelist.add(sorted(match.groups(), key=bool, reverse=True)[0])
                else:
                    match = self.REGEX.fullmatch(line)
                    if match:
                        self.blocked_hosts.add(sorted(match.groups(), key=bool, reverse=True)[0])
    def parse_privacy_badger(self, data):
        temp_whitelist = set()
        for x in data['snitch_map']:
            temp_whitelist.update(data['snitch_map'])
        for i in data['action_map']:
            if self.DOMAIN_REGEX.fullmatch(i):
                if isinstance(data['action_map'][i], dict) and 'heuristicaction' in data['action_map'][i]:
                    if data['action_map'][i]['heuristicaction'] == 'block':
                        if i not in temp_whitelist:
                            self.blocked_hosts.add(i)
                    elif data['action_map'][i]['heuristicaction'] == 'cookieblock':
                        self.whitelist.add(i)
    def clean(self):
        for filter_list in [self.blocked_hosts, self.whitelist]:
            for url in list(filter_list):
                if url.endswith('*'):
                    filter_list.remove(url)
                    for tld in self.TLDS:
                        filter_list.add(url[:-1]+tld)
        for i in self.whitelist:
            try:
                self.blocked_hosts.remove(i)
            except KeyError:
                pass
    def to_domain_list(self):
        return '\n'.join(sorted(self.blocked_hosts))
    def to_adblock(self):
        return '\n'.join(['||%s^' % i for i in sorted(self.blocked_hosts)])
    def to_hosts(self):
        return '\n'.join(['0.0.0.0 ' + i for i in sorted(self.blocked_hosts)])
    def to_privacy_badger(self):
        base = '{"action_map":{%s},"snitch_map":{%s}, "settings_map":{}}'
        url_string = '"%s":{"userAction":"","dnt":false,"heuristicAction":"block","nextUpdateTime":0}'
        return base % (',\n'.join([url_string % i for i in sorted(self.blocked_hosts)]),
                       ',\n'.join(['"%s":["1","2","3"]' % (i) for i in sorted(self.blocked_hosts)]))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-dns-check', action='store_true')
    parser.add_argument('--dns-check-threads', type=int, default=40)
    args = parser.parse_args()
    blocklist = BlockList()
    try:
        paths = [os.path.join('target', f) for f in os.listdir('target')]
        paths = [f for f in paths if os.path.isfile(f)]
    except FileNotFoundError:
        print('Target directory does not exist')
        return
    paths.sort()
    for path in paths:
        blocklist.add_file(path)
    blocklist.clean()
    print('Generated %s rules' % len(blocklist.blocked_hosts))
    if not args.no_dns_check:
        dns = dns_check.DNSChecker()
        result = dns.mass_check(blocklist.blocked_hosts, args.dns_check_threads)
        for domain in result:
            if not result[domain]:
                blocklist.blocked_hosts.remove(domain)
        print('Trimmed to %s rules' % len(blocklist.blocked_hosts))
    try:
        os.makedirs('output')
    except FileExistsError:
        pass
    for (path, func) in [('domains.txt', blocklist.to_domain_list),
                         ('adblock.txt', blocklist.to_adblock),
                         ('hosts.txt', blocklist.to_hosts),
                         ('PrivacyBadger.json', blocklist.to_privacy_badger)]:
        with open(os.path.join('output', path), 'w') as file:
            file.write(func())

if __name__ == '__main__':
    main()
