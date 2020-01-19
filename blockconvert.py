import argparse
import time
import json
import os
import re

import dns_check
import build_regex
import get_subdomains

ADBLOCK_PLUS_HEADER = '''[Adblock Plus 2.0]
! Version: {version}
! Title: {title}
! Last modified: {last_modified}
! Expires: {expires} (update frequency)
! Homepage: {homepage}
! Licence: {license}
! Bitcoin: {bitcoin}
!
!-----------------------Filters-----------------------!
'''

DOMAIN_LIST_HEADER = '''
# Title: {title}
# Last modified: {last_modified}
# Expires: {expires} (update frequency)
# Homepage: {homepage}
# Licence: {license}
# Bitcoin: {bitcoin}
'''

HOSTS_HEADER = '''
# Title: {title}
# Last modified: {last_modified}
# Expires: {expires} (update frequency)
# Homepage: {homepage}
# Licence: {license}
# Bitcoin: {bitcoin}
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
'''


class BlockList():
    def __init__(
            self,
            config,
            update,
            dns_check_threads=40,
            disable_networking=False):
        self.config = config
        self.blacklist = set()
        self.ip_blocklist = set()
        self.whitelist = set()
        self.REGEX = build_regex.REGEX
        self.DOMAIN_REGEX = build_regex.DOMAIN_REGEX
        self.IP_REGEX = build_regex.IP_REGEX
        self.TLDS = build_regex.TLDS
        self.URL_REGEX = build_regex.URL_REGEX
        self.dns_check_threads = max(1, dns_check_threads)
        self.dns = dns_check.DNSChecker(config, update, disable_networking)
        self.title = ''
        self.expires = '1 days'
        self.homepage = ''
        self.license = ''
        self.bitcoin = ''

    def add_file(self, contents, is_whitelist=False, match_url=False):
        data = contents.lower()
        try:
            data = json.loads(data)
            if (
                'action_map' in data and isinstance(
                    data['action_map'],
                    dict) and 'snitch_map' in data and isinstance(
                    data['snitch_map'],
                    dict)):
                self.parse_privacy_badger(data)
        except json.JSONDecodeError:
            whitelist = self.whitelist
            if is_whitelist:
                blacklist = whitelist
            else:
                blacklist = self.blacklist
            for line in data.splitlines():
                if match_url:
                    match = self.URL_REGEX.fullmatch(line)
                    if match:
                        blacklist.update(filter(bool, match.groups()))
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
                if isinstance(
                        data['action_map'][i],
                        dict) and 'heuristicaction' in data['action_map'][i]:
                    if data['action_map'][i]['heuristicaction'] == 'block':
                        if i not in temp_whitelist:
                            self.blacklist.add(i)
                    elif data['action_map'][i]['heuristicaction'] == 'cookieblock':
                        self.whitelist.add(i)

    def basic_clean(self, keep_ip=True):
        if not keep_ip:
            for filter_list in [self.blacklist, self.whitelist]:
                ips = []
                for item in filter_list:
                    if self.IP_REGEX.fullmatch(item):
                        ips.append(item)
                for ip in ips:
                    filter_list.remove(ip)

    def clean(self, do_reverse_dns=False):
        dns = self.dns
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            ips = []
            for item in filter_list:
                if self.IP_REGEX.fullmatch(item):
                    ips.append(item)
            if ips:
                if filter_list is self.blacklist:
                    self.ip_blocklist = ips
                for ip in ips:
                    filter_list.remove(ip)
                if do_reverse_dns:
                    print('Found %s IP addresses' % len(ips))
                    found = dns.mass_reverse_lookup(ips)
                    filter_list.update(found)
                    print('Added %s rules via reverse dns' % len(found))
        print('Checked for IP addresses(%ss)' % (time.time() - last))
        print()
        last = time.time()
        print('Started with %s rules' % len(self.blacklist))
        for filter_list in [self.blacklist, self.whitelist]:
            star_tld = []
            for url in filter_list:
                if url.endswith('*'):
                    star_tld.append(url)
            for url in star_tld:
                filter_list.remove(url)
                for tld in self.TLDS:
                    filter_list.add(url[:-1] + tld)
        print('Expanded .* TLD to %s rules(%ss)' %
              (len(self.blacklist), time.time() - last))
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            to_remove_subdomains = []
            for url in filter_list:
                if url.split('.')[0] in ('m', 'www'):
                    to_remove_subdomains.append(url)
            for url in to_remove_subdomains:
                filter_list.add('.'.join(url.split('.')[1:]))
        for domain in list(self.whitelist):
            if not domain.startswith('www.'):
                self.whitelist.add('www.' + domain)
        print('Expanded to %s rules(%ss)' %
              (len(self.blacklist), time.time() - last))
        last = time.time()
        star_subdomain = []
        for url in self.blacklist:
            if url.startswith('*.'):
                star_subdomain.append(url)
        for url in star_subdomain:
            self.blacklist.remove(url)
            self.blacklist.add(url[2:])
        self.blacklist.update(
            get_subdomains.get_subdomains(
                self.dns, star_subdomain))
        print('Expanded *. subdomain to %s rules(%ss)' %
              (len(self.blacklist), time.time() - last))
        last = time.time()
        whitelist_star = {}
        for i in self.whitelist:
            if i.startswith('*.'):
                try:
                    self.blacklist.remove(i[2:])
                except KeyError:
                    pass
                try:
                    whitelist_star[i[-3:]].append(i[1:])
                except KeyError:
                    whitelist_star[i[-3:]] = [i[1:]]
            else:
                try:
                    self.blacklist.remove(i)
                except KeyError:
                    pass
        if whitelist_star:
            to_remove = []
            for domain in self.blacklist:
                try:
                    for d2 in whitelist_star[domain[-3:]]:
                        if domain.endswith(d2):
                            to_remove.append(domain)
                            break
                except KeyError:
                    pass
            self.blacklist.difference_update(to_remove)
        print('Applied whitelist, now at %s rules(%ss)' %
              (len(self.blacklist), time.time() - last))
        print()
        last = time.time()
        result = dns.mass_check(self.blacklist, self.dns_check_threads)
        print('Checked DNS(%ss)' % (time.time() - last))
        last = time.time()
        for domain in result:
            if not result[domain]:
                self.blacklist.remove(domain)
        print('Removed expired domains, now at %s rules(%ss)' %
              (len(self.blacklist), time.time() - last))
        last = time.time()
        for filter_list in [self.blacklist, self.whitelist]:
            for url in list(filter_list):
                if not self.DOMAIN_REGEX.match(url):
                    filter_list.remove(url)
        print('Removed invalid domains(%ss)' % (time.time() - last))

    def to_domain_list(self):
        header = DOMAIN_LIST_HEADER.format(
            version=time.strftime('%d-%b-%Y-%H-%M'),
            title=self.title,
            last_modified=time.strftime('%d %b %Y %H:%M UTC'),
            expires=self.expires,
            homepage=self.homepage,
            license=self.license,
            bitcoin=self.bitcoin)
        return header + '\n'.join(sorted(self.blacklist))

    def to_adblock(self):
        header = ADBLOCK_PLUS_HEADER.format(
            version=time.strftime('%d-%b-%Y-%H-%M'),
            title=self.title,
            last_modified=time.strftime('%d %b %Y %H:%M UTC'),
            expires=self.expires,
            homepage=self.homepage,
            license=self.license,
            bitcoin=self.bitcoin)
        domains = list(self.blacklist) + list(self.ip_blocklist)
        return header + '\n'.join(['||%s^' % i for i in sorted(domains)])

    def to_hosts(self):
        header = HOSTS_HEADER.format(
            version=time.strftime('%d-%b-%Y-%H-%M'),
            title=self.title,
            last_modified=time.strftime('%d %b %Y %H:%M UTC'),
            expires=self.expires,
            homepage=self.homepage,
            license=self.license,
            bitcoin=self.bitcoin)
        return header + \
            '\n'.join(['0.0.0.0 ' + i for i in sorted(self.blacklist)])

    def to_rpz(self):
        return '\n'.join(['%s CNAME .' % i for i in sorted(self.blacklist)])

    def to_ip_blocklist(self):
        return '\n'.join(sorted(self.ip_blocklist))

    def to_ipset_blocklist(self):
        data = 'create %s hash:ip family inet hashsize 4096 maxelem 65536\n' % self.title
        return data + '\n'.join(['add %s %s' % (self.title, ip)
                                 for ip in sorted(self.ip_blocklist)])

    def to_domain_whitelist(self):
        return '\n'.join(sorted(self.whitelist))

    def to_adblock_whitelist(self):
        return '\n'.join(['@@||%s^' % i for i in sorted(self.whitelist)])

    def clear(self):
        self.blacklist = set()
        self.ip_blocklist = set()
        self.whitelist = set()
