import multiprocessing
import threading
import ipaddress
import urllib
import queue
import json
import time
import os

import requests

import build_regex
import dns.argus
import dns.virus_total
import dns.threatminer
import dns.dns_over_https

RESERVED = [
    ipaddress.IPv4Network('0.0.0.0/8'),
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('100.64.0.0/10'),
    ipaddress.IPv4Network('127.0.0.0/8'),
    ipaddress.IPv4Network('169.254.0.0/16'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.0.0.0/24'),
    ipaddress.IPv4Network('192.0.2.0/24'),
    ipaddress.IPv4Network('192.88.99.0/24'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('198.18.0.0/15'),
    ipaddress.IPv4Network('198.51.100.0/24'),
    ipaddress.IPv4Network('203.0.113.0/24'),
    ipaddress.IPv4Network('224.0.0.0/4'),
    ipaddress.IPv4Network('240.0.0.0/4'),
    ipaddress.IPv4Network('255.255.255.255/32')
]


class DNSChecker():
    def __init__(self, config, update, disable_networking):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'DOH'
        self.session.headers['Accept'] = 'application/dns-json'
        self.session2 = requests.Session()
        self.session2.headers['User-Agent'] = 'DOH'
        self.session2.headers['Accept'] = '*/*'
        self.servers = ['https://dns.google.com/resolve?',
                        'https://cloudflare-dns.com/dns-query?', ]
        self.cache = dict()
        self.reverse_cache = dict()
        one_week_ago = (time.time() - 60 * 60 * 24 * 7)
        try:
            with open('dns_cache.txt') as file:
                for line in file:
                    try:
                        split = line.rstrip().split(',')
                        if len(split) == 3:
                            domain, ip, last_modified = split
                        else:
                            domain, last_modified = split
                            ip = ''
                        last_modified = int(last_modified)
                        if (not update) or (last_modified > one_week_ago):
                            self.cache[domain] = (ip, last_modified)
                    except (ValueError):
                        pass
        except FileNotFoundError:
            pass
        self.argus = dns.argus.PassiveDNS(
            config.get(
                'argus_api', ''), os.path.join(
                'db', 'argus.db'), update, disable_networking)
        self.virus_total = dns.virus_total.PassiveDNS(
            config.get(
                'virus_total_api', ''), os.path.join(
                'db', 'virus_total.db'), update, disable_networking)
        self.threatminer = dns.threatminer.PassiveDNS(
            config.get(
                'threatminer_api', ''), os.path.join(
                'db', 'threatminer.db'), update, disable_networking)
        self.doh = dns.dns_over_https.DNSLookupDOH(
            os.path.join(
                'db',
                'dns_cache.db'),
            update,
            thread_count=80,
            disable_network=disable_networking)

    def clean_forward_cache(self):
        cache = self.cache
        for domain in list(cache):
            now = cache[domain]
            if not ('*' not in domain
                    and build_regex.DOMAIN_REGEX.fullmatch(domain)
                    and (now[0] == '' or build_regex.IP_REGEX.fullmatch(now[0]))):
                del cache[domain]

    def save_forward_cache(self, clean=True):
        if clean:
            self.clean_forward_cache()
        with open('temp', 'w') as file:
            for domain in sorted(self.cache):
                if self.cache[domain][0]:
                    file.write(
                        '%s,%s,%s\n' %
                        (domain, self.cache[domain][0], int(
                            self.cache[domain][1])))
                else:
                    file.write('%s,%s\n' %
                               (domain, int(self.cache[domain][1])))
        os.replace('temp', 'dns_cache.txt')

    def mass_check(self, domain_list, thread_count=40):
        return self.doh.get_dns_results(domain_list)

    def mass_reverse_lookup(self, ip_list, thread_count=40):
        ip_list = set(ip_list)
        results = set()
        function_list = [
            self.argus.get_domains,
            self.virus_total.get_domains,
            self.threatminer.get_domains]
        processes = []
        for function in function_list:
            result_queue = multiprocessing.Queue()
            process = multiprocessing.Process(
                target=function, args=(
                    list(ip_list), result_queue))
            process.start()
            processes.append((process, result_queue))
        for (process, result) in processes:
            try:
                results.update(result.get())
            except KeyboardInterrupt:
                results.update(result.get())
        print('Found %s domains, performing dns check' % len(results))
        print('Performed reverse DNS, and passive DNS lookup')
        self.mass_check(results, thread_count)
        print('Checked IP addresses')
        cache = self.cache
        checked_domains = []
        for domain in cache:
            if cache[domain][0] in ip_list:
                checked_domains.append(domain)
        print(
            'Added domains which resolve to malware IP addresses: %s' %
            len(checked_domains))
        return checked_domains
