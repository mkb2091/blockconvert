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


class DNSCheckerWorker(threading.Thread):
    def __init__(self, session, servers, request_queue, response_queue,
                 request_type=1):
        threading.Thread.__init__(self)
        self.session = session
        self.servers = servers
        self.request_queue = request_queue
        self.response_queue = response_queue
        self.request_type = request_type

    def run(self):
        session = self.session
        servers = self.servers
        request_queue = self.request_queue
        response_queue = self.response_queue
        pos = 0
        try:
            while True:
                old_domain = domain = request_queue.get_nowait()
                if self.request_type == 12:
                    try:
                        ip = ipaddress.ip_address(domain)
                    except ValueError:
                        response_queue.put((old_domain, {}))
                        continue
                    if isinstance(ip, ipaddress.IPv4Address):
                        domain = ip.exploded.split('.')[::-1]
                    else:
                        domain = ipaddress.ip_address(
                            domain).exploded.replace(':', '')[::-1]
                    domain = '.'.join(domain)
                    domain += '.in-addr.arpa.'
                success = False
                for retry in range(3):
                    pos = (pos + 1) % len(servers)
                    server = servers[pos]
                    try:
                        r = session.get(server + urllib.parse.urlencode(
                            {'name': domain.lstrip('.'), 'type': self.request_type}))
                        response_queue.put((old_domain, r.json()))
                        if retry > 0:
                            print('Fixed\n', end='')
                        success = True
                        break
                    except json.JSONDecodeError:
                        print('JSON decode error using %s to check %s' % (server, old_domain) + '\n', end='')
                    except Exception as error:
                        print(server + '\n', end='')
                if not success:
                    print('Could\'t fix\n', end='')
                    response_queue.put((domain, True))
        except queue.Empty:
            pass


class DNSChecker():
    def __init__(self, config):
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
                        if last_modified > one_week_ago:
                            self.cache[domain] = (ip, last_modified)
                    except (ValueError):
                        pass
        except FileNotFoundError:
            pass
        self.argus = dns.argus.PassiveDNS(config.get('argus_api', ''), os.path.join('db', 'argus.db'))
        self.virus_total = dns.virus_total.PassiveDNS(config.get('virus_total_api', ''), os.path.join('db', 'virus_total.db'))
        self.threatminer = dns.threatminer.PassiveDNS(config.get('threatminer_api', ''), os.path.join('db', 'threatminer.db'))

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
        domain_list_length = len(domain_list)
        cache = self.cache
        request_queue = queue.Queue()
        response_queue = queue.Queue()
        results = dict()
        all_from_cache = True
        valid_count = 0
        invalid_count = 0
        for domain in domain_list:
            if not domain.startswith('*'):
                try:
                    results[domain] = cache[domain][0]
                    if cache[domain][0]:
                        valid_count += 1
                    else:
                        invalid_count += 1
                except KeyError:
                    if build_regex.DOMAIN_REGEX.fullmatch(domain):
                        request_queue.put(domain)
                        all_from_cache = False
                    else:
                        results[domain] = ('', time.time())
        if all_from_cache:
            return results
        del domain_list
        threads = []
        for i in range(thread_count):
            thread = DNSCheckerWorker(
                self.session,
                self.servers,
                request_queue,
                response_queue,
                1)
            thread.start()
            threads.append(thread)
        start = time.time()
        initial_length = len(results)
        while any(thread.is_alive() for thread in threads):
            try:
                while True:
                    domain, result = response_queue.get(timeout=0.1)
                    exists = result['Status'] == 0 and 'Answer' in result
                    ip = ''
                    if exists:
                        for answer in result['Answer']:
                            try:
                                ip = ipaddress.IPv4Network(
                                    '%s/32' % answer['data'])
                                exists = exists and (
                                    not any(network.overlaps(ip) for network in RESERVED))
                            except ipaddress.AddressValueError:
                                pass
                    if exists and isinstance(ip, ipaddress.IPv4Network):
                        valid_count += 1
                        ip = ip.network_address.exploded
                    else:
                        invalid_count += 1
                        ip = ''
                    results[domain] = ip
                    cache[domain] = (ip, time.time())
                    if len(results) % 20000 == 19999:
                        print('%s/s %s Valid: %s Invalid: %s ' %
                              (round((len(results) -
                                      initial_length) /
                                     (time.time() -
                                      start), 2), round(len(results) /
                                                        domain_list_length, 5), valid_count, invalid_count))
                        self.save_forward_cache(clean=False)
            except queue.Empty:
                pass
            except Exception as error:
                print(error)
                print(domain, result)
        self.save_forward_cache()
        return results

    def mass_reverse_lookup(self, ip_list, thread_count=40):
        ip_list = set(ip_list)
        results = set()
        function_list = [self.argus.get_domains, self.virus_total.get_domains, self.threatminer.get_domains]
        processes = []
        for function in function_list:
            result_queue = multiprocessing.Queue()
            process = multiprocessing.Process(target=function, args=(list(ip_list), result_queue))
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
