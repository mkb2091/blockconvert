import threading
import ipaddress
import urllib
import queue
import json

import requests

try:
    import dns_lookup
except ImportError:
    import dns.dns_lookup as dns_lookup

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
    def __init__(self, session, servers, domain_list, response_queue,
                 request_type=1):
        threading.Thread.__init__(self)
        self.session = session
        self.servers = servers
        self.domain_list = domain_list
        self.response_queue = response_queue
        self.request_type = request_type
        self.pos = 0

    def lookup_domain(self, domain):
        for retry in range(3):
            self.pos = (self.pos + 1) % len(self.servers)
            server = self.servers[self.pos]
            try:
                r = self.session.get(server + urllib.parse.urlencode(
                    {'name': domain.lstrip('.'), 'type': self.request_type}))
                try:
                    result = r.json()
                    ttl = 7 * 24 * 60 * 60
                    if result['Status'] in (0, 2, 3):
                        ips = []
                        for answer in result.get('Answer', ()):
                            ttl = answer['TTL']
                            try:
                                ip = ipaddress.IPv4Network(
                                    '%s/32' % answer['data'])
                                if any(network.overlaps(ip)
                                        for network in RESERVED):
                                    print(
                                        'IP (%s) in reserved block' %
                                        ip.network_address.exploded)
                                else:
                                    ips.append(ip.network_address.exploded)
                            except ipaddress.AddressValueError:
                                temp = self.lookup_domain(answer['data'])
                                if temp is not None:
                                    (_domain, ips, _ttl) = temp
                                    ips.extend(ips)
                                else:
                                    print(
                                        'Failed conversion to IPv4:', answer['data'])

                        self.response_queue.put((domain, ips, ttl))
                        return (domain, ips, ttl)
                    else:
                        print(result)
                except json.JSONDecodeError:
                    print(
                        'JSON decode error using %s to check %s' %
                        (server, domain) + '\n', end='')
                except Exception as error:
                    print(type(error), error)
                if retry > 0:
                    print('Fixed\n', end='')
                break
            except Exception as error:
                print(
                    'Server: %s, ErrorType: %s, Error: %s\n' %
                    (server, type(error), error), end='')

    def run(self):
        for domain in self.domain_list:
            self.lookup_domain(domain)


class DNSLookupDOH(dns_lookup.DNSLookup):
    SERVERS = ['https://dns.google.com/resolve?',
               'https://cloudflare-dns.com/dns-query?', ]

    def lookup_domains(self, domains):
        pos = 0
        domain_lists = [[] for _ in range(self.thread_count)]
        for domain in domains:
            pos = (pos + 1) % self.thread_count
            domain_lists[pos].append(domain)
        result_queue = queue.Queue()
        threads = []
        for domain_sublist in domain_lists:
            thread = DNSCheckerWorker(
                self.session,
                self.SERVERS,
                domain_sublist,
                result_queue)
            thread.start()
            threads.append(thread)
        while threads:
            threads = [thread for thread in threads if thread.is_alive()]
            try:
                while True:
                    yield result_queue.get(timeout=0.5)
            except queue.Empty:
                pass
