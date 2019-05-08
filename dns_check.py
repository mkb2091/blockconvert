import threading
import queue
import json
import time
import os

import requests

class DNSCheckerWorker(threading.Thread):
    def __init__(self, session, servers, request_queue, response_queue):
        threading.Thread.__init__(self)
        self.session = session
        self.servers = servers
        self.request_queue = request_queue
        self.response_queue = response_queue
    def run(self):
        session = self.session
        servers = self.servers
        request_queue = self.request_queue
        response_queue = self.response_queue
        pos = 0
        try:
            while True:
                domain = request_queue.get_nowait()
                success = False
                for retry in range(3):
                    pos = (pos + 1) % len(servers)
                    server = servers[pos]
                    try:
                        r = session.get(server + domain)
                        response_queue.put((domain, r.json()['Status'] == 0))
                        if retry > 0:
                            print('Fixed\n', end='')
                        success = True
                        break
                    except Exception as error:
                        print(server+'\n', end='')
                if not success:
                    print('Could\'t fix\n', end='')
                    response_queue.put((domain, True))
        except queue.Empty:
            pass

class DNSChecker():
    def __init__(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'DNSExistsDomainChecker'
        self.session.headers['accept'] = 'application/dns-json'
        self.servers = ['https://dns.google.com/resolve?name=',
                        'https://cloudflare-dns.com/dns-query?type=1&name=',
                        'https://doh.securedns.eu/dns-query?name=',]
        self.cache = dict()
        try:
            with open('dns_cache.txt') as file:
                for line in file:
                    try:
                        domain, exists, last_modified = line.rstrip().split(',')
                        last_modified = int(last_modified)
                        if last_modified > (time.time() - 60*60*24*7):
                            self.cache[domain] = [bool(exists), int(last_modified)]
                    except (ValueError):
                        pass
        except FileNotFoundError:
            pass
    def mass_check(self, domain_list, thread_count=40):
        domain_list_length = len(domain_list)
        cache = self.cache
        request_queue = queue.Queue()
        response_queue = queue.Queue()
        results = dict()
        for domain in sorted(domain_list):
            try:
                results[domain] = cache[domain][0]
            except KeyError:
                request_queue.put(domain)
        del domain_list
        threads = []
        for i in range(thread_count):
            thread = DNSCheckerWorker(self.session, self.servers, request_queue,
                                      response_queue)
            thread.start()
            threads.append(thread)
        start = time.time()
        initial_length = len(results)
        while any(thread.is_alive() for thread in threads):
            try:
                while True:
                    domain, exists = response_queue.get(timeout=1.0)
                    results[domain] = exists
                    cache[domain] = [exists, time.time()]
                    if len(results) % 2000 == 1999:
                        print(round((len(results) - initial_length)/(time.time() - start), 2),
                              round(len(results)/domain_list_length, 5))
                        lines = [[i, '1'if cache[i][0] else '', str(int(cache[i][1]))] for i in sorted(cache)]
                        with open('temp', 'w') as file:
                            file.write('\n'.join(','.join(line) for line in lines))
                        os.replace('temp', 'dns_cache.txt')
            except queue.Empty:
                pass
        lines = [[i, '1'if cache[i][0] else '', str(int(cache[i][1]))] for i in sorted(cache)]
        with open('temp', 'w') as file:
            file.write('\n'.join(','.join(line) for line in lines))
        os.replace('temp', 'dns_cache.txt')
        return results
