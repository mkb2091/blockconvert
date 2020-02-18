import random
import sqlite3
import time
import json

import requests


class DNSLookup:
    def __init__(
            self,
            path,
            do_update=True,
            thread_count=40,
            commit_frequency=10,
            disable_network=False):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'DOH'
        self.session.headers['Accept'] = 'application/dns-json'
        self.do_update = do_update
        self.thread_count = 40
        self.conn = sqlite3.connect(path)
        cursor = self.conn.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS DNSLookupCache (domain PRIMARY KEY, ip_addresses, last_modified, ttl)')
        self.conn.commit()
        self.last_commit = 0
        self.commit_frequency = 10
        self.disable_network = disable_network

    def lookup_domains(self, domain):
        raise NotImplementedError

    def _add_result(
            self,
            domain,
            ips,
            ttl=7 * 24 * 60 * 60,
            last_modified=None,
            commit=True):
        cursor = self.conn.cursor()
        if last_modified is None:
            last_modified = time.time()
        cursor.execute(
            'REPLACE INTO DNSLookupCache VALUES (?, ?, ?, ?)',
            (domain,
             json.dumps(ips).replace(
                 ' ',
                 ''),
                ttl,
                int(last_modified)))
        if commit and time.time() > self.commit_frequency + self.last_commit:
            self.conn.commit()
            self.last_commit = time.time()

    def _add_results(self, results, last_modified):
        for (domain, ips, ttl) in results:
            self._add_result(domain, ips, ttl, last_modified, commit=False)
        self.conn.commit()

    def get_dns_results(self, domain_list):
        results = dict()
        domain_list = list(set(domain_list))
        cursor = self.conn.cursor()
        fetched = list()
        for i in range(int(len(domain_list) / 100) + 1):
            current = domain_list[100 * i: 100 * (i + 1)]
            cursor.execute(
                'SELECT domain, ip_addresses, ttl, last_modified FROM DNSLookupCache WHERE domain IN (%s)' %
                (','.join(
                    ['?'] *
                    len(current))),
                current)
            fetched.extend(cursor.fetchall())
        domain_list = set(domain_list)
        result = fetched
        expired = list()
        for (domain, ips, ttl, last_modified) in result:
            ips = json.loads(ips)
            results[domain] = tuple(ips)
            if self.do_update and time.time() > (last_modified + ttl):
                expired.append((domain, last_modified + ttl))
        failure = False
        print('Found %s existing records' % len(results))
        new = [domain for domain in domain_list if domain not in results]
        i = 0
        print('Looking up %s new domain' % len(new))
        if not self.disable_network:
            for result in self.lookup_domains(new):
                if isinstance(result, str) or result is None:
                    print('Domain lookup failed:', result)
                    failure = True
                    break
                else:
                    (domain, ips, ttl) = result
                    self._add_result(
                        domain, ips, ttl, last_modified=time.time())
                    if domain in domain_list:
                        if domain not in results:
                            i += 1
                            if i % 100 == 99:
                                print('%s / %s\n' % (i, len(new)), end='')
                        results[domain] = tuple(ips)
            if not failure:
                print('Looking up %s expired records' % len(expired))
                for (i, result) in self.lookup_domains(expired):
                    if isinstance(result, str) or result is None:
                        print('Domain lookup failed:', result)
                        failure = True
                        break
                    else:
                        (ips, ttl) = result
                        self._add_result(
                            self, domain, ips, ttl, last_modified=time.time())
                        results[domain] = tuple(ips)
        self.conn.commit()
        return results
