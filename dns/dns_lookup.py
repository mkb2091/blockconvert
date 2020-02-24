import sqlite3
import time

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
            'CREATE TABLE IF NOT EXISTS DNSLookupCache (domain_id INTEGER PRIMARY KEY AUTOINCREMENT, domain, last_modified, ttl)')
        cursor.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_domain ON DNSLookupCache(domain)'
        )
        cursor.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_lookup_domain_ids ON DNSLookupCache(domain_id)'
        )
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS DNSResultCache (domain_id INTEGER, ip_address)')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_result_domain_ids ON DNSResultCache(domain_id)'
        )
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_result_ip_address ON DNSResultCache(ip_address)'
        )
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
        self._add_results([(domain, ips, ttl)], last_modified)

    def _add_results(self, results, last_modified):
        results = dict([(domain, (ips, ttl)) for (domain, ips, ttl) in results])
        results = [(domain, results[domain][0], results[domain][1]) for domain in results]
        cursor = self.conn.cursor()
        domain_to_domain_id = dict()
        for (domain, _, _) in results:
            cursor.execute(
                'SELECT domain, domain_id FROM DNSLookupCache WHERE domain = ?', (domain, ))
            for (domain, domain_id) in cursor.fetchall():
                domain_to_domain_id[domain] = domain_id
        print(len(results), len(domain_to_domain_id))
        cursor.executemany(
            'REPLACE INTO DNSLookupCache (domain_id, domain, last_modified, ttl) VALUES (?, ?, ?, ?)', [
                (domain_to_domain_id[domain], domain, last_modified, ttl) for (
                    domain, _, ttl) in results if domain in domain_to_domain_id])
        cursor.executemany(
            'INSERT INTO DNSLookupCache (domain, last_modified, ttl) VALUES (?, ?, ?)', [
                (domain, last_modified, ttl) for (
                    domain, _, ttl) in results if domain not in domain_to_domain_id])
        domain_to_domain_id = dict()
        for (domain, _, _) in results:
            cursor.execute(
                'SELECT domain, domain_id FROM DNSLookupCache WHERE domain = ?', (domain, ))
            for (domain, domain_id) in cursor.fetchall():
                domain_to_domain_id[domain] = domain_id
        cursor.executemany('DELETE FROM DNSResultCache WHERE domain_id = ?',
                           [(domain_to_domain_id[domain], ) for domain in domain_to_domain_id])
        cursor.executemany(
            'INSERT INTO DNSResultCache VALUES (?, ?)', [
                (domain_to_domain_id[domain], ip) for (
                    domain, ips, _) in results for ip in ips if domain in domain_to_domain_id])
        self.conn.commit()

    def get_dns_results(self, domain_list):
        results = list()
        domain_list = list(set(domain_list))
        cursor = self.conn.cursor()
        amount = 100
        results = dict()
        expired = set()
        for i in range(int(len(domain_list) / amount) + 1):
            current = domain_list[amount * i: amount * (i + 1)]
            cursor.execute(
                'SELECT domain, ip_address, last_modified, ttl FROM DNSLookupCache LEFT JOIN DNSResultCache ON DNSLookupCache.domain_id = DNSResultCache.domain_id WHERE domain IN (%s)' %
                (','.join(
                    ['?'] *
                    len(current))),
                current)
            for (domain, ip, last_modified, ttl) in cursor.fetchall():
                if ip:
                    results.append(ip)
                if self.do_update and time.time() > (last_modified + ttl):
                    expired.add((domain, last_modified + ttl))
        expired = [
            domain for (
                domain,
                _) in sorted(
                expired,
                key=lambda x: x[1])]
        failure = False
        print('Found %s existing records' % len(results))
        new = [domain for domain in domain_list if domain not in results]
        if not self.disable_network:
            print('Looking up %s new domain' % len(new))
            i = 0
            to_add = list()
            for result in self.lookup_domains(new):
                if isinstance(result, str) or result is None:
                    print('Domain lookup failed:', result)
                    failure = True
                    break
                else:
                    (domain, ips, ttl) = result
                    to_add.append((domain, ips, ttl))
                    if domain in domain_list:
                        i += 1
                        if i % 100 == 99:
                            print('%s / %s\n' % (i, len(new)), end='')
                            self._add_results(to_add, time.time())
                            to_add.clear()
                        if ips:
                            results.append(domain)
            self._add_results(to_add, time.time())

            if not failure:
                i = 0
                to_add = list()
                print('Looking up %s expired records' % len(expired))
                for result in self.lookup_domains(expired):
                    if isinstance(result, str) or result is None:
                        print('Domain lookup failed:', result)
                        break
                    else:
                        (domain, ips, ttl) = result
                        to_add.append((domain, ips, ttl))
                        if ips:
                            results.append(domain)
                        if domain in domain_list:
                            i += 1
                            if i % 100 == 99:
                                print('%s / %s\n' % (i, len(expired)), end='')
                                self._add_results(to_add, time.time())
                                to_add.clear()
                self._add_results(to_add, time.time())
        self.conn.commit()
        return results

    def reverse_lookup(self, ip_list):
        ip_list = list(set(ip_list))
        cursor = self.conn.cursor()
        results = set()
        amount = 100
        for i in range(int(len(ip_list) / amount) + 1):
            current = ip_list[amount * i: amount * (i + 1)]
            cursor.execute(
                'SELECT domain, ip_address, last_modified, ttl FROM DNSLookupCache LEFT JOIN DNSResultCache ON DNSLookupCache.domain_id = DNSResultCache.domain_id WHERE ip_address IN (%s)' %
                (','.join(
                    ['?'] *
                    len(current))),
                current)
            for (domain, _, _, _) in cursor.fetchall():
                results.add(domain)
            print(len(results))
        return list(results)

    def get_subdomains(self, domain_list):
        domain_list = list(set(domain_list))
        cursor = self.conn.cursor()
        results = list()
        amount = 100
        print('Checking database for subdomains')
        for i in range(int(len(domain_list) / amount) + 1):
            current = domain_list[amount * i: amount * (i + 1)]
            cursor.execute('SELECT domain, last_modified, ttl FROM DNSLookupCache WHERE %s'
                           % (' OR '.join(
                               ['domain LIKE ?'] *
                               len(current))),
                           ['%.' + domain.lstrip('.') for domain in current])
            for (domain, _, _) in cursor.fetchall():
                results.append(domain)
            print(len(results))
        return results
