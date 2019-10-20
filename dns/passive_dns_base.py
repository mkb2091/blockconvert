import random
import sqlite3
import time
import json

import requests


class PassiveDNS:
    NAME = 'PassiveDNSBase'
    def __init__(self, api_key, path):
        self.api_key = api_key
        self.session = requests.Session()
        self.conn = sqlite3.connect(path)
        cursor = self.conn.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS PassiveDNS (ip PRIMARY KEY, domains, last_modified, last_used)')
        self.conn.commit()

    def _add_result(self, ip, domains):
        cursor = self.conn.cursor()
        cursor.execute(
            'REPLACE INTO PassiveDNS VALUES (?, ?, ?, ?)', (ip, json.dumps(domains), int(
                time.time()), int(
                time.time())))
        self.conn.commit()

    def get_domains(self, ips, result_queue):
        total_domains = set()
        ips = list(set(ips))
        ips_left = set(ips)
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT ip, domains, last_modified FROM PassiveDNS WHERE ip IN (%s)' %
            (','.join(
                ['?'] *
                len(ips))),
            ips)
        result = cursor.fetchall()
        random.shuffle(result)
        for (ip, _, _) in result:
            ips_left.remove(ip)
        print('%s: %s new - %s total' % (self.NAME, len(ips_left), len(ips)))
        ips_left = list(ips_left)
        random.shuffle(ips_left)
        api_working = True
        try:
            for ip in ips_left:
                fetched = self._get_domains(ip)
                if fetched is not None:
                    total_domains.update(fetched)
                else:
                    api_working = False
                    break
        except KeyboardInterrupt:
            print('KeyboardInterrupt, skipping fetching new ips')
            api_working = False
        for (ip, domains, last_modified) in result:
            domains = json.loads(domains)
            if time.time() > (last_modified + 7 * 24 * 60 * 60) and api_working:
                result = self._get_domains(ip)
                if result is not None:
                    total_domains.update(result)
                else:
                    total_domains.update(domains)
                    api_working = False
            else:
                total_domains.update(domains)
        try:
            result_queue.put(list(total_domains))
        except KeyboardInterrupt:
            print('Error while transferring data')
            result_queue.put(list(total_domains))
        print('%s: %s' % (self.NAME, len(total_domains)))
