import sqlite3
import time
import json

import requests

class PassiveDNS:
    def __init__(self, api_key, path):
        self.api_key = api_key
        self.session = requests.Session()
        self.conn = sqlite3.connect(path)
        cursor = self.conn.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS PassiveDNS (ip PRIMARY KEY, domains, last_modified, last_used)')
        self.conn.commit()

    def get_domains(self, ips):
        total_domains = set()
        ips_left = set(ips)
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT ip, domains, last_modified FROM PassiveDNS WHERE ip IN (%s)' %
            (','.join(
                ['?'] *
                len(ips))),
            ips)
        result = cursor.fetchall()
        for (ip, _, _) in result:
            ips_left.remove(ip)
        for ip in ips_left:
            fetched = self._get_domains(ip)
            if fetched is not None:
                total_domains.update(fetched)
        for (ip, domains, last_modified) in result:
            domains = json.loads(domains)
            if time.time() > (last_modified + 7 * 24 * 60 * 60):
                result = self._get_domains(ip)
                if result is not None:
                    total_domains.update(result)
                else:
                    total_domains.update(domains)
            else:
                total_domains.update(domains)
        return total_domains
