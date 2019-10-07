import sqlite3
import time
import json

import requests


class PassiveDNS:
    URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip}'

    def __init__(self, api_key, path):
        self.api_key = api_key
        self.session = requests.Session()
        self.conn = sqlite3.connect(path)
        cursor = self.conn.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS VirusTotalPassiveDNS (ip PRIMARY KEY, domains, last_modified, last_used)')
        self.conn.commit()

    def get_domains(self, ips):
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT ip, domains, last_modified FROM VirusTotalPassiveDNS WHERE ip IN (%s)' %
            (','.join(
                ['?'] *
                len(ips))),
            ips)
        result = cursor.fetchall()
        total_domains = set()
        ips_left = set(ips)
        for (ip, _, _) in result:
            ips_left.remove(ip)
        for ip in ips_left:
            result = self._get_domains(ip)
            if result is not None:
                total_domains.update(result)
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

    def _get_domains(self, ip):
        for _ in range(10):
            try:
                r = self.session.get(self.URL.format(api_key=self.api_key, ip=ip))
                if r.status_code == 200:
                    if r.json()['response_code'] == 1:
                        domains = sorted([x['hostname'] for x in r.json()['resolutions']])
                    else:
                        domains = []
                    cursor = self.conn.cursor()
                    cursor.execute('REPLACE INTO VirusTotalPassiveDNS VALUES (?, ?, ?, ?)',
                                   (ip, json.dumps(domains), int(time.time()), int(time.time())))
                    self.conn.commit()
                    return domains
                elif r.status_code == 204:
                    print('VirusTotal: 204 - Request rate limit exceeded')
                    time.sleep(15)
                elif r.status_code == 403:
                    print('VirusTotal: 403 Forbidden')
                    return 
                else:
                    return []
            except Exception as error:
                print(error)
                time.sleep(5)


class GetSubdomains:
    def __init__(self, api_key):
        pass

    def get_subdomains(self, domains):
        pass
