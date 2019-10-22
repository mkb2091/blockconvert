import sqlite3
import time
import json

import requests

try:
    import passive_dns_base
except ImportError:
    import dns.passive_dns_base as passive_dns_base 


class PassiveDNS(passive_dns_base.PassiveDNS):
    NAME = 'ThreatMiner'
    URL = 'https://api.threatminer.org/v2/host.php?q={ip}&rt=2'

    def _get_domains(self, ip):
        try:
            for _ in range(10):
                r = self.session.get(self.URL.format(ip=ip))
                time.sleep(max(0, 6 - r.elapsed.total_seconds()))
                if r.status_code == 200:
                    try:
                        domains = set()
                        for item in r.json()['results']:
                            if '.' in item['domain']:
                                domains.add(item['domain'])
                        domains = list(domains)
                        self._add_result(ip, domains)
                        print('%s: %s, %s' % (self.NAME, ip, len(domains)))
                        return domains
                    except TypeError:
                        print('%s: Received unexpected data' % self.NAME)
                else:
                    print('%s: Recieved unexpected status code:%s' % (self.NAME, r.status_code))
                    return
        except Exception as error:
            print('%s: %s' % (self.NAME, error))
