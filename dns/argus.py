import sqlite3
import time
import json

import requests

try:
    import passive_dns_base
except ImportError:
    import dns.passive_dns_base as passive_dns_base 


class PassiveDNS(passive_dns_base.PassiveDNS):
    NAME = 'Argus'
    URL = 'https://api.mnemonic.no/pdns/v3/{ip}?limit=100000'

    def _get_domains(self, ip):
        try:
            for _ in range(10):
                r = self.session.get(self.URL.format(ip=ip))
                if r.status_code == 200:
                    try:
                        domains = set()
                        for item in r.json()['data']:
                            if '.' in item['query']:
                                domains.add(item['query'])
                        domains = list(domains)
                        self._add_result(ip, domains)
                        print('Argus: %s, %s' % (ip, len(domains)))
                        return domains
                    except TypeError:
                        print('Argus: Received unexpected data')
                elif r.status_code == 402:
                    try:
                        millisUntilResourcesAvailable = int(r.json()['metaData']['millisUntilResourcesAvailable']) / 1000
                        print('Argus: Resource Available in %s' % millisUntilResourcesAvailable)
                        if millisUntilResourcesAvailable > 30 * 60:
                            return
                        time.sleep(millisUntilResourcesAvailable)
                        time.sleep(1)
                    except KeyError as error:
                        print('Argus: %s' % error)
                        time.sleep(1)
                        break
                else:
                    print('Argus: Recieved unexpected status code:', r.status_code)
                    return
        except Exception as error:
            print('Argus: %s' % error)
