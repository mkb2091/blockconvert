import sqlite3
import time
import json

import requests

import passive_dns_base


class PassiveDNS(passive_dns_base.PassiveDNS):
    URL = 'https://api.mnemonic.no/pdns/v3/{ip}'

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
                        return domains
                    except TypeError:
                        try:
                            if r.json()[
                                    'metaData']['millisUntilResourcesAvailable'] / 1000 > 30 * 60:
                                return
                            time.sleep(
                                r.json()['metaData']['millisUntilResourcesAvailable'] / 1000)
                            time.sleep(1)
                        except KeyError as error:
                            print(error)
                            time.sleep(1)
                            break
        except Exception as error:
            print(error)
