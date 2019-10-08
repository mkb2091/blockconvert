import sqlite3
import time
import json

import requests

import passive_dns_base


class PassiveDNS(passive_dns_base.PassiveDNS):
    URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip}'

    def _get_domains(self, ip):
        try:
            for _ in range(10):
                r = self.session.get(
                    self.URL.format(
                        api_key=self.api_key, ip=ip))
                if r.status_code == 200:
                    if r.json()['response_code'] == 1:
                        domains = sorted([x['hostname']
                                          for x in r.json()['resolutions']])
                    else:
                        print(r.json()['response_code'])
                        domains = []
                    self._add_result(ip, domains)
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


class GetSubdomains:
    def __init__(self, api_key):
        pass

    def get_subdomains(self, domains):
        pass
