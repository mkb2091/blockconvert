import sqlite3
import time
import json

import requests

try:
    import passive_dns_base
except ImportError:
    import dns.passive_dns_base as passive_dns_base


class PassiveDNS(passive_dns_base.PassiveDNS):
    NAME = 'VirusTotal'
    URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip}'

    def _get_domains(self, ip):
        try:
            for _ in range(10):
                r = self.session.get(
                    self.URL.format(
                        api_key=self.api_key, ip=ip))
                time.sleep(15 - r.elapsed.total_seconds())
                if r.status_code == 200:
                    if r.json()['response_code'] == 1:
                        domains = sorted([x['hostname'] for x in r.json()[
                                         'resolutions'] if x['hostname']])
                    else:
                        domains = []
                    self._add_result(ip, domains)
                    print('VirusTotal: %s, %s' % (ip, len(domains)))
                    return domains
                elif r.status_code == 204:
                    print('VirusTotal: 204 - Request rate limit exceeded')
                    time.sleep(15)
                elif r.status_code == 403:
                    print('VirusTotal: 403 Forbidden')
                    return
                else:
                    print(
                        'VirusTotal: Unexpected status code: %s' %
                        r.status_code)
                    return
        except Exception as error:
            print('VirusTotal: %s' % error)


class GetSubdomains:
    def __init__(self, api_key):
        pass

    def get_subdomains(self, domains):
        pass
