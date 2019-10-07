import sqlite3
import time
import json

import requests

import passive_dns_base

class PassiveDNS(passive_dns_base.PassiveDNS):
    URL = 'https://api.mnemonic.no/pdns/v3/'

    def _get_domains(self, ip):
        pass

    
