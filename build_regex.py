import re

class BuildRegex():
    def __init__(self):
        self.generate_domain_regex()
        self.generate_host_regex()
        self.generate_adblock_regex()
        self.generate_dns_reponse_policy_zone_regex()
        self.generate_master_regex()
        self.generate_url_regex()

    def generate_domain_regex(self):
        with open('tld_list.txt') as file:
            self.TLDS = [tld for tld in file.read().lower().splitlines() if '#' not in tld]
        tlds = self.TLDS.copy()
        tld_dict = dict()
        for tld in tlds:
            if tld[0] in tld_dict:
                if tld[1] in tld_dict[tld[0]]:
                    tld_dict[tld[0]][tld[1]].append(tld[2:])
                else:
                    tld_dict[tld[0]][tld[1]] = [tld[2:]]
            else:
                tld_dict[tld[0]] = {tld[1]: [tld[2:]]}
        tld_regex = []
        for first_letter in sorted(tld_dict, reverse=True):
            now = []
            for second_letter in sorted(tld_dict[first_letter],
                                        key=lambda x: len(tld_dict[first_letter][x]),
                                        reverse=True):
                current = '|'.join([re.escape(i) for i in sorted(tld_dict[first_letter][second_letter], key=len,
                                                                 reverse=True)])
                now.append('(?:%s(?:%s))' % (second_letter, current))
            now = '|'.join(now)
            tld_regex.append('(?:%s(?:%s))' % (re.escape(first_letter), now))
        tld_regex = r'(?:%s|\*)' % '|'.join(tld_regex)
        ip_v4 = '[12]?[0-9]{,2}[.][12]?[0-9]{,2}[.][12]?[0-9]{,2}[.][12]?[0-9]{,2}'
        ip_v6 = '[0-9a-f]{,4}(?:[:][0-9a-f]{,4}){2,8}'
        ip = '(?:{ip_v4}|{ip_v6})'.format(**locals())
        self.IP_REGEX = re.compile(ip)
        segment = r'(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)'
        self.DOMAIN_STRING =  '[.]?((?:(?:\*[.])?{segment}(?:[.]{segment})*[.]{tld_regex})|{ip})[.]?'.format(**locals())
        self.DOMAIN_REGEX = re.compile(self.DOMAIN_STRING)
    def generate_url_regex(self):
        domain_string = self.DOMAIN_STRING
        protocol = r'(?:(?:(?:https?|ftps?)?[:])?//)?'
        ending = r'(?:/[/a-zA-Z0-9_?&=.%-]*)?'
        self.URL_STRING = r'{protocol}{domain_string}{ending}'.format(**locals())
        self.URL_REGEX = re.compile(self.URL_STRING)
    def generate_host_regex(self):
        ips = ['0.0.0.0', '127.0.0.1', '::1']
        ip_string = '(?:%s)' % '|'.join('(?:%s)' % re.escape(ip) for ip in ips)
        domain_string = self.DOMAIN_STRING
        self.HOSTS_STRING = r'{ip_string}\s+{domain_string}\s*(?:\#.*)?'.format(**locals())
    def generate_adblock_regex(self):
        domain_string = self.DOMAIN_STRING
        url_string = r'(?:(?:(?:http(?:s|\*)?)?[:])(?:(?:\/\/)|\*))?{domain_string}\/?'.format(**locals())
        start = r'(?:\|?\|)?'
        options = ['popup', r'first\-party', r'\~third\-party', r'third\-party']
        options_noop = ['important', r'domain\=\2']
        options_string = '(?:%s)' % '|'.join('(?:%s)' % i for i in options)
        options_other = '(?:%s)' % '|'.join('(?:%s)' % i for i in ['[a-z~-]+'] + options_noop)
        options_full = r'\$(?:(?:(?:{options_other}[,])*{options_string}(?:[,]{options_other})*)|%s)'.format(**locals())
        options_full%= '|'.join('(?:%s)' % i for i in options_noop)
        ending = r'[*]?\|?\^?(?:{options_full})?(?:\s+(?:(?:\!.*)|(?:\#.*))?)?'.format(**locals())
        href_element_hiding = r'\#\#\[href\^?\=\"{url_string}\"\]'.format(**locals())
        self.ADBLOCK_STRING = r'(?:{start}{url_string}{ending})|(?:{href_element_hiding})'.format(**locals())
    def generate_dns_reponse_policy_zone_regex(self):
        domain_string = self.DOMAIN_STRING
        self.RPZ_STRING = r'{domain_string}\s+cname\s+[.]\s*(?:[;].*)?'.format(**locals())

    def generate_master_regex(self):
        self.REGEX_STRING = '(?:%s)|(?:%s)|(?:%s)' % (self.HOSTS_STRING, self.ADBLOCK_STRING, self.RPZ_STRING)
        self.REGEX = re.compile(self.REGEX_STRING)
temp = BuildRegex()
REGEX = temp.REGEX
DOMAIN_REGEX = temp.DOMAIN_REGEX
IP_REGEX = temp.IP_REGEX
TLDS = temp.TLDS
URL_REGEX = temp.URL_REGEX
del temp
