import json
import os
import re

def generate_tld_regex():
    with open('tld_list.txt') as file:
        tlds = [tld for tld in file.read().lower().splitlines() if '#' not in tld]
    tld_dict = dict()
    for tld in tlds:
        try:
            tld_dict[tld[0]].append(tld[1:])
        except KeyError:
            tld_dict[tld[0]] = [tld[1:]]
    TLD_REGEX = []
    for first_letter in sorted(tld_dict, key=lambda x:len(tld_dict[x]), reverse=True):
        now = '|'.join(['(?:%s)' % i for i in tld_dict[first_letter]])
        TLD_REGEX.append('(?:%s(?:%s))' % (first_letter, now))
    TLD_REGEX = '(?:%s)' % '|'.join(TLD_REGEX)
    return TLD_REGEX

class BlockList():
    DOMAIN_STRING = '(?:\*[.])?([a-z0-9_-]+(?:[.][a-z0-9_-]+)*[.]%s)[.]?' % generate_tld_regex()
    ADBLOCK_STRING = rf'(?:(?:(?:\|\|)?[.]?)|(?:(?:(?:https?)?[:])?//)?)?{DOMAIN_STRING}/?\|?(?:\^)?(?:\$(?:[,]?(?:(?:popup)|(?:first\-party)|(?:third\-party))))?'
    HOSTS_STRING = rf'(?:(?:0\.0\.0\.0)|(?:127\.0\.0\.1)|(?:\:\:1))\s+{DOMAIN_STRING}\s*(?:\#.*)?'
    DOMAIN_REGEX = re.compile(DOMAIN_STRING)
    ADBLOCK_REGEX = re.compile(ADBLOCK_STRING)
    HOSTS_REGEX = re.compile(HOSTS_STRING)
    def __init__(self):
        self.blocked_hosts = set()
        self.whitelist = set()
    def add_file(self, path):
        with open(path) as file:
            data = file.read().lower()
        try:
            data = json.loads(data)
            if ('action_map' in data and isinstance(data['action_map'], dict)
                and 'snitch_map' in data and isinstance(data['snitch_map'], dict)):
                self.parse_privacy_badger(data)
        except json.JSONDecodeError:
            for line in data.splitlines():
                if not self.parse_hosts(line):
                    self.parse_adblock(line)
    def parse_privacy_badger(self, data):
        temp_whitelist = set()
        for x in data['snitch_map']:
            temp_whitelist.update(data['snitch_map'])
        for i in data['action_map']:
            if self.DOMAIN_REGEX.fullmatch(i):
                if isinstance(data['action_map'][i], dict) and 'heuristicaction' in data['action_map'][i]:
                    if data['action_map'][i]['heuristicaction'] == 'block':
                        if i not in temp_whitelist:
                            self.blocked_hosts.add(i)
                    elif data['action_map'][i]['heuristicaction'] == 'cookieblock':
                        self.whitelist.add(i)
    def parse_hosts(self, line):
        match = self.HOSTS_REGEX.fullmatch(line)
        if match:
            self.blocked_hosts.add(match.group(1))
            return True
    def parse_adblock(self, line):
        if '!' not in line:
            if line.startswith('@@'):
                match = self.ADBLOCK_REGEX.fullmatch(line[2:])
                if match:
                    self.whitelist.add(match.group(1))
            else:
                match = self.ADBLOCK_REGEX.fullmatch(line)
                if match:
                    self.blocked_hosts.add(match.group(1))
    def clean(self):
        for i in self.whitelist:
            try:
                self.blocked_hosts.remove(i)
            except KeyError:
                pass
    def to_adblock(self):
        return '\n'.join(['||%s^' % i for i in sorted(self.blocked_hosts)])
    def to_hosts(self):
        return '\n'.join(['0.0.0.0 ' + i for i in sorted(self.blocked_hosts)])
    def to_privacy_badger(self):
        base = '{"action_map":{%s},"snitch_map":{%s}, "settings_map":{}}'
        url_string = '"%s":{"userAction":"","dnt":false,"heuristicAction":"block","nextUpdateTime":0}'
        return base % (','.join([url_string % i for i in sorted(self.blocked_hosts)]),
                       ','.join(['"%s":["1","2","3"]' % (i) for i in sorted(self.blocked_hosts)]))

def main():
    blocklist = BlockList()
    try:
        paths = [os.path.join('target', f) for f in os.listdir('target')]
        paths = [f for f in paths if os.path.isfile(f)]
    except FileNotFoundError:
        print('Target directory does not exist')
        return
    paths.sort()
    for path in paths:
        blocklist.add_file(path)
    blocklist.clean()
    print('Generated %s rules' % len(blocklist.blocked_hosts))
    try:
        os.makedirs('output')
    except FileExistsError:
        pass
    for (path, func) in [('adblock.txt', blocklist.to_adblock),
                         ('hosts.txt', blocklist.to_hosts),
                         ('PrivacyBadger.json', blocklist.to_privacy_badger)]:
        with open(os.path.join('output', path), 'w') as file:
            file.write(func())

if __name__ == '__main__':
    main()
