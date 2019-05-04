import json
import os
import re

class BlockList():
    ADBLOCK_STRING = r'(?:(?:(?:\|\|)?[.]?)|(?:(?:(?:https?)?[:])?//)?)?([a-z0-9-]+(?:[.][a-z0-9-]+)+)(?:\^)?(?:\$(?:[,]?(?:(?:popup)|(?:first\-party))))?'
    WHITELIST_STRING = '@@' + ADBLOCK_STRING
    ADBLOCK_REGEX = re.compile(ADBLOCK_STRING)
    WHITELIST_REGEX = re.compile(WHITELIST_STRING)
    def __init__(self):
        self.blocked_hosts = set()
        self.whitelist = set()
    def add_file(self, path):
        with open(path) as file:
            data = file.read()
        try:
            data = json.loads(data)
            if 'action_map' in data and isinstance(data['action_map'], dict):
                self.parse_privacy_badger(data)
                return
        except json.JSONDecodeError:
            pass
        self.parse_adblock(data)
        self.parse_hosts(data)
    def parse_privacy_badger(self, data):
        for i in data['action_map']:
            if isinstance(data['action_map'][i], dict) and 'heuristicAction' in data['action_map'][i]:
                if data['action_map'][i]['heuristicAction'] == 'block':
                    self.blocked_hosts.add(i)
                elif data['action_map'][i]['heuristicAction'] == 'cookieblock':
                    self.whitelist.add(i)
    def parse_adblock(self, data):
        for line in data.splitlines()[1:]:
            if '!' not in line:
                match = self.ADBLOCK_REGEX.fullmatch(line)
                if match:
                    self.blocked_hosts.add(match.group(1))
                else:
                    match = self.WHITELIST_REGEX.fullmatch(line)
                    if match:
                        self.whitelist.add(match.group(1))
    def parse_hosts(self, data):
        for line in data.splitlines():
            line, *_ = line.split('#')
            try:
                host, domain = line.split()
                if host in ('0.0.0.0', '127.0.0.1'):
                    self.blocked_hosts.add(domain)
            except ValueError:
                pass
    def clean(self):
        for i in self.whitelist:
            try:
                self.blocked_hosts.remove(i)
            except KeyError:
                pass
    def to_adblock(self):
        self.clean()
        return '\n'.join('||%s^' % i for i in sorted(self.blocked_hosts))
    def to_hosts(self):
        self.clean()
        return '\n'.join('0.0.0.0 ' + i for i in sorted(self.blocked_hosts))
    def to_privacy_badger(self):
        self.clean()
        base = '{"action_map":{%s},"snitch_map":{%s}, "settings_map":{}}'
        url_string = '"%s":{"userAction":"","dnt":false,"heuristicAction":"block","nextUpdateTime":0}'
        return base % (','.join(url_string % i for i in sorted(self.blocked_hosts)),
                       ','.join('"%s":["1","2","3"]' % (i) for i in sorted(self.blocked_hosts)))

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
    with open('output/PrivacyBadger.json', 'w') as file:
        file.write(blocklist.to_privacy_badger())
    with open('output/adblock.txt', 'w') as file:
        file.write(blocklist.to_adblock())
    with open('output/hosts.txt', 'w') as file:
        file.write(blocklist.to_hosts())

if __name__ == '__main__':
    main()
