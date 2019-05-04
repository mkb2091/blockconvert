import urllib.request
urls = [
    'http://winhelp2002.mvps.org/hosts.txt',
    'https://github.com/EFForg/badger-sett/blob/master/results.json',
    'https://github.com/uBlockOrigin/uAssets/blob/master/filters/filters.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext',
    'https://raw.githubusercontent.com/AdroitAdorKhan/EnergizedProtection/master/core/hosts',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://someonewhocares.org/hosts/hosts',
    'https://easylist.to/easylist/easylist.txt',
    'https://easylist.to/easylist/easyprivacy.txt',
    'https://adaway.org/hosts.txt',
    'https://hosts-file.net/ad_servers.txt',
    'https://www.malwaredomainlist.com/hostslist/hosts.txt'
    ]
for (i, url) in enumerate(urls):
    print('Starting %s, url: %s' % (i, url))
    req = urllib.request.Request(url, data=None,
                                 headers={'User-Agent':'BlockConvert'})
    with urllib.request.urlopen(req) as response:
        with open('target/%s' % i, 'wb') as file:
            file.write(response.read())
