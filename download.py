import urllib.request
urls = [
    'http://winhelp2002.mvps.org/hosts.txt',
    'https://github.com/EFForg/badger-sett/blob/master/results.json',
    'https://github.com/uBlockOrigin/uAssets/blob/master/filters/filters.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext',
    'https://raw.githubusercontent.com/AdroitAdorKhan/EnergizedProtection/master/core/hosts',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://someonewhocares.org/hosts/hosts'
    ]
for (i, url) in enumerate(urls):
    print('Starting %s' % i)
    with urllib.request.urlopen(url) as response:
        with open('target/%s' % i, 'wb') as file:
            file.write(response.read())
