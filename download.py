import urllib.request
import hashlib
import time
import os

urls = [
    'http://winhelp2002.mvps.org/hosts.txt',
    'https://1hos.cf/',
    'https://adaway.org/hosts.txt',
    'https://easylist-downloads.adblockplus.org/adwarefilters.txt',
    'https://easylist-downloads.adblockplus.org/malwaredomains_full.txt',
    'https://easylist.to/easylist/easylist.txt',
    'https://easylist.to/easylist/easyprivacy.txt',
    'https://easylist.to/easylist/fanboy-annoyance.txt',
    'https://filters.adtidy.org/extension/chromium/filters/11.txt',
    'https://filters.adtidy.org/extension/chromium/filters/14.txt',
    'https://filters.adtidy.org/extension/chromium/filters/15.txt',
    'https://filters.adtidy.org/extension/chromium/filters/2.txt',
    'https://filters.adtidy.org/extension/chromium/filters/3.txt',
    'https://hosts-file.net/ad_servers.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext',
    'https://raw.githubusercontent.com/AdroitAdorKhan/EnergizedProtection/master/core/hosts',
    'https://raw.githubusercontent.com/DataMaster-2501/DataMaster-Android-AdBlock-Hosts/master/hosts',
    'https://raw.githubusercontent.com/EFForg/badger-sett/master/results.json',
    'https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt',
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
    'https://raw.githubusercontent.com/austinheap/sophos-xg-block-lists/master/coinblocker.txt',
    'https://raw.githubusercontent.com/bjornstar/hosts/master/hosts',
    'https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/Notracking-hostnames.txt',
    'https://raw.githubusercontent.com/hl2guide/All-in-One-Customized-Adblock-List/master/deanoman-adblocklist.txt',
    'https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt',
    'https://raw.githubusercontent.com/kano1/I/master/adware.txt',
    'https://raw.githubusercontent.com/kano1/Kano/master/Spyware.txt',
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt',
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt',
    'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt',
    'https://someonewhocares.org/hosts/hosts',
    'https://www.fanboy.co.nz/enhancedstats.txt',
    'https://www.malwaredomainlist.com/hostslist/hosts.txt',
    ]
def copy_whitelist_and_clean():
    hashes = [hashlib.sha256(url.encode()).hexdigest() for url in urls]
    for path in os.listdir('target'):
        if path not in hashes:
            os.remove(os.path.join('target', path))
    with open('whitelist.txt') as file:
        with open('target/whitelist.txt', 'w') as outfile:
            outfile.write(file.read())


def fetch_new_tld():
    req = urllib.request.Request('https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
                                 data=None,
                                 headers={'User-Agent':'BlockListConvert' + str(id(urls))})
    if os.path.exists('tld_list.txt'):
        if (time.time() - os.stat('tld_list.txt').st_mtime) / (60 * 60 * 12) > 1:
            with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())
    else:
        with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())

copy_whitelist_and_clean()
fetch_new_tld()

for (i, url) in enumerate(urls):
    path = os.path.join('target', hashlib.sha256(url.encode()).hexdigest())
    req = urllib.request.Request(url, data=None,
                                 headers={'User-Agent':'BlockListConvert' + str(id(urls))})
    if os.path.exists(path):
        if (time.time() - os.stat(path).st_mtime) / (60 * 60 * 12) < 1:
            print('Hasn\'t expired:', i)
            continue
    print('Starting %s, url: %s' % (i, url))
    with urllib.request.urlopen(req) as response:
        if os.path.exists(path):
            last_modified = response.headers['Last-Modified']
            if last_modified is not None:
                lm_time = time.strptime(last_modified, '%a, %d %b %Y %H:%M:%S GMT')
                if lm_time < os.stat(path):
                    response.close()
                    print('Unchanged')
                    continue
        print('Fetching new')
        with open(path, 'wb') as file:
            file.write(response.read())
