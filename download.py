import urllib.request
import hashlib
import time
import os

urls = [
    'https://blocklist.kowabit.de/fritzboxliste.txt',#Public Domain
    'https://blocklist.kowabit.de/list.txt',#Public Domain
    'https://easylist-downloads.adblockplus.org/adwarefilters.txt',#GPLv3
    'https://easylist.to/easylist/easylist.txt',#GPLv3
    'https://easylist.to/easylist/easyprivacy.txt', #GPLv3
    'https://easylist.to/easylist/fanboy-annoyance.txt',#GPLv3
    'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt',#GPLv3
    'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',#GPLv3
    'https://hostsfile.mine.nu/hosts0.txt',#GPLv3
    'https://raw.githubusercontent.com/DataMaster-2501/DataMaster-Android-AdBlock-Hosts/master/hosts',#GPLv3
    'https://raw.githubusercontent.com/SkeletalDemise/Skeletal-Blocker/master/Skeletal%20Blocker%20List',#GPLv3
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',#MIT
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt',#MIT
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',#MIT
    'https://raw.githubusercontent.com/betterwebleon/international-list/master/filters.txt',#The unlicense
    'https://raw.githubusercontent.com/bjornstar/hosts/master/hosts',#Public Domain
    'https://raw.githubusercontent.com/hl2guide/All-in-One-Customized-Adblock-List/master/deanoman-adblocklist.txt',#MIT
    'https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt',#MIT
    'https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt',#Apache2
    'https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking.txt',#Apache2
    'https://raw.githubusercontent.com/lightswitch05/hosts/master/tracking-aggressive-extended.txt',#Apache2
    'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt',#Public Domain
    'https://raw.githubusercontent.com/metaphoricgiraffe/tracking-filters/master/trackingfilters.txt',#The Unlicense
    'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardApps.txt',#GPLv3
    'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt',#GPLv3
    'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt',#GPLv3
    'https://raw.githubusercontent.com/xxcriticxx/.pl-host-file/master/hosts.txt',#The Unlicense
    'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',#GPLv3
    'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt',#GPLv3
    'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',#GPLv3
    'https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt',#Permission to modify,copy and distribute
    ]

def copy_whitelist_and_clean():
    hashes = [hashlib.sha256(url.encode()).hexdigest()+'.txt' for url in urls]
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
    path = os.path.join('target', hashlib.sha256(url.encode()).hexdigest()+'.txt')
    req = urllib.request.Request(url, data=None,
                                 headers={'User-Agent':'BlockListConvert' + str(id(urls))})
    if os.path.exists(path):
        if (time.time() - os.stat(path).st_mtime) / (60 * 60 * 12) < 1:
            print('Hasn\'t expired:%s' % i)
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
                    with open(path) as file:
                        data = file.read()
                    with open(path, 'w') as file:
                        file.write(data)
                    continue
        print('Fetching new')
        with open(path, 'w') as file:
            data = response.read().decode('ascii', 'ignore')
            file.write(data)
