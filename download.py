import urllib.request
import hashlib
import time
import os

blacklist_urls = [
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',#GPL3
    'https://better.fyi/blockerList.txt',#CCASA4.0
    'https://cybercrime-tracker.net/all.php',#CC0
    'https://easylist-downloads.adblockplus.org/adwarefilters.txt',#GPLv3
    'https://easylist-downloads.adblockplus.org/easylistchina.txt',#GPLv3
    'https://easylist-downloads.adblockplus.org/easylistdutch.txt',#GPLv3
    'https://easylist.to/easylistgermany/easylistgermany.txt',#GPLv3
    'https://easylist-downloads.adblockplus.org/easylistitaly.txt',#GPLv3
    'https://easylist.to/easylist/easylist.txt',#GPLv3
    'https://easylist.to/easylist/easyprivacy.txt', #GPLv3
    'https://easylist.to/easylist/fanboy-annoyance.txt',#GPLv3
    'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt',#GPLv3
    'https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter.txt',#CC0
    'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',#GPLv3
    'https://hblock.molinero.dev/hosts',#MIT
    'https://hostsfile.mine.nu/hosts0.txt',#GPLv3
    'https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt',#CC-BY-SA v4.0
    'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',#Free for use without any limitations
    'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt',#Free for use without any limitations
    'https://raw.githubusercontent.com/CHEF-KOCH/Audio-fingerprint-pages/master/AudioFp.txt',#MIT
    'https://raw.githubusercontent.com/CHEF-KOCH/Canvas-Font-Fingerprinting-pages/master/Canvas.txt',#MIT
    'https://raw.githubusercontent.com/CHEF-KOCH/Canvas-fingerprinting-pages/master/Canvas.txt',#MIT
    'https://raw.githubusercontent.com/CHEF-KOCH/WebRTC-tracking/master/WebRTC.txt',#MIT
    'https://raw.githubusercontent.com/DataMaster-2501/DataMaster-Android-AdBlock-Hosts/master/hosts',#GPLv3
    'https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/seed.json',#GPL3
    'https://raw.githubusercontent.com/SkeletalDemise/Skeletal-Blocker/master/Skeletal%20Blocker%20List',#GPLv3
    'https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt',#Permission to modify,copy and distribute
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',#MIT
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt',#MIT
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',#MIT
    'https://raw.githubusercontent.com/betterwebleon/international-list/master/filters.txt',#The unlicense
    'https://raw.githubusercontent.com/bjornstar/hosts/master/hosts',#The Unlicense
    'https://raw.githubusercontent.com/bogachenko/presstheattack/master/presstheattack.txt',#MIT
    'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',#MIT
    'https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt',#GPLv3
    'https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt',#GPLv3
    'https://raw.githubusercontent.com/hl2guide/All-in-One-Customized-Adblock-List/master/deanoman-adblocklist.txt',#MIT
    'https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt',#MIT
    'https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt',#Apache2
    'https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking.txt',#Apache2
    'https://raw.githubusercontent.com/lightswitch05/hosts/master/tracking-aggressive-extended.txt',#Apache2
    'https://raw.githubusercontent.com/ligyxy/Blocklist/master/BLOCKLIST',#MIT
    'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt',#Public Domain
    'https://raw.githubusercontent.com/metaphoricgiraffe/tracking-filters/master/trackingfilters.txt',#The Unlicense
    'https://raw.githubusercontent.com/michaeltrimm/hosts-blocking/master/_hosts.txt',#MIT
    'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',#MIT
    'https://raw.githubusercontent.com/mitchellkrogza/Stop.Google.Analytics.Ghost.Spam.HOWTO/master/output/domains/ACTIVE/list',#MIT
    'https://raw.githubusercontent.com/mitchellkrogza/Suspicious.Snooping.Sniffing.Hacking.IP.Addresses/master/ips.list',#MIT
    'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list',#MIT
    'https://raw.githubusercontent.com/mitchellkrogza/Top-Attacking-IP-Addresses-Against-Wordpress-Sites/master/wordpress-attacking-ips.txt',#MIT
    'https://raw.githubusercontent.com/nabble/semalt-blocker/master/domains/blocked',#MIT
    'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardApps.txt',#GPLv3
    'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt',#GPLv3
    'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt',#GPLv3
    'https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt',#CC-BY-SA v4.0
    'https://raw.githubusercontent.com/toshiya44/myAssets/master/filters-exp.txt',#GPL3
    'https://raw.githubusercontent.com/toshiya44/myAssets/master/hosts/hosts.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt',#GPLv3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt',#GPL3
    'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt',#GPLv3
    'https://raw.githubusercontent.com/xxcriticxx/.pl-host-file/master/hosts.txt',#The Unlicense
    'https://raw.githubusercontent.com/yowu/AnnoyanceMobileAdHosts/master/AnnoyanceMobileAdHosts.txt',#MIT
    'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',#GPLv3
    'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt',#GPLv3
    'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',#GPLv3
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',#CC0
    'https://v.firebog.net/hosts/BillStearns.txt',#GPL
    'https://www.squidblacklist.org/downloads/dg-ads.acl',#You may freely use, copy, and redistribute this blacklist in any manner you like.
    ]

whitelist_urls = [
    'https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/yellowlist.txt',#GPLv3+
    'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list',#MIT
    'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt',#MIT
    'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt',#MIT
    ]

def copy_whitelist_and_clean():
    for (folder, urls) in (('blacklist', blacklist_urls), ('whitelist', whitelist_urls)):
        hashes = [hashlib.sha256(url.encode()).hexdigest()+'.txt' for url in urls]
        for path in os.listdir(folder):
            if path not in hashes:
                os.remove(os.path.join(folder, path))
    with open('whitelist.txt') as file:
        with open('whitelist/whitelist.txt', 'w') as outfile:
            outfile.write(file.read())


def fetch_new_tld():
    req = urllib.request.Request('https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
                                 data=None,
                                 headers={'User-Agent':'BlockListConvert' + str(id(blacklist_urls))})
    if os.path.exists('tld_list.txt'):
        if (time.time() - os.stat('tld_list.txt').st_mtime) / (60 * 60 * 11.5) > 1:
            with urllib.request.urlopen(req) as response:
                with open('tld_list.txt', 'wb') as file:
                    file.write(response.read())
    else:
        with urllib.request.urlopen(req) as response:
            with open('tld_list.txt', 'wb') as file:
                file.write(response.read())
def fetch_new_subdomains():
    req = urllib.request.Request('https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000',
                                 data=None,
                                 headers={'User-Agent':'BlockListConvert' + str(id(blacklist_urls))})
    if os.path.exists('subdomain_list.txt'):
        if (time.time() - os.stat('subdomain_list.txt').st_mtime) / (60 * 60 * 11.5) > 1:
            with urllib.request.urlopen(req) as response:
                with open('subdomain_list.txt', 'wb') as file:
                    file.write(response.read())
    else:
        with urllib.request.urlopen(req) as response:
            with open('subdomain_list.txt', 'wb') as file:
                file.write(response.read())
if not os.path.exists('blacklist'):
    os.mkdir('blacklist')
if not os.path.exists('whitelist'):
    os.mkdir('whitelist')
copy_whitelist_and_clean()
fetch_new_tld()
fetch_new_subdomains()

for (folder, urls) in (('blacklist', blacklist_urls), ('whitelist', whitelist_urls)):
    for (i, url) in enumerate(urls):
        path = os.path.join(folder, hashlib.sha256(url.encode()).hexdigest()+'.txt')
        req = urllib.request.Request(url, data=None,
                                     headers={'User-Agent':'BlockListConvert' + str(id(urls))})
        print('Starting %s, url: %s' % (i, url))
        print('Paths: %s' % path)
        if os.path.exists(path):
            if (time.time() - os.stat(path).st_mtime) / (60 * 60 * 11.5) < 1:
                print('Hasn\'t expired:%s' % i)
                continue
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
