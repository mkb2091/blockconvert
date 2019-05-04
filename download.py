import urllib.request
urls = [
        'http://winhelp2002.mvps.org/hosts.txt',
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
	'https://raw.githubusercontent.com/EFForg/badger-sett/master/results.json',
	'https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt',
	'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
        'https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/Notracking-hostnames.txt',
	'https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt',
	'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt',
	'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt',
        'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt',
        'https://someonewhocares.org/hosts/hosts',
	'https://www.malwaredomainlist.com/hostslist/hosts.txt'
    ]
for (i, url) in enumerate(urls):
    print('Starting %s, url: %s' % (i, url))
    req = urllib.request.Request(url, data=None,
                                 headers={'User-Agent':'BlockListConvert' + str(id(urls))})
    with urllib.request.urlopen(req) as response:
        with open('target/%s' % i, 'wb') as file:
            file.write(response.read())
