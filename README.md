# blockconvert
Tool for generating blacklists in domain list format/host file format/adblockplus style format/privacy badger style format(not really advised since it is far larger than the files it expects to use).

It merges filter lists from many different sources(the list is in download.py), and tries to convert it into a list of blockable domains. It then uses dns to lookup all of those domains to check if they actually exist, and removes the ones which don't to reduce space and hopefully improve speed for blocking tools. It uses DNS-over-https for the dns lookup to avoid being flagged as accessing lots of malware websites, and to stop local dns blocking from effecting results. It also performs reverse dns on any ip addresses in any of the blocklists to add them to the list of blocked domains to improve the blocklist

## Links
Adblock Plus style blocklist:  https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/adblock.txt

Hosts file style blocklist: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/hosts.txt

List of blocked domains: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt

Blocklist for use in Privacy Badger(takes a while to import): https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/PrivacyBadger.json

URLs used to build lists: https://github.com/mkb2091/blockconvert/blob/master/urls.txt

## Credits

enemyofarsenic(Reddit): Suggested addition of whitelists, and use of passive dns services to find as many as possible of malware domains hosted on blacklisted IP address
