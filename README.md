# blockconvert
Tool for generating blacklists in domain list format/host file format/adblockplus style format/privacy badger style format(not really advised since it is far larger than the files it expects to use).

It merges filter lists from many different sources(the list is in download.py), and tries to convert it into a list of blockable domains. It then uses dns to lookup all of those domains to check if they actually exist, and removes the ones which don't to reduce space and hopefully improve speed for blocking tools. It uses DNS-over-https for the dns lookup to avoid being flagged as accessing lots of malware websites, and to stop local dns blocking from effecting results
