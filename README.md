# BlockConvert

Tool for generating blacklists in domain list format/host file format/ adblockplus style format/privacy badger style format(not really advised since it is far larger than the files it expects to use)/DNS Response Policy Zone format.

It merges filter lists from many different sources(the list is in urls.txt and below), and tries to convert it into a list of blockable domains. It then uses dns to lookup all of those domains to check if they actually exist, and removes the ones which don't to reduce space and hopefully improve speed for blocking tools. It uses DNS-over-https for the dns lookup to avoid being flagged as accessing lots of malware websites, and to stop local dns blocking from effecting results. It also performs reverse dns on any ip addresses in any of the blocklists to add them to the list of blocked domains to improve the blocklist. For malware domains it also finds all other domains hosted on the same IP address, to try and ensure as much malware as possible is blocked, this does result in the chance of some false positives for websites using shared IP addresses.

If there are any false positives, make an issue/contact me and I'll whitelist them

## The Process

1. Download file

2. Extract domains into whitelist and blacklist

3. Use passive dns and reverse dns on all of the ip addresses in the whitelist and blacklist

4. For any domains which have "\*" in tld field replace it with every tld in downloaded list

5. For each domain which starts with "www" or "m" add a copy of that domain without the subdomain

6. For each domain with "\*" as subdomain replace it with every subdomain in top 1000 subdomains file, and add a copy without any subdomain

7. For every domain in the whitelist, remove it from the blacklist

8. For all remaining domains in blacklist, use dns to check if the domain is still registered, remove those that are not

9. Remove all invalid domains

## Links

Adblock Plus style blocklist:  https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/adblock.txt

Hosts file style blocklist: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/hosts.txt

List of blocked domains: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt

Blocklist for use in Privacy Badger(takes a while to import): https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/PrivacyBadger.json

DNS Response Policy Zone file: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.rpz

URLs used to build lists: https://github.com/mkb2091/blockconvert/blob/master/urls.txt

## Last Commit Infomation

Theres are 622692 blocked domains in each of the generated filter lists

## Sources

For static sources 100 days is put, and for sources with unknown expires, 1 days is put

URL|Expires|Type|License
:---:|:---:|:---:|:---:
http://vxvault.net/URL_List.php|1.0 days|Blacklist|Copyleft 2010. No rights reserved. 
https://adaway.org/hosts.txt|1.0 days|Blacklist|CC-BY-3
https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt|1.0 days|Blacklist|GPLv3
https://better.fyi/blockerList.txt|1.0 days|Blacklist|CC-BY-SA-4.0
https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt|10.0 days|Blacklist|Public Domain
https://cybercrime-tracker.net/all.php|1.0 days|Blacklist|CC0
https://easylist-downloads.adblockplus.org/adwarefilters.txt|1.0 days|Blacklist|GPLv3
https://easylist-downloads.adblockplus.org/easylistchina.txt|4.0 days|Blacklist|GPLv3
https://easylist-downloads.adblockplus.org/easylistdutch.txt|4.0 days|Blacklist|GPLv3
https://easylist-downloads.adblockplus.org/easylistitaly.txt|1.0 days|Blacklist|GPLv3
https://easylist.to/easylist/easylist.txt|4.0 days|Blacklist|GPLv3
https://easylist.to/easylist/easyprivacy.txt|4.0 days|Blacklist|GPLv3
https://easylist.to/easylist/fanboy-annoyance.txt|4.0 days|Blacklist|GPLv3
https://easylist.to/easylistgermany/easylistgermany.txt|1.0 days|Blacklist|GPLv3
https://feodotracker.abuse.ch/downloads/ipblocklist.txt|1.0 days|Blacklist|CC0
https://filtri-dns.ga/filtri.txt|1.0 days|Blacklist|GPLv3
https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt|1.0 days|Blacklist|GPLv3
https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter.txt|1.0 days|Blacklist|CC0
https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt|1.0 days|Blacklist|GPLv3
https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt|1.0 days|Blacklist|GPLv3
https://hblock.molinero.dev/hosts|1.0 days|Blacklist|MIT
https://hostsfile.mine.nu/hosts0.txt|1.0 days|Blacklist|GPLv3
https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt|1.0 days|Blacklist|CC-BY-SA-4.0
https://pastebin.com/raw/0vSxs719|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/5WWQUxEH|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/BiQKjQaK|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/ZzZutnXE|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/a1TPEPfP|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/g8bhsb4G|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/mU2XkjmV|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/mU7abvT9|100.0 days|Blacklist|Public Domain
https://pastebin.com/raw/sRzfwfsa|100.0 days|Blacklist|Public Domain
https://ransomwaretracker.abuse.ch/downloads/LY_C2_IPBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://ransomwaretracker.abuse.ch/downloads/LY_PS_IPBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://ransomwaretracker.abuse.ch/downloads/TC_PS_IPBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://ransomwaretracker.abuse.ch/downloads/TL_C2_IPBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://ransomwaretracker.abuse.ch/downloads/TL_PS_IPBL.txt|1.0 days|Blacklist|Free for use without any limitations
https://raw.githubusercontent.com/DataMaster-2501/DataMaster-Android-AdBlock-Hosts/master/hosts|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/seed.json|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/yellowlist.txt|1.0 days|Whitelist|GPLv3+
https://raw.githubusercontent.com/Marfjeh/coinhive-block/master/domains|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt|1.0 days|Blacklist|CC-BY-SA-4
https://raw.githubusercontent.com/SkeletalDemise/Skeletal-Blocker/master/Skeletal%20Blocker%20List|2.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt|2.0 days|Blacklist|Permission to modify, copy and distribute
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list|1.0 days|Whitelist|MIT
https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt|1.0 days|Whitelist|MIT
https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt|1.0 days|Whitelist|MIT
https://raw.githubusercontent.com/betterwebleon/international-list/master/filters.txt|3.0 days|Blacklist|The Unlicense
https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/bjornstar/hosts/master/hosts|1.0 days|Blacklist|The Unlicense
https://raw.githubusercontent.com/bogachenko/presstheattack/master/presstheattack.txt|3.0 hours|Blacklist|MIT
https://raw.githubusercontent.com/cb-software/CB-Malicious-Domains/master/block_lists/domains_only.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt|1.0 days|Blacklist|Apache2
https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/hl2guide/All-in-One-Customized-Adblock-List/master/deanoman-adblocklist.txt|2.0 hours|Blacklist|MIT
https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt|2.0 days|Blacklist|Apache2
https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking.txt|2.0 days|Blacklist|Apache2
https://raw.githubusercontent.com/lightswitch05/hosts/master/tracking-aggressive-extended.txt|2.0 days|Blacklist|Apache2
https://raw.githubusercontent.com/ligyxy/Blocklist/master/BLOCKLIST|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt|1.0 days|Blacklist|Public Domain
https://raw.githubusercontent.com/metaphoricgiraffe/tracking-filters/master/trackingfilters.txt|1.0 days|Blacklist|The Unlicense
https://raw.githubusercontent.com/michaeltrimm/hosts-blocking/master/_hosts.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/mitchellkrogza/Stop.Google.Analytics.Ghost.Spam.HOWTO/master/output/domains/ACTIVE/list|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/mitchellkrogza/Suspicious.Snooping.Sniffing.Hacking.IP.Addresses/master/ips.list|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/mitchellkrogza/Top-Attacking-IP-Addresses-Against-Wordpress-Sites/master/wordpress-attacking-ips.txt|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/nabble/semalt-blocker/master/domains/blocked|1.0 days|Blacklist|MIT
https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardApps.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt|4.0 hours|Blacklist|CC-BY-SA-4.0
https://raw.githubusercontent.com/toshiya44/myAssets/master/filters-exp.txt|4.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/toshiya44/myAssets/master/hosts/hosts.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt|4.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt|4.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt|4.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt|4.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt|4.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/xxcriticxx/.pl-host-file/master/hosts.txt|1.0 days|Blacklist|GPLv3
https://raw.githubusercontent.com/yowu/AnnoyanceMobileAdHosts/master/AnnoyanceMobileAdHosts.txt|1.0 days|Blacklist|The Unlicense
https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt|1.0 days|Blacklist|GPLv3
https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt|1.0 days|Blacklist|GPLv3
https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt|1.0 days|Blacklist|GPLv3
https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt|1.0 days|Blacklist|GPLv3
https://sslbl.abuse.ch/blacklist/sslipblacklist.txt|1.0 days|Blacklist|CC0
https://urlhaus.abuse.ch/downloads/rpz/|1.0 days|Blacklist|CC0
https://v.firebog.net/hosts/BillStearns.txt|1.0 days|Blacklist|GPLv3
https://www.squidblacklist.org/downloads/dg-ads.acl|1.0 days|Blacklist|You may freely use, copy, and redistribute this blacklist in any manner you like.
https://www.squidblacklist.org/downloads/dg-malicious.acl|1.0 days|Blacklist|You may freely use, copy, and redistribute this blacklist in any manner you like.
https://zeustracker.abuse.ch/blocklist.php?download=baddomains|1.0 days|Blacklist|CC0
https://zeustracker.abuse.ch/blocklist.php?download=badips|1.0 days|Blacklist|CC0

## Credits

enemyofarsenic(Reddit): Many very useful suggestions such as whitelist, passive dns, and many lists

