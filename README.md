# BlockConvert


Generated blocklist in a variety of formats.

Advantages of using this list:
- Conversion of list types. As well as supporting many common filter list formats, it also supports Privacy Badger data file, which uses algorithms to detect trackers allowing newly created trackers to be quickly detected and added to this blocklist without a human needing to spot the tracker.

- Reverse DNS and passive DNS on malware IP addresses. This allows finding all the domains which a malware IP blacklist suggests could be dangerous to be found and blocked. This allows blocking of malware domains that haven't yet been added to other malware domain lists.

- Use of a whitelist. Using a hosts file doesn't allow whitelisting, and many DNS-based blockers don't have great support of whitelists. This list has it's own whitelist, as well as using a few others to try to reduce false positives. This list supports "*" in subdomain and tld to aid in easily fixing many false positives at once. (If you do find a false positive(domain that shouldn't be blocked), then please make an issue and I will remove it)

- Use of DNS to check if domains still exist. Many lists contain domains that have expired and no longer exist. This makes those lists larger than needed which wastes bandwidth, space and can slow blocking.


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

DNS Response Policy Zone file: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.rpz

URLs used to build lists: https://github.com/mkb2091/blockconvert/blob/master/urls.txt

## Last Commit Infomation

Theres are 904806 blocked domains in each of the generated filter lists

## Sources

For static sources 100 days is put, and for sources with unknown expires, 1 days is put.

The files in data/ are all modified versions generated from the below sources:

Title|URL|Author|Expires|Type|License
:---:|:---:|:---:|:---:|:---:|:---:
|https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt||10.0 days|Public Domain|Blacklist
|https://cybercrime-tracker.net/all.php||1.0 days|CC0|Blacklist
|https://filtri-dns.ga/filtri.txt||1.0 days|GPLv3|Blacklist
|https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt||1.0 days|GPLv3|Blacklist
|https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_optional.txt||1.0 days|GPLv3|Blacklist
|https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter.txt||1.0 days|CC0|Blacklist
|https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt||1.0 days|CC-BY-SA-4.0|Blacklist
|https://pastebin.com/raw/0vSxs719||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/5WWQUxEH||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/9QAxNkaS||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/BiQKjQaK||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/JEtG4aG0||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/ZzZutnXE||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/a1TPEPfP||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/aAcp1cNs||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/eJHNbf4W||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/f2dd77fR||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/ffDu8u46||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/g8bhsb4G||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/iGCZ1Vq4||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/jarnEpx5||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/mU2XkjmV||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/mU7abvT9||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/pkZ0TBnc||100.0 days|Public Domain|Blacklist
|https://pastebin.com/raw/sRzfwfsa||100.0 days|Public Domain|Blacklist
|https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/seed.json||1.0 days|GPLv3|Blacklist
|https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/yellowlist.txt||1.0 days|GPLv3+|Whitelist
|https://raw.githubusercontent.com/Marfjeh/coinhive-block/master/domains||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list||1.0 days|MIT|Whitelist
|https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt|Anudeep <anudeep@protonmail.com>|1.0 days|MIT|Whitelist
|https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt||1.0 days|MIT|Whitelist
|https://raw.githubusercontent.com/bjornstar/hosts/master/hosts||1.0 days|The Unlicense|Blacklist
|https://raw.githubusercontent.com/cb-software/CB-Malicious-Domains/master/block_lists/domains_only.txt||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt||1.0 days|Apache2|Blacklist
|https://raw.githubusercontent.com/ligyxy/Blocklist/master/BLOCKLIST||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt||1.0 days|Public Domain|Blacklist
|https://raw.githubusercontent.com/michaeltrimm/hosts-blocking/master/_hosts.txt||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt|Mitchell Krog|1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/mitchellkrogza/Stop.Google.Analytics.Ghost.Spam.HOWTO/master/output/domains/ACTIVE/list|Mitchell Krog|1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/mitchellkrogza/Suspicious.Snooping.Sniffing.Hacking.IP.Addresses/master/ips.list|Mitchell Krog|1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list|Mitchell Krog|1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/mitchellkrogza/Top-Attacking-IP-Addresses-Against-Wordpress-Sites/master/wordpress-attacking-ips.txt|Mitchell Krog|1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/nabble/semalt-blocker/master/domains/blocked||1.0 days|MIT|Blacklist
|https://raw.githubusercontent.com/toshiya44/myAssets/master/hosts/hosts.txt||1.0 days|GPLv3|Blacklist
|https://raw.githubusercontent.com/xxcriticxx/.pl-host-file/master/hosts.txt||1.0 days|GPLv3|Blacklist
|https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt||1.0 days|GPLv3|Blacklist
|https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt||1.0 days|GPLv3|Blacklist
|https://v.firebog.net/hosts/BillStearns.txt||1.0 days|GPLv3|Blacklist
|https://www.squidblacklist.org/downloads/dg-ads.acl||1.0 days|You may freely use, copy, and redistribute this blacklist in any manner you like.|Blacklist
|https://www.squidblacklist.org/downloads/dg-malicious.acl||1.0 days|You may freely use, copy, and redistribute this blacklist in any manner you like.|Blacklist
ABP Japanese 3rd party SNS filters (ONLY FOR Japanese and experienced users: READ Support Policy)|https://raw.githubusercontent.com/k2jp/abp-japanese-filters/master/abpjf_3rd_party_sns.txt|k2japan|6.0 hours|GPLv3|Blacklist
ABP Japanese Paranoid filters (ONLY FOR Japanese and experienced users: READ Support Policy)|https://raw.githubusercontent.com/k2jp/abp-japanese-filters/master/abpjf_paranoid.txt|k2japan|6.0 hours|GPLv3|Blacklist
ABP Japanese filters (ONLY FOR Japanese and experienced users: READ Support Policy)|https://raw.githubusercontent.com/k2jp/abp-japanese-filters/master/abpjf.txt|k2japan|6.0 hours|GPLv3|Blacklist
ABPindo|https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt||4.0 days|GPLv3|Blacklist
ABPindo|https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt||1.0 days|GPLv3|Blacklist
AakList (Anti-Adblock Killer)|https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt|Reek | http://reeksite.com/|1.0 days|CC-BY-SA-4.0|Blacklist
Ad filter list by Disconnect|https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt||1.0 days|GPLv3|Blacklist
AdAway default blocklist|https://adaway.org/hosts.txt||1.0 days|CC-BY-3|Blacklist
AdBlock Farsi|https://raw.githubusercontent.com/SlashArash/adblockfa/master/adblockfa.txt||5.0 days|The Beer-Ware License|Blacklist
AdGuard Simplified Domain Names filter|https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt||1.0 days|GPLv3|Blacklist
Adblock List for Finland|https://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/master/Finland_adb.txt||5.0 days|The Unlicense|Blacklist
Adblock Polska|https://raw.githubusercontent.com/adblockpolska/Adblock_PL_List/master/adblock_polska.txt|adblockpl, tomasko126, MonztA|2.0 days|GPLv3|Blacklist
AdguardApps|https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardApps.txt||1.0 days|GPLv3|Blacklist
AdguardDNS|https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt||1.0 days|GPLv3|Blacklist
AdguardMobileAds|https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt||1.0 days|GPLv3|Blacklist
Adware filters|https://easylist-downloads.adblockplus.org/adwarefilters.txt||1.0 days|GPLv3|Blacklist
Annoyance Mobile Ad hosts filter|https://raw.githubusercontent.com/yowu/AnnoyanceMobileAdHosts/master/AnnoyanceMobileAdHosts.txt||1.0 days|The Unlicense|Blacklist
Anudeep's Blacklist|https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt|Anudeep <anudeep@protonmail.com>|1.0 days|MIT|Blacklist
Anudeep's Blacklist|https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt|Anudeep <anudeep@protonmail.com>|1.0 days|MIT|Blacklist
Basic tracking list by Disconnect|https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt||1.0 days|GPLv3|Blacklist
Better content blocking rules|https://better.fyi/blockerList.txt||1.0 days|CC-BY-SA-4.0|Blacklist
DataMaster-Android-AdBlock-Hosts|https://raw.githubusercontent.com/DataMaster-2501/DataMaster-Android-AdBlock-Hosts/master/hosts|https://github.com/DataMaster-2501|1.0 days|GPLv3|Blacklist
EasyList China|https://easylist-downloads.adblockplus.org/easylistchina.txt||4.0 days|GPLv3|Blacklist
EasyList Dutch|https://easylist-downloads.adblockplus.org/easylistdutch.txt||4.0 days|GPLv3|Blacklist
EasyList Germany|https://easylist.to/easylistgermany/easylistgermany.txt||1.0 days|GPLv3|Blacklist
EasyList Hebrew|https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt||1.0 days|GPLv3|Blacklist
EasyList Italy|https://easylist-downloads.adblockplus.org/easylistitaly.txt||1.0 days|GPLv3|Blacklist
EasyList|https://easylist.to/easylist/easylist.txt||4.0 days|GPLv3|Blacklist
EasyPrivacy|https://easylist.to/easylist/easyprivacy.txt||4.0 days|GPLv3|Blacklist
Easylist Czech and Slovak filter list|https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt|tomasko126, Aslanex, vobruba-martin, Moskoe, Fanboy|4.0 hours|CC-BY-SA-4.0|Blacklist
Fanboy's Annoyance List|https://easylist.to/easylist/fanboy-annoyance.txt||4.0 days|GPLv3|Blacklist
Frellwit's Swedish Hosts File|https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Hosts-File.txt||1.0 days|GPL-3.0|Blacklist
GOODBYE ADS|https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt|Jerryn70 (XDA Senior Member)|1.0 days|MIT|Blacklist
International List|https://raw.githubusercontent.com/betterwebleon/international-list/master/filters.txt||3.0 days|The Unlicense|Blacklist
KADhosts|https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt||1.0 days|CC-BY-SA-4|Blacklist
Latvian List|https://hostsfile.mine.nu/hosts0.txt||1.0 days|GPLv3|Blacklist
Lightswitch05's ads-and-tracking-extended.txt|https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt|Daniel White|2.0 days|Apache2|Blacklist
Lightswitch05's ads-and-tracking.txt|https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking.txt|Daniel White|2.0 days|Apache2|Blacklist
Lightswitch05's tracking-aggressive-extended.txt|https://raw.githubusercontent.com/lightswitch05/hosts/master/tracking-aggressive-extended.txt|Daniel White|2.0 days|Apache2|Blacklist
MinerBlock Filters|https://raw.githubusercontent.com/xd4rker/MinerBlock/master/assets/filters.txt||1.0 days|MIT|Blacklist
NoCoin Filter List|https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt||1.0 days|MIT|Blacklist
NoTrack Malware Blocklist|https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt|QuidsUp|1.0 days|GPLv3|Blacklist
NoTrack Tracker Blocklist|https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt|QuidsUp|1.0 days|GPLv3|Blacklist
Press the Attack|https://raw.githubusercontent.com/bogachenko/presstheattack/master/presstheattack.txt||3.0 hours|MIT|Blacklist
Privacy filters|https://raw.githubusercontent.com/metaphoricgiraffe/tracking-filters/master/trackingfilters.txt||1.0 days|The Unlicense|Blacklist
Ransomware Domain Blocklist|https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt||1.0 days|Free for use without any limitations|Blacklist
Ransomware IP Blocklist|https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt||1.0 days|Free for use without any limitations|Blacklist
Ransomware URL Blocklist |https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt||1.0 days|Free for use without any limitations|Blacklist
Skeletal Blocker|https://raw.githubusercontent.com/SkeletalDemise/Skeletal-Blocker/master/Skeletal%20Blocker%20List|SkeletalDemise|2.0 days|GPLv3|Blacklist
Spam404|https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt||2.0 days|Permission to modify, copy and distribute|Blacklist
The Hosts File Project|https://hblock.molinero.dev/hosts|Héctor Molinero Fernández <hector@molinero.dev>|1.0 days|MIT|Blacklist
Toshiya's Filter List - Experimental|https://raw.githubusercontent.com/toshiya44/myAssets/master/filters-exp.txt|Toshiya|4.0 days|GPLv3|Blacklist
VX Vault last 100 Links|http://vxvault.net/URL_List.php|Kicelo, Dominik Schuermann|1.0 days|Copyleft 2010. No rights reserved. |Blacklist
WindowsSpyBlocker - Hosts extra rules|https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt||1.0 days|MIT|Blacklist
WindowsSpyBlocker - Hosts spy rules|https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt||1.0 days|MIT|Blacklist
😍 All-in-One Customized Adblock List 2.7|https://raw.githubusercontent.com/hl2guide/All-in-One-Customized-Adblock-List/master/deanoman-adblocklist.txt|deanoman|2.0 hours|MIT|Blacklist
abuse.ch Feodo Tracker Botnet C2 IP Blocklist|https://feodotracker.abuse.ch/downloads/ipblocklist.txt||1.0 days|CC0|Blacklist
abuse.ch SSLBL Botnet C2 IP Blacklist|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt||1.0 days|CC0|Blacklist
abuse.ch URLhaus Response Policy Zones|https://urlhaus.abuse.ch/downloads/rpz/||1.0 days|CC0|Blacklist
abuse.ch ZeuS IP blocklist BadIPs|https://zeustracker.abuse.ch/blocklist.php?download=badips||1.0 days|CC0|Blacklist
abuse.ch ZeuS domain blocklist|https://zeustracker.abuse.ch/blocklist.php?download=baddomains||1.0 days|CC0|Blacklist
hostsVN|https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts||1.0 days|MIT|Blacklist
uBlock filters -- Unbreak|https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt||4.0 days|GPLv3|Blacklist
uBlock filters – Badware risks|https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt||4.0 days|GPLv3|Blacklist
uBlock filters – Privacy|https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt||4.0 days|GPLv3|Blacklist
uBlock filters – Resource abuse|https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt||4.0 days|GPLv3|Blacklist
uBlock filters|https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt||4.0 days|GPLv3|Blacklist

## Credits

enemyofarsenic(Reddit): Many very useful suggestions such as whitelist, passive dns, and many lists

