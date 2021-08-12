# BlockConvert

Malware, advert and tracking blocklist which consolidates and improves upon many other [blocklists](https://github.com/mkb2091/blockconvert/blob/master/filterlists.csv).


## What this blocks:
- Malware/Phishing: Many malware lists are used in building this list, including multiple malware IP lists, which are used to find many more malware domains.

- Adverts: Adblock syntax is partially supported, so this list is able to extract some advert domains. This list is pretty good at blocking adverts, but an in-browser adblocker such as uBlock Origin is recommended as well as relying on hosts/DNS blocking.

- Trackers: Many tracking domains are extracted from the lists used, including Privacy Badger data files which automatically identify trackers.

- Coin mining: A few coin mining blocklists are used to block browser-based coin mining from using cpu.

## Advantages of using this list:
- Conversion of list types. As well as supporting many common filter list formats, it also supports Privacy Badger data file, which uses algorithms to detect trackers allowing newly created trackers to be quickly detected and added to this blocklist without a human needing to spot the tracker.

- Reverse DNS and passive DNS on malware IP addresses. This allows finding all the domains which a malware IP blacklist suggests could be dangerous to be found and blocked. This allows blocking of malware domains that haven't yet been added to other malware domain lists.

- Use of a whitelist. Using a hosts file doesn't allow whitelisting, and many DNS-based blockers don't have great whitelist support. This list has it's own whitelist, as well as using a few others to try to reduce false positives. This list supports "*" in subdomain and TLD to aid in easily fixing many false positives at once. (If you do find a false positive(a domain that shouldn't be blocked), then please make an issue and I will remove it)

- Use of DNS to check if domains still exist. Many lists contain domains that have expired and no longer exist. This makes those lists larger than needed which wastes bandwidth, space and can slow blocking.

## How to use:
- Pi-hole: Go to the web interface. Log in. Settings -> Blocklists. Copy domain list URL(Pi-hole currently only supports domain lists) from below in the links section, and paste it in the textbox. Click Save.

- Blokada: Open Blokada. Click shield with black middle which says "{number} in blacklist". Click the plus in the circle at the bottom of the screen. Copy and paste hosts file from link sections. Click save. WARNING: This list is large and might slow down your phone

- uBlock Origin: Click the uBlock Origin logo/uBlock Origin extension. Click open dashboard(3 horizontal lines under the disable uBlock Origin button, on the right). Click Filter lists. Scroll to the bottom, and click Import(in custom section). Copy and paste the Adblock style blocklist from the link section below.

## Links

[Adblock Plus format](https://mkb2091.github.io/blockconvert/output/adblock.txt)

[Hosts file format](https://mkb2091.github.io/blockconvert/output/hosts.txt)

WARNING: Too large for Windows: https://github.com/mkb2091/blockconvert/issues/87

[Domain list](https://mkb2091.github.io/blockconvert/output/domains.txt)

[Blocked IP address list](https://mkb2091.github.io/blockconvert/output/ip_blocklist.txt)

[DNS Response Policy Zone(RPZ) format](https://mkb2091.github.io/blockconvert/output/domains.rpz)

As well as generating blocklists, this project also generates whitelists which are used in the process. If you maintain your own blocklist, you may find one of the following whitelists useful:

[Whitelisted domains](https://mkb2091.github.io/blockconvert/output/whitelist_domains.txt)

[Whitelisted ABP format](https://mkb2091.github.io/blockconvert/output/whitelist_adblock.txt)

## The Process

1. Download all expired filterlists

2. Combine and split all the filterlists based on their type. This splits the lines into seperate groups: Adblock rules, blocked domains, regexes of blocked domains, allowed domains, regex of allowed domains, ips which are blocked, ips which are allowed, subnets which are blocked, subnets which are allowed.

3. Apply a regex to all the filterlists to extract domains and combine with other domains found via other means.

4. For each of those domains, use DNS to check if the domain is still active. If the domain isn't in the allowed domains list, doesn't match any of the allowed regexes, isn't in allowed by an adblock exception rule and it is blocked, or one of its cnames/ips is blocked then add it to the output.

Sources: [Sources](https://github.com/mkb2091/blockconvert/blob/master/filterlists.csv)
