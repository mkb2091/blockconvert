# BlockConvert


Malware, advert and tracking blacklist

Advantages of using this list:
- Conversion of list types. As well as supporting many common filter list formats, it also supports Privacy Badger data file, which uses algorithms to detect trackers allowing newly created trackers to be quickly detected and added to this blocklist without a human needing to spot the tracker.

- Reverse DNS and passive DNS on malware IP addresses. This allows finding all the domains which a malware IP blacklist suggests could be dangerous to be found and blocked. This allows blocking of malware domains that haven't yet been added to other malware domain lists.

- Use of a whitelist. Using a hosts file doesn't allow whitelisting, and many DNS-based blockers don't have great support of whitelists. This list has it's own whitelist, as well as using a few others to try to reduce false positives. This list supports "*" in subdomain and tld to aid in easily fixing many false positives at once. (If you do find a false positive(domain that shouldn't be blocked), then please make an issue and I will remove it)

- Use of DNS to check if domains still exist. Many lists contain domains that have expired and no longer exist. This makes those lists larger than needed which wastes bandwidth, space and can slow blocking.

## What this blocks:
- Malware/Phishing: Many malware lists are used in building this list, including multiple malware IP lists, which are used to find many more malware domains.

- Adverts: Adblock syntax is partially supported, so this list is able to extract some advert domains. This list is pretty good at blocking adverts, but an in-browser adblocker such as uBlock Origin is recommended as well as relying on hosts/dns blocking.

- Trackers: Many tracking domains are extracted from the lists used, including Privacy Badger data files which automatically identify trackers.

- Coin mining: A few coin mining blocklists are used to block browser-based coin mining from using cpu.

## How to use:
- Pi-hole: Go to web interface. Log in. Settings -> Blocklists. Copy domain list url(Pi-hole supports hosts and domain lists, and domain list is a smaller file) from below in the links section, and paste it in the textbox. Click Save.

- Blokada: Open Blokada. Click shield with black middle which says "{number} in blacklist". Click plus in circle at bottom of screen. Copy and paste hosts file from link sections. Click save

- uBlock Origin: Click uBlock Origin logo. Click open dashboard(3 horizontal lines, under disable uBlock Origin button, on the right). Click Filter lists. Scroll to bottom, and click Import(in custom section). Copy and paste either adblock style blocklist or domain blocklist from the link section below.


## Links

Adblock Plus format:  https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/adblock.txt

Hosts file format: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/hosts.txt

Domain list: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt

DNS Response Policy Zone(RPZ) format: https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.rpz

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

Sources: [Sources](https://github.com/mkb2091/blockconvert/blob/master/sources.md)
