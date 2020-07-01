# BlockConvert

[![HitCount](http://hits.dwyl.io/mkb2091/blockconvert.svg)](http://hits.dwyl.io/mkb2091/blockconvert)

Malware, advert and tracking blocklist which consolidates and improves many other blocklists.


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

- Blokada: Open Blokada. Click shield with black middle which says "{number} in blacklist". Click the plus in the circle at the bottom of the screen. Copy and paste hosts file from link sections. Click save

- uBlock Origin: Click the uBlock Origin logo/uBlock Origin extension. Click open dashboard(3 horizontal lines under the disable uBlock Origin button, on the right). Click Filter lists. Scroll to the bottom, and click Import(in custom section). Copy and paste either Adblock style blocklist or domain blocklist from the link section below.

- IPset + iptables: Run `sudo ipset create BlockConvert` to create the ipset where the blocklist will be. Pick a directory to store file, then set the following script to run on reboot(eg via cron, or via init system) and also create a regular script to download new version(eg weekly/daily cron which runs wget): `sudo ipset -exist -file $PATH_TO_FILE restore && sudo iptables -I INPUT -m set --match-set BlockConvert src -j DROP && sudo iptables -I FORWARD -m set --match-set BlockConvert src -j DROP`

## Links

[Adblock Plus format](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/adblock.txt)

[Hosts file format](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/hosts.txt)

[Domain list](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt)

[Blocked IP address list](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/ip_blocklist.txt)

[IPSet format](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/ip_blocklist.ipset)

[DNS Response Policy Zone(RPZ) format](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.rpz)

As well as generating blocklists, this project also generates whitelists which are used in the process. If you maintain your own blocklist, you may find one of the following whitelists useful:

[Whitelisted domains](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/whitelist_domains.txt)

[Whitelist in AdBlock Plus format](https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/whitelist_adblock.txt)

## The Process

1. Download expired blocklist data and extract domains and IP addresses into whitelist and blacklist

2. Combine all the blacklists and the whitelists

3. Filter out all the IPv4 addresses from each list and use passive dns lookup APIs to find domains which resolve to those IP addresses

4. Store all the IP addresses that were in the blacklist in a seperate list

5. For each domain that has "\*" for its TLD (e.g. "tracker.\*"), replace the "\*" with every TLD in the TLD file

5. Remove all the domains in the whitelist from the blacklist

6. For each domain in each list that starts with either "m." or "www.", add a version of the domain without the subdomain

7. For each domain in the whitelist, if there isn't a version of the domain starting with a "www.", then add one

8. For each domain in the blacklist that starts with a "\*.", remove the start

9. For each domain in the blacklist that is in the whitelist, or is a subdomain of a domain in the whitelist starting with a "\*.", remove that domain from the blacklist

10. For all the domains left, check that they have a valid DNS record, and remove the ones that do not

Sources: [Sources](https://github.com/mkb2091/blockconvert/blob/master/sources.md)

## Donation

Bitcoin: 1MJZRsWS12oX68iGfedrabxQyacGUiGVwv
