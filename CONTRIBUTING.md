# Contributing

If you are contibuting, then thank you, it is appreciated. Below is what requirements a change must have for it to be added, and what information would be useful to have. 

## Adding to whitelist
Requirement(s):
- Adding domain to whitelist must fix broken functionality/blocked first-party websites, advert domains will not be whitelisted.

Information needed:
- What website is blocked/broken, for third-party domains, just the blocked domains that need to be whitelisted isn't enough.

## Adding a new filter list
Requirement(s):
- URL must be to original host(unless original no longer exists), not a mirror/processed version
- License must be compatible with GPLv3

Information needed:
- URL to filter list
- Whether filter list is blacklist or whitelist
- Whether it is a list of malicious paths(will result in base domains being added)

## Adding a domain to blacklist
Requirement(s):
- Must not break pages

Information needed:
- Reason for adding domain, eg for adverts, example website using it, for malicious domains, virustotal report or other proof that it is malicious
