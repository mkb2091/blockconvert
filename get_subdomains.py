def get_subdomains(dns_checker, domains):
    domains = list(set(domains))
    for i in range(len(domains)):
        if domains[i].startswith('*.'):
            domains[i] = domains[i][2:]
    ip_results = dns_checker.mass_check(domains)
    ip_set = set()
    for domain in ip_results:
        if ip_results[domain]:
            ip_set.add(ip_results[domain])
    reverse_lookup_results = dns_checker.mass_reverse_lookup(ip_set)
    results = set()
    targets = []
    for target in domains:
        targets.append('.' + target)
    for domain in dns_checker.cache:
        if dns_checker.cache[domain]:
            for target in targets:
                if domain.endswith(target):
                    results.add(domain)
                    break
    return results
