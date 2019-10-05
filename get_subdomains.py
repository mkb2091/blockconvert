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
    min_length = len(domains[0])
    for target in domains:
        targets.append('.' + target)
        if len(target) < min_length:
            min_length = len(target)
    for domain in dns_checker.cache:
        if len(domain) >= (min_length + 2) and dns_checker.cache[domain]:
            for target in targets:
                if domain.endswith(target):
                    results.add(domain)
                    break
    return results
