SOURCES = '''## Last Commit Infomation

Theres are {rule_count} blocked domains in each of the generated filter lists

## Sources

For static sources 100 days is put, and for sources with unknown expires, 1 days is put.

The files in data/ are all modified versions generated from the below sources:

{url_table}

## Credits

enemyofarsenic(Reddit): Many very useful suggestions such as whitelist, passive dns, and many lists

'''


def generate_readme(urls, rule_count):
    url_table = [['Link', 'Author', 'Expires', 'License', 'Type'],
                 [':---:', ':---:', ':---:', ':---:', ':---:']]
    for (
        title,
        url,
        author,
        expires,
        list_license,
        is_whitelist,
        match_url,
            do_reverse_dns) in urls:
        if expires >= 24 * 60 * 60:
            expires = '%s days' % (round(expires / 24 / 60 / 60, 1))
        elif expires >= 60 * 60:
            expires = '%s hours' % (round(expires / 60 / 60, 1))
        elif expires >= 60:
            expires = '%s minute' % (round(expires / 60, 1))
        else:
            expires = '%s seconds' % expires
        if title == '':
            title = url
        if author == '':
            author = '-'
        link = '[%s](%s)' % (title, url)
        url_table.append([link, author, expires, list_license,
                          ('Whitelist' if is_whitelist else 'Blacklist')])
    url_table = '\n'.join('|'.join(line) for line in url_table)
    with open('sources.md', 'w') as file:
        file.write(SOURCES.format(**locals()))
