set -e
git pull
python3 download.py
python3 blockconvert.py
git commit tld_list.txt dns_cache.txt output/* -m "Ran Update"
git push
