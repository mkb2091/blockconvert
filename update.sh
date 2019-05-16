set -e
git pull
python3 download.py
python3 blockconvert.py
git commit -a -m "Ran Update"
git push
