set -e
git pull
python3 main.py
git commit -a -m "Ran Quick Autoupdate"
git push
python3 main.py -u
git commit -a -m "Ran Full Autoupdate"
git push
