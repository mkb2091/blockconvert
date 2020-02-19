set -e
git checkout -- .
git pull
python3 main.py
git pull
git commit -a -m "Ran Quick Autoupdate"
git push
python3 main.py -u
git pull
git commit -a -m "Ran Full Autoupdate"
git push
