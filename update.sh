set -e
git pull
python3 main.py
git commit -a -m "Ran Autoupdate"
git push
