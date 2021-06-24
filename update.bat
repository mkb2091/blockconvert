cargo run --release generate --concurrent-requests 10 --dns-max-age 1209600 --extracted-max-age 604800 --file-max-size 40000000
git commit output -m "Ran Autoupdate"
git push