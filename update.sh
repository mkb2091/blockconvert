set -e
git pull
cargo run --release generate
git commit output -m "Ran Autoupdate"
git push

