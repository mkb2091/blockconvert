set -e
cargo run --release generate
git commit -a -m "Ran Autoupdate"
git push
cargo run --release find-domains --virus-total-api $1

