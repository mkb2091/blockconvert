set -e
cargo run --release generate
git commit output -m "Ran Autoupdate"
git push
cargo run --release find-domains --virus-total-api $1

