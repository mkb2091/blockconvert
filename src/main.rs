fn main() {
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    let mut client = reqwest::Client::new();
    let servers = [
        "https://dns.google.com/resolve".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
    ];
    let mut rng = rand::thread_rng();
    let attempts = 3;
    let dns_result = blockconvert::doh::lookup_domain(
        &servers,
        &mut client,
        &mut rng,
        attempts,
        "analytics.google.com",
    );
    let output = rt.block_on(dns_result);
    println!("Result: {:?}", output);
}
