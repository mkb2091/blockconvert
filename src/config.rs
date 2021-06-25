use notify::Watcher;
use serde_derive::Deserialize;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Clone, Default, Debug, Deserialize)]
pub struct OutputPaths {
    pub blocked_domains: String,
    pub allowed_domains: String,
    pub hostfile: String,
    pub adblock: String,
    pub allowed_adblock: String,
    pub rpz: String,
    pub blocked_ips: String,
    pub allowed_ips: String,
}

#[derive(Clone, Default, Debug, Deserialize)]
pub struct Paths {
    pub output_base: String,
    pub output: OutputPaths,
    pub extracted: String,
}

#[derive(Clone, Default, Debug, Deserialize)]
struct InternalConfig {
    dns_servers: Vec<String>,
    virus_total_api: Option<String>,
    concurrent_requests: usize,
    max_dns_age: u64,
    max_extracted_age: u64,
    max_file_size: usize,
    timeout: Option<std::time::Duration>,
    paths: Paths,
}

#[derive(Debug)]
pub enum ReadConfigError {
    Io(std::io::Error),
    Parsing(toml::de::Error),
}

impl From<std::io::Error> for ReadConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<toml::de::Error> for ReadConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Parsing(error)
    }
}

impl std::fmt::Display for ReadConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => write!(f, "Config IO Error: {}", io),
            Self::Parsing(parsing) => write!(f, "Config Parsing Error: {}", parsing),
        }
    }
}

impl std::error::Error for ReadConfigError {}

type DnsServers = Box<[Arc<str>]>;

#[derive(Clone, Default)]
pub struct Config {
    local_id: usize,
    id: Arc<AtomicUsize>,
    base: Arc<Mutex<(InternalConfig, DnsServers, Arc<Paths>)>>,
    dns_servers: DnsServers,
    paths: Arc<Paths>,
    virus_total_api: Option<String>,
    concurrent_requests: usize,
    max_dns_age: u64,
    max_extracted_age: u64,
    max_file_size: usize,
    timeout: Option<std::time::Duration>,
}

impl Config {
    pub fn open(path: String) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Self::read_config(&path)?;
        let dns_servers = Self::create_dns_server_list(&config.dns_servers);
        let paths = Arc::new(config.paths.clone());
        let base = Arc::new(Mutex::new((
            config.clone(),
            dns_servers.clone(),
            paths.clone(),
        )));
        let id = Arc::new(AtomicUsize::new(0));

        {
            let base = base.clone();
            let id = id.clone();
            std::thread::spawn(move || {
                let (tx, rx) = std::sync::mpsc::channel();
                let mut watcher = notify::watcher(tx, std::time::Duration::from_secs(2)).unwrap();
                watcher
                    .watch(&path, notify::RecursiveMode::NonRecursive)
                    .unwrap();
                loop {
                    if let Err(e) = rx.recv() {
                        println!("watch error: {:?}", e)
                    }
                    match Self::read_config(&path) {
                        Ok(config) => {
                            let dns_servers = Self::create_dns_server_list(&config.dns_servers);
                            let paths = Arc::new(config.paths.clone());
                            *base.lock().unwrap() = (config, dns_servers, paths);
                            id.fetch_add(1, Ordering::Relaxed);
                            println!("Reloaded config");
                        }
                        Err(e) => println!("Failed to read config: {:?}", e),
                    }
                }
            });
        }

        Ok(Self {
            local_id: 0,
            id,
            base,
            dns_servers,
            paths,
            virus_total_api: config.virus_total_api,
            concurrent_requests: config.concurrent_requests,
            max_dns_age: config.max_dns_age,
            max_extracted_age: config.max_extracted_age,
            max_file_size: config.max_file_size,
            timeout: config.timeout,
        })
    }

    fn read_config(path: &str) -> Result<InternalConfig, ReadConfigError> {
        Ok(toml::from_str(&std::fs::read_to_string(&path)?)?)
    }

    fn create_dns_server_list(dns_servers: &[String]) -> DnsServers {
        dns_servers
            .iter()
            .map(|server| Arc::from(server.clone()))
            .collect::<Vec<Arc<str>>>()
            .into_boxed_slice()
    }

    fn check_for_updates(&mut self) {
        let id = self.id.load(Ordering::Relaxed);
        if id == self.local_id {
            return;
        }
        self.local_id = id;
        let base = self.base.lock().unwrap();
        self.dns_servers = base.1.clone();
        self.paths = base.2.clone();
        self.concurrent_requests = base.0.concurrent_requests;
        self.max_dns_age = base.0.max_dns_age;
        self.max_extracted_age = base.0.max_extracted_age;
        self.max_file_size = base.0.max_file_size;
        self.timeout = base.0.timeout;
    }
    pub fn get_dns_servers(&mut self) -> &'_ [Arc<str>] {
        self.check_for_updates();
        &self.dns_servers
    }

    pub fn get_concurrent_requests(&mut self) -> usize {
        self.check_for_updates();
        self.concurrent_requests
    }
    pub fn get_max_dns_age(&mut self) -> u64 {
        self.check_for_updates();
        self.max_dns_age
    }
    pub fn get_max_extracted_age(&mut self) -> u64 {
        self.check_for_updates();
        self.max_extracted_age
    }
    pub fn get_max_file_size(&mut self) -> usize {
        self.check_for_updates();
        self.max_file_size
    }
    pub fn get_virus_total_api(&mut self) -> &'_ Option<String> {
        self.check_for_updates();
        &self.virus_total_api
    }
    pub fn get_timeout(&mut self) -> Option<core::time::Duration> {
        self.check_for_updates();
        self.timeout
    }
    pub fn get_paths(&mut self) -> Arc<Paths> {
        self.check_for_updates();
        self.paths.clone()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.base.lock().unwrap())
    }
}
