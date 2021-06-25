use crate::config;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use tokio_stream::StreamExt;

pub trait DBReadHandler: Send + Sync {
    fn handle_input(&self, data: &str);
    fn finished_with_file(&self) {}
}

pub async fn dir_db_read<T: 'static + DBReadHandler>(
    handle_input: Arc<T>,
    path: &std::path::Path,
    max_age: u64,
) -> Result<(), std::io::Error> {
    let _ = tokio::fs::create_dir_all(&path).await;
    let mut entries = tokio_stream::wrappers::ReadDirStream::new(tokio::fs::read_dir(&path).await?);

    let mut tasks: futures::stream::FuturesUnordered<_> = futures::stream::FuturesUnordered::new();
    println!("Started reading from files");
    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let metadata = entry.metadata().await?;
        let path = entry.path();
        let handle_input = handle_input.clone();
        let task = tokio::task::spawn(async move {
            let mut record_count: usize = 0;
            if let Ok(modified) = metadata.modified().or_else(|_| metadata.created()) {
                let now = std::time::SystemTime::now();
                if let Ok(duration_since) = now.duration_since(modified) {
                    if duration_since.as_secs() < max_age {
                        if let Ok(file) = tokio::fs::File::open(&path).await {
                            let mut file = tokio::io::BufReader::new(file);
                            let mut line = String::new();
                            while let Ok(len) = file.read_line(&mut line).await {
                                if len == 0 {
                                    break;
                                }
                                handle_input.handle_input(&line);
                                line.clear();
                                record_count += 1;
                            }
                        } else {
                            println!("Failed to read file: {:?}", &path);
                        }
                        if record_count != 0 {
                            println!(
                                "Finished with file: {} with {} records",
                                path.to_string_lossy(),
                                record_count
                            );
                        }
                        handle_input.finished_with_file();
                        return;
                    }
                }
            }
            println!("Removing expired record");
            if std::fs::remove_file(&path).is_err() {
                println!("Failed to remove file: {:?}", path);
            };
        });
        tasks.push(task);
    }
    while tasks.next().await.is_some() {}
    Ok(())
}

async fn open_writer(
    path: &std::path::Path,
    prefix: Option<&String>,
) -> Result<BufWriter<tokio::fs::File>, std::io::Error> {
    let mut path = std::path::PathBuf::from(&path);
    let now = chrono::Local::now().format("%Y-%m-%d %H-%M-%S");

    path.push(if let Some(prefix) = prefix {
        format!("{}_{}", prefix, now)
    } else {
        now.to_string()
    });
    Ok(BufWriter::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?,
    ))
}

pub struct DirDbWriter {
    path: std::path::PathBuf,
    wtr: BufWriter<tokio::fs::File>,
    config: config::Config,
    current_size: usize,
    prefix: Option<String>,
}

impl DirDbWriter {
    pub async fn new(
        path: &std::path::Path,
        config: config::Config,
        prefix: Option<String>,
    ) -> Result<Self, std::io::Error> {
        let _ = tokio::fs::create_dir_all(&path).await;
        Ok(Self {
            wtr: open_writer(&path, prefix.as_ref()).await?,
            path: std::path::PathBuf::from(path),
            config,
            current_size: 0,
            prefix,
        })
    }
    pub async fn write_line(&mut self, line: &[u8]) -> Result<(), std::io::Error> {
        if self.current_size + line.len() > self.config.get_max_file_size() {
            self.wtr.flush().await?;
            self.wtr = open_writer(&self.path, self.prefix.as_ref()).await?;
            self.current_size = 0;
        }
        self.wtr.write_all(line).await?;
        self.wtr.write_all(b"\n").await?;
        self.current_size += line.len() + 1;
        Ok(())
    }
    pub async fn flush(&mut self) -> Result<(), std::io::Error> {
        self.wtr.flush().await?;
        Ok(())
    }
}
