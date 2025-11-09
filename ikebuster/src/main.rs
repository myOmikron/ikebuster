use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::process::exit;
use std::time::Duration;

use clap::ArgAction;
use clap::Parser;
use ikebuster::detect_supported_versions;
use ikebuster::v2;
use ikebuster::v2::finding::Finding;
use ikebuster::v2::finding::FindingResult;
use ikebuster::v2::serialization::ScanResultOutputFormat;
use ikebuster::v2::ScanOptionsV2;
use ikebuster::ScanError;
use ikebuster::ScanOptions;
use ikebuster::SupportedVersions;
use isakmp::v1::generator::Transform;
use owo_colors::OwoColorize;
use serde::Serialize;
use tokio::select;
use tokio::time::interval;
use tracing::debug;
use tracing::info;

const BANNER: &str = r#"
Welcome to
  _ _        _               _
 (_) | _____| |__  _   _ ___| |_ ___ _ __
 | | |/ / _ \ '_ \| | | / __| __/ _ \ '__|
 | |   <  __/ |_) | |_| \__ \ ||  __/ |
 |_|_|\_\___|_.__/ \__,_|___/\__\___|_|

"#;

macro_rules! owo_println {
    ($input:expr) => {
        println!("{} {}", "[ikebuster]".purple().bold(), $input);
    };
}

/// Possible scan modes for ikebuster
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ScanMode {
    V1,
    V2,
    Both,
    Autodetect,
}

/// The cli of ikebuster
#[derive(Debug, Parser)]
#[clap(author, version)]
pub struct Cli {
    /// The mode of the scan, either IKEv1, IKEv2, both, or autodetect
    pub mode: ScanMode,

    /// The IP to scan
    pub ip: IpAddr,

    /// The port to connect to
    #[clap(short, default_value_t = 500)]
    pub port: u16,

    /// The local listen port to bind to (values other than 500 may not work with all servers)
    #[clap(long, default_value_t = 500)]
    pub listen_port: u16,

    /// The interval in milliseconds in which the messages should be sent
    #[clap(short, long, default_value_t = 500)]
    pub interval: u64,

    /// The max number of transforms to send in a proposal
    #[clap(long, default_value_t = 20)]
    pub transforms: usize,

    /// Output the results in a JSON file
    #[clap(long)]
    pub json: Option<String>,

    /// Output the results in a CSV file. Only used in IKEv2
    #[clap(long)]
    pub csv: Option<String>,

    /// Save the current scanning state periodically to a JSON file. Only used in IKEv2
    #[clap(long)]
    pub json_state: Option<String>,

    /// The sleep time (in seconds) after a valid transform is found.
    ///
    /// Some servers limit new requests when there are half-open connections. Only used in IKEv1
    #[clap(long, default_value_t = 45)]
    pub sleep_on_transform_found: u64,

    /// Do not probe the target host before the scan to check the remote host,
    /// i.e. send a single packet with many transforms first
    #[clap(long, action)]
    pub no_probing: bool,

    /// Set the verbosity of the output
    #[clap(short, long, action = ArgAction::Count)]
    pub verbose: u8,
}

/// container struct for json output
#[derive(Serialize)]
pub struct DataOutput {
    /// The target that was scanned
    pub target: SocketAddr,
    /// All found valid transforms
    pub valid_transforms: Vec<Transform>,
}

/// Main function for the IKEv2 mode which is called via the actual main function as a wrapper
async fn main_v2(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let options = ScanOptionsV2 {
        ip: cli.ip,
        port: cli.port,
        listen_port: cli.listen_port,
        interval: cli.interval,
        transform_no: cli.transforms,
        json_state: cli.json_state.clone(),
        enable_probing: !cli.no_probing,
    };

    let now = std::time::Instant::now();
    let handler = match v2::scanner::start_scan(&options).await {
        Ok(handler) => handler,
        Err(err) => {
            if let ScanError::CouldNotBind(e) = &err {
                print_couldnt_bind_solution(cli.listen_port, e)?
            };
            return Err(err.into());
        }
    };
    let mut ticker = interval(Duration::from_millis(1_500));
    let mut updater = interval(Duration::from_millis(15_000));
    updater.tick().await;

    loop {
        select! {
            _ = ticker.tick() => {
                if handler.is_finished() {
                    break;
                }
            }

            _ = updater.tick() => {
                let progress = handler.progress().await;
                let remaining = handler.remaining().await;
                let stats = handler.stats().await;
                if let Some(stats) = stats {
                    owo_println!(format!(
                        "Stats: {:.1}%. {} remaining. Sent {} bytes / {} packets. Received {} bytes / {} packets. {} errors.",
                        progress.unwrap_or_default() * 100f64,
                        remaining.unwrap_or(usize::MAX),
                        stats.sent_bytes,
                        stats.sent_packets,
                        stats.recv_bytes,
                        stats.recv_packets,
                        stats.errors
                    ));
                }

                if let Some(json_state_path) = &cli.json_state {
                    if let Some(state) = handler.dump_state().await {
                        let file = File::create(json_state_path)?;
                        serde_json::to_writer_pretty(file, &state)?;
                    }
                }
            }
        }
    }

    let (results, statistics) = handler.complete().await??;
    let elapsed = now.elapsed();
    info!(
        "Completed scan in {:#?}. Accepted {} proposals, rejected {} proposals.",
        elapsed,
        results.accepted.len(),
        results.rejected.len()
    );
    for v in results.vendor_ids.iter() {
        debug!("Vendor ID detected: {v:#?}");
    }
    debug!(
        sent_bytes = statistics.sent_bytes,
        sent_packets = statistics.sent_packets,
        recv_bytes = statistics.recv_bytes,
        recv_packets = statistics.recv_packets,
        errors = statistics.errors,
        "Stats: Sent {} bytes / {} packets. Received {} bytes / {} packets. {} errors.",
        statistics.sent_bytes,
        statistics.sent_packets,
        statistics.recv_bytes,
        statistics.recv_packets,
        statistics.errors
    );

    let findings = results.to_findings();
    if let Some(csv_path) = &cli.csv {
        let mut file = File::create(csv_path)?;
        let content = v2::finding::format_to_csv(&findings)?;
        file.write_all(content.as_bytes())?;
    }
    if let Some(json_path) = &cli.json {
        let mut file = File::create(json_path)?;
        let content = serde_json::to_string_pretty(&ScanResultOutputFormat {
            target: cli.ip,
            target_port: cli.port,
            completed: true,
            statistics,
            rejected: results.rejected.len(),
            invalid_syntax: results.invalid_syntax.len(),
            accepted: results
                .accepted
                .iter()
                .filter_map(|p| Finding::from_proposal(p, FindingResult::Accepted))
                .collect(),
            vendor_ids: results.vendor_ids,
        })?;
        file.write_all(content.as_bytes())?;
    }

    owo_println!("---------------");
    if findings.is_empty() {
        owo_println!("No valid transforms found :(".yellow());
    } else {
        owo_println!("Found transforms:");
    }
    for finding in findings.iter() {
        if finding.result == FindingResult::Accepted {
            owo_println!(format!(
                "\t{}{} {}{} {}{} {}{}",
                "ENC=".bright_black(),
                if let Some(key_len) = finding.key_size {
                    format!("{}/{key_len}", finding.encryption)
                } else {
                    finding.encryption.to_string()
                },
                "INT=".bright_black(),
                finding
                    .integrity
                    .map(|i| i.to_string())
                    .unwrap_or("<none>".to_string()),
                "PRF=".bright_black(),
                finding.prf,
                "KEX=".bright_black(),
                finding.kex,
            ));
        }
    }
    owo_println!("---------------");

    Ok(())
}

async fn main_v1(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let opts = ScanOptions {
        ip: cli.ip,
        port: cli.port,
        interval: cli.interval,
        transform_no: cli.transforms,
        sleep_on_transform_found: Duration::new(cli.sleep_on_transform_found, 0),
    };

    let res = match ikebuster::scan(opts).await {
        Ok(res) => res,
        Err(err) => {
            match &err {
                ScanError::CouldNotBind(e) => {
                    print_couldnt_bind_solution(500, &e)?;
                }
                _ => {
                    owo_println!(format!("{err}").red().bold());
                }
            }
            return Err(err.into());
        }
    };

    owo_println!("---------------");

    if res.valid_transforms.is_empty() {
        owo_println!("No valid transforms found :(".yellow());
    } else {
        owo_println!("Found transforms:");
    }

    for valid in &res.valid_transforms {
        owo_println!(format!(
            "\t{}{} {}{} {}{} {}{}",
            "ENC=".bright_black(),
            if let Some(key_len) = valid.key_size {
                format!("{}/{key_len}", valid.encryption_algorithm)
            } else {
                valid.encryption_algorithm.to_string()
            },
            "HASH=".bright_black(),
            valid.hash_algorithm,
            "AUTH=".bright_black(),
            valid.authentication_method,
            "GROUP=".bright_black(),
            valid.group_description,
        ));
    }
    if let Some(target) = &cli.json {
        owo_println!("---------------");
        let Ok(serialized) = serde_json::to_string_pretty(&DataOutput {
            target: SocketAddr::new(cli.ip, cli.port),
            valid_transforms: res.valid_transforms,
        }) else {
            owo_println!("Error serializing results".bright_red());
            exit(1);
        };

        let mut file = match File::create(target) {
            Ok(file) => file,
            Err(err) => {
                owo_println!(format!("Error creating json file: {err}").bright_red());
                exit(1);
            }
        };

        write!(file, "{serialized}")?;
        file.flush()?;

        owo_println!(format!(
            "{} {}",
            "Written json output to".bright_black(),
            target.default_color()
        ));
    }
    Ok(())
}

async fn main_both(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    owo_println!("Starting scan for IKEv2, then scanning IKEv1...");
    main_v2(&cli).await?;
    let result_v2 = if let Some(json) = &cli.json {
        Some(fs::read_to_string(json)?)
    } else {
        None
    };
    main_v1(&cli).await?;
    if let Some(json) = &cli.json {
        let result_v1 = fs::read_to_string(json)?;
        if let Some(result_v2) = result_v2 {
            let mut file = match File::create(json) {
                Ok(file) => file,
                Err(err) => {
                    owo_println!(format!("Error creating json file: {err}").bright_red());
                    exit(1);
                }
            };
            write!(
                file,
                "{{\n  \"v1\": {result_v1},\n  \"v2\": {result_v2}\n}}"
            )?;
            file.flush()?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if cli.transforms < 1 {
        owo_println!("At least one transform is required".bright_red());
        exit(2);
    }

    if cli.verbose > 0 {
        match cli.verbose {
            1 => env::set_var("RUST_LOG", "ikebuster=debug"),
            _ => env::set_var("RUST_LOG", "ikebuster=trace"),
        }
    } else if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    println!("{}", BANNER.blue().bold());

    match cli.mode {
        ScanMode::V1 => {
            main_v1(&cli).await?;
        }
        ScanMode::V2 => {
            main_v2(&cli).await?;
        }
        ScanMode::Both => {
            main_both(&cli).await?;
        }
        ScanMode::Autodetect => {
            owo_println!("Trying to autodetect the IKE version supported by the destination...");
            let supported_versions = detect_supported_versions(cli.ip, cli.port, cli.listen_port)
                .await
                .map_err(|e| {
                    owo_println!("Failed to detect IKE version!".bright_red());
                    owo_println!(format!("Error: {:#?}", e).red());
                    e
                })?;
            owo_println!(
                format!("Detected supported IKE versions: {supported_versions:#?}").green()
            );
            match supported_versions {
                SupportedVersions::V1 => {
                    main_v1(&cli).await?;
                }
                SupportedVersions::V2 => {
                    main_v2(&cli).await?;
                }
                SupportedVersions::Both => {
                    main_both(&cli).await?;
                }
                SupportedVersions::Neither => {
                    owo_println!("The autodetection could not determine the supported versions of the target.".yellow());
                    owo_println!("Consider checking if the host is reachable, and specify the version explicitly.".yellow());
                }
            }
        }
    }

    owo_println!("---------------");
    owo_println!("See you soon! :)".blue());

    Ok(())
}

fn print_couldnt_bind_solution(port: u16, e: &std::io::Error) -> Result<(), std::io::Error> {
    owo_println!("---------------");
    owo_println!(format!("Could not bind to local port {}", port)
        .red()
        .bold());
    owo_println!(format!("\t{e}").red().bold());
    owo_println!("---------------");
    owo_println!("Possible solutions:");
    owo_println!(format!("\tsudo {}", env::current_exe()?.display()).bright_black());
    owo_println!(format!(
        "\tsetcap 'cap_net_bind_service=+ep' {}",
        env::current_exe()?.display()
    )
    .bright_black());
    owo_println!("---------------");
    Ok(())
}
