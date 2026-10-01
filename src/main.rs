use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use ssh_stream_gateway::{
    auth, client,
    config::{ClientConfig, Config},
    server,
};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "Authenticated HTTPS/HTTP2 streams to explicitly allowed SSH targets"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the gateway (Mac or Linux); no daemon installation is performed.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Execute a remote shell command, preserving stdin/stdout/stderr and exit status.
    Exec {
        /// Optional TOML with endpoint, ca and password_file (no actual password).
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, required_unless_present = "config")]
        endpoint: Option<String>,
        /// Add this PEM CA/certificate to native TLS trust. Verification is mandatory.
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Owner-only passphrase file; otherwise prompt on /dev/tty with echo disabled.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Alias from the gateway's allowlist.
        target: String,
        /// One quoted string interpreted by the REMOTE shell, never a local shell.
        command: String,
    },
    /// Hash a manually chosen passphrase from the terminal (prints only Argon2id PHC).
    HashPassword,
    /// Check config syntax/security limits without starting a listener or reading SSH keys.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
}
fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            125
        }
    };
    std::process::exit(code);
}
fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Action::HashPassword => {
            let first = auth::prompt("New gateway passphrase (six random words recommended): ")?;
            auth::check_password(&first)?;
            let second = auth::prompt("Repeat passphrase: ")?;
            ensure!(*first == *second, "passphrases did not match");
            println!("{}", auth::hash_password(&first)?);
            Ok(0)
        }
        Action::CheckConfig { config } => {
            Config::load(&config)?;
            eprintln!("Configuration syntax and policy checks passed");
            Ok(0)
        }
        action => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(async {
                match action {
                    Action::Serve { config } => {
                        server::serve(Config::load(&config)?).await?;
                        Ok(0)
                    }
                    Action::Exec {
                        config,
                        endpoint,
                        ca,
                        password_file,
                        target,
                        command,
                    } => {
                        let configured = config
                            .as_deref()
                            .map(ClientConfig::load)
                            .transpose()?
                            .unwrap_or_default();
                        client::execute(client::Options {
                            endpoint: endpoint
                                .or(configured.endpoint)
                                .ok_or_else(|| anyhow::anyhow!("endpoint is required"))?,
                            ca: ca.or(configured.ca),
                            password_file: password_file.or(configured.password_file),
                            target,
                            command,
                        })
                        .await
                    }
                    _ => unreachable!(),
                }
            });
            // Tokio stdin uses a blocking reader. Early remote exit must not wait
            // forever for another local keystroke before the process can terminate.
            runtime.shutdown_timeout(Duration::from_millis(100));
            result
        }
    }
}
