//! The BARK coordination server, as a program.
//!
//! Run with no arguments and it configures itself: creates its data folder,
//! generates its certificate, opens its database, listens, and prints the join
//! information an administrator copies to each machine. There is nothing to
//! configure and no database to administer.
//!
//! It will later also run as a Windows service; this is the same code with a
//! different front door.

use bark_core::{BarkError, Result};
use bark_net::endpoint::{bidirectional_endpoint, local_address, Role};
use bark_net::tls::{pinned_client_config, TransportCredentials};
use bark_server::db::Db;
use bark_server::registry::Registry;
use bark_server::session::ServerState;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    let options = match Options::from_args(std::env::args().skip(1)) {
        Ok(Some(o)) => o,
        // `--help` was asked for; the text has already been printed.
        Ok(None) => return,
        Err(e) => {
            eprintln!("{e}");
            eprintln!();
            eprintln!("Run with --help to see the available options.");
            std::process::exit(2);
        }
    };

    bark_core::clock::init();
    bark_core::logging::init_in(&options.data_dir.join("logs"), bark_core::logging::Component::Server, true);

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("BARK could not start its network runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = runtime.block_on(run(options)) {
        eprintln!();
        eprintln!("{}", e.explain());
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Options {
    data_dir: PathBuf,
    bind: SocketAddr,
    /// Print the join information and exit, without listening.
    show_join_only: bool,
}

impl Options {
    fn from_args(args: impl Iterator<Item = String>) -> Result<Option<Self>> {
        let mut data_dir = bark_core::paths::server_dir();
        let mut port = bark_core::DEFAULT_SERVER_PORT;
        let mut host = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut show_join_only = false;

        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" | "/?" => {
                    print_help();
                    return Ok(None);
                }
                "--version" | "-V" => {
                    println!("BARK Coordination Server {}", bark_core::VERSION);
                    return Ok(None);
                }
                "--join-info" => show_join_only = true,
                "--data-dir" => {
                    let v = args.next().ok_or_else(|| {
                        BarkError::config("--data-dir needs a folder after it")
                    })?;
                    data_dir = PathBuf::from(v);
                }
                "--port" => {
                    let v = args
                        .next()
                        .ok_or_else(|| BarkError::config("--port needs a number after it"))?;
                    port = v.parse().map_err(|_| {
                        BarkError::config(format!("\"{v}\" is not a valid port number"))
                    })?;
                }
                "--host" => {
                    let v = args
                        .next()
                        .ok_or_else(|| BarkError::config("--host needs an address after it"))?;
                    host = v.parse().map_err(|_| {
                        BarkError::config(format!("\"{v}\" is not a valid IP address"))
                    })?;
                }
                other => {
                    return Err(BarkError::config(format!("Unknown option \"{other}\".")));
                }
            }
        }

        Ok(Some(Options { data_dir, bind: SocketAddr::new(host, port), show_join_only }))
    }
}

fn print_help() {
    println!("BARK Coordination Server {}", bark_core::VERSION);
    println!();
    println!("Run with no options to start the server with its normal settings.");
    println!();
    println!("Options:");
    println!("  --join-info          Show the information other computers need, then exit");
    println!("  --port <number>      Listen on a different port (default {})", bark_core::DEFAULT_SERVER_PORT);
    println!("  --host <address>     Listen on one address only (default: all addresses)");
    println!("  --data-dir <folder>  Keep the database and certificate somewhere else");
    println!("  --version            Show the version");
    println!("  --help               Show this text");
}

async fn run(options: Options) -> Result<()> {
    std::fs::create_dir_all(&options.data_dir)?;

    let (credentials, created) = TransportCredentials::load_or_create(&options.data_dir)?;
    if created {
        tracing::info!("generated a new server certificate");
    }

    if options.show_join_only {
        print_join_info(&credentials, options.bind.port());
        return Ok(());
    }

    let db = Arc::new(Db::open(&options.data_dir.join("bark-server.sqlite"))?);
    let registry = Arc::new(Registry::new());

    let endpoint = bidirectional_endpoint(
        options.bind,
        &credentials,
        // The server never dials nodes, but the endpoint needs a client
        // configuration; pinning its own certificate is the safe filler.
        pinned_client_config(credentials.fingerprint())?,
        Role::Control,
    )?;
    let listening = local_address(&endpoint)?;

    // The relay listens on the next port up, on the same address.
    let relay_bind = std::net::SocketAddr::new(options.bind.ip(), listening.port().wrapping_add(1));
    let relay = bark_server::relay::Relay::bind(relay_bind, Default::default()).await?;
    tokio::spawn(relay.clone().run());

    let state = Arc::new(ServerState {
        db: db.clone(),
        registry: registry.clone(),
        cert_fingerprint: credentials.fingerprint(),
        version: bark_core::VERSION.to_string(),
        relay: Some(relay.clone()),
    });

    bark_server::serve::note_start(&state, listening)?;

    println!();
    println!("BARK Coordination Server {} is running.", bark_core::VERSION);
    println!("  Listening on   {listening}");
    println!("  Relay          {} (UDP)", relay.listening());
    println!("  Data folder    {}", options.data_dir.display());
    println!("  Devices known  {}", db.device_count()?);
    println!();
    print_join_info(&credentials, listening.port());
    println!("Press Ctrl+C to stop.");
    println!();

    let (accept, maintenance) = bark_server::serve::spawn(state.clone(), endpoint);

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| BarkError::other(format!("could not listen for Ctrl+C: {e}")))?;

    println!();
    println!("Stopping. {} device(s) were connected.", registry.online_count());
    accept.abort();
    maintenance.abort();
    Ok(())
}

/// Prints what an administrator types into each machine.
///
/// Deliberately plain text that survives being pasted into an email or read
/// down a phone line. The fingerprint is the security-relevant part: it is what
/// stops a machine being pointed at an impostor server.
fn print_join_info(credentials: &TransportCredentials, port: u16) {
    println!("------------------------------------------------------------------");
    println!(" JOIN INFORMATION");
    println!();
    println!(" Enter this on each computer that should use this BARK server.");
    println!();
    println!("   Server address:  <this computer's name or IP>:{port}");
    println!("   Server key:      {}", credentials.fingerprint_text());
    println!();
    println!(" The server key is not a password. It is a fingerprint that lets");
    println!(" each computer confirm it is talking to this server and not an");
    println!(" impostor, so it is safe to email or read aloud.");
    println!("------------------------------------------------------------------");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Options>> {
        Options::from_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn default_options_are_sensible() {
        let o = parse(&[]).unwrap().expect("should parse");
        assert_eq!(o.bind.port(), bark_core::DEFAULT_SERVER_PORT);
        assert!(o.bind.ip().is_unspecified(), "listens on every address by default");
        assert!(!o.show_join_only);
        assert!(o.data_dir.ends_with("server"));
    }

    #[test]
    fn options_are_parsed() {
        let o = parse(&["--port", "9999", "--host", "127.0.0.1", "--data-dir", "C:\\temp\\bark"])
            .unwrap()
            .expect("should parse");
        assert_eq!(o.bind.port(), 9999);
        assert_eq!(o.bind.ip().to_string(), "127.0.0.1");
        assert_eq!(o.data_dir, PathBuf::from("C:\\temp\\bark"));
    }

    #[test]
    fn join_info_exits_without_listening() {
        let o = parse(&["--join-info"]).unwrap().expect("should parse");
        assert!(o.show_join_only);
    }

    #[test]
    fn help_and_version_stop_early() {
        assert!(parse(&["--help"]).unwrap().is_none());
        assert!(parse(&["--version"]).unwrap().is_none());
    }

    #[test]
    fn bad_options_are_explained_rather_than_ignored() {
        let e = parse(&["--nonsense"]).unwrap_err();
        assert!(format!("{e}").contains("nonsense"), "should name the bad option");

        let e = parse(&["--port"]).unwrap_err();
        assert!(format!("{e}").contains("needs a number"));

        let e = parse(&["--port", "not-a-number"]).unwrap_err();
        assert!(format!("{e}").contains("not a valid port"));

        let e = parse(&["--host", "999.999.999.999"]).unwrap_err();
        assert!(format!("{e}").contains("not a valid IP"));

        let e = parse(&["--data-dir"]).unwrap_err();
        assert!(format!("{e}").contains("needs a folder"));
    }
}
