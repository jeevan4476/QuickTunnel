//! QuickTunnel CLI interface and command implementations.

use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use qt_client::config::HostHeaderRewrite;
use qt_inspector_ui::store::CapturedRequest;

#[derive(Parser, Debug)]
#[command(
    name = "quicktunnel",
    version,
    about = "Fast, secure HTTP and TCP reverse tunnels to localhost"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start QuickTunnel server daemon
    Server(ServerArgs),
    /// Start QuickTunnel client tunnel to localhost
    Client(ClientArgs),
    /// Generate a cryptographically secure 256-bit authentication token
    Genkey,
}

#[derive(Args, Debug, Clone)]
pub struct ServerArgs {
    #[arg(long, default_value = "0.0.0.0:7000")]
    pub control_bind: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:80")]
    pub http_bind: SocketAddr,
    #[arg(long, default_value = "tunnel.local")]
    pub domain: String,
    #[arg(long, default_value = "20000-29999")]
    pub tcp_port_range: String,
    #[arg(long, env = "QT_SECRET")]
    pub secret: String,
}

#[derive(Args, Debug, Clone)]
pub struct ClientArgs {
    #[arg(long, default_value = "127.0.0.1:7000")]
    pub to: String,
    #[arg(long)]
    pub local: String, // e.g. "3000" or "127.0.0.1:3000"
    #[arg(long, default_value = "http")]
    pub mode: String, // "http" or "tcp"
    #[arg(long)]
    pub subdomain: Option<String>,
    #[arg(long)]
    pub remote_port: Option<u16>,
    #[arg(long, env = "QT_SECRET")]
    pub secret: String,
    #[arg(long, default_value = "rewrite")]
    pub host_header: String, // "rewrite", "preserve", or "custom:<host>"
    #[arg(long, default_value_t = 4040)]
    pub inspect_port: u16,
    #[arg(long, default_value_t = false)]
    pub no_inspect: bool,
    #[arg(long, default_value = "pretty")]
    pub log: String, // "pretty" or "json"
}

/// Generate a cryptographically secure 256-bit authentication token.
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Parse local target string into a SocketAddr.
pub fn parse_local_target(input: &str) -> Result<SocketAddr> {
    let mut s = input.trim();
    if s.is_empty() {
        return Err(anyhow::anyhow!("Local target address cannot be empty"));
    }

    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    }

    s = s.trim_end_matches('/');

    if s.is_empty() {
        return Err(anyhow::anyhow!("Local target address cannot be empty"));
    }

    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Some(rest) = s.strip_prefix("localhost:") {
        if let Ok(port) = rest.parse::<u16>() {
            return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
        }
    }
    Err(anyhow::anyhow!(
        "Invalid local target '{}': expected a port (e.g. 3000) or socket address (e.g. 127.0.0.1:3000)",
        input
    ))
}

/// Parse host header rewrite option.
pub fn parse_host_header_rewrite(input: &str) -> Result<HostHeaderRewrite> {
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("rewrite") {
        Ok(HostHeaderRewrite::Rewrite)
    } else if trimmed.eq_ignore_ascii_case("preserve") {
        Ok(HostHeaderRewrite::Preserve)
    } else if let Some(custom) = trimmed.strip_prefix("custom:") {
        let val = custom.trim();
        if val.is_empty() {
            Err(anyhow::anyhow!("Custom host header value cannot be empty"))
        } else {
            Ok(HostHeaderRewrite::Custom(val.to_string()))
        }
    } else if trimmed.eq_ignore_ascii_case("custom") {
        Ok(HostHeaderRewrite::Custom("custom".to_string()))
    } else {
        Err(anyhow::anyhow!(
            "Invalid host-header rewrite policy '{}': must be 'rewrite', 'preserve', or 'custom:<host>'",
            input
        ))
    }
}

/// Parse TCP port range string (e.g. "20000-29999").
pub fn parse_port_range(input: &str) -> Result<RangeInclusive<u16>> {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid port range '{}': expected 'START-END' (e.g. '20000-29999')",
            input
        ));
    }
    let start = parts[0].trim().parse::<u16>().map_err(|e| {
        anyhow::anyhow!("Invalid port range '{}': invalid start port: {}", input, e)
    })?;
    let end = parts[1]
        .trim()
        .parse::<u16>()
        .map_err(|e| anyhow::anyhow!("Invalid port range '{}': invalid end port: {}", input, e))?;
    if start > end {
        return Err(anyhow::anyhow!(
            "Invalid port range '{}-{}': start port cannot be greater than end port",
            start,
            end
        ));
    }
    Ok(start..=end)
}

/// Format a captured request access log line.
pub fn format_request_log(req: &CapturedRequest, format: &str) -> String {
    match format.to_ascii_lowercase().as_str() {
        "json" => {
            let status = req.response.as_ref().map(|r| r.status);
            let status_text = req.response.as_ref().map(|r| r.status_text.as_str());
            let json_obj = serde_json::json!({
                "id": req.id,
                "visitor_ip": req.visitor_ip,
                "method": req.request.method,
                "path": req.request.path,
                "status": status,
                "status_text": status_text,
                "duration_ms": req.timing.total_ms,
                "is_replay": req.is_replay,
            });
            serde_json::to_string(&json_obj).unwrap_or_else(|_| "{}".to_string())
        }
        _ => {
            if let Some(ref resp) = req.response {
                format!(
                    "{} {} {} {} {}ms",
                    req.request.method,
                    req.request.path,
                    resp.status,
                    resp.status_text,
                    req.timing.total_ms
                )
            } else {
                format!("{} {} (in flight)", req.request.method, req.request.path)
            }
        }
    }
}

/// Format startup terminal status banner.
pub fn format_banner(
    status: &str,
    public_url: &str,
    local_target: &SocketAddr,
    inspector_url: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("QuickTunnel Client\n");
    out.push_str(&format!("Status:       {}\n", status));
    out.push_str(&format!(
        "Forwarding:   {} -> {}\n",
        public_url, local_target
    ));
    if let Some(inspector) = inspector_url {
        out.push_str(&format!("Web Inspector: {}\n", inspector));
    }
    out
}

/// Wait for shutdown signal (SIGINT/Ctrl+C or SIGTERM on Unix).
pub async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| anyhow::anyhow!("Failed to register SIGTERM handler: {e}"))?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    Ok(())
}

/// Run server daemon until SIGINT or SIGTERM shutdown signal.
pub async fn run_server(args: ServerArgs) -> Result<()> {
    run_server_with_shutdown(args, async {
        let _ = wait_for_shutdown_signal().await;
    })
    .await
}

/// Run server daemon with custom shutdown signal.
pub async fn run_server_with_shutdown<F: std::future::Future<Output = ()> + Send>(
    args: ServerArgs,
    shutdown_signal: F,
) -> Result<()> {
    let port_range = parse_port_range(&args.tcp_port_range)?;
    let config = qt_server::ServerConfig::new()
        .with_control_bind(args.control_bind)
        .with_http_bind(args.http_bind)
        .with_root_domain(args.domain)
        .with_tcp_port_range(port_range)
        .with_secret(args.secret);
    let server = Arc::new(qt_server::Server::new(config));
    let server_clone = server.clone();

    tokio::select! {
        res = server_clone.run() => {
            res.map_err(|e| anyhow::anyhow!("Server error: {}", e))?;
        }
        _ = shutdown_signal => {
            tracing::info!("Shutdown signal received, shutting down server...");
            server.shutdown();
        }
    }
    Ok(())
}

/// Run client daemon until SIGINT or SIGTERM shutdown signal.
pub async fn run_client(args: ClientArgs) -> Result<()> {
    run_client_with_shutdown(args, async {
        let _ = wait_for_shutdown_signal().await;
    })
    .await
}

/// Run client daemon with custom shutdown signal.
pub async fn run_client_with_shutdown<F: std::future::Future<Output = ()> + Send>(
    args: ClientArgs,
    shutdown_signal: F,
) -> Result<()> {
    let local_target = parse_local_target(&args.local)?;
    let mode = match args.mode.to_ascii_lowercase().as_str() {
        "http" => qt_proto::TunnelMode::Http,
        "tcp" => qt_proto::TunnelMode::Tcp,
        other => {
            return Err(anyhow::anyhow!(
                "Invalid tunnel mode '{}': expected 'http' or 'tcp'",
                other
            ))
        }
    };
    let host_header = parse_host_header_rewrite(&args.host_header)?;
    let server_addr = match args.to.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            // Try resolving as hostname:port (e.g. "localhost:7000" or domain)
            let mut addrs = tokio::net::lookup_host(&args.to)
                .await
                .map_err(|e| anyhow::anyhow!("Invalid server address '{}': {}", args.to, e))?;
            addrs
                .next()
                .ok_or_else(|| anyhow::anyhow!("Could not resolve server address '{}'", args.to))?
        }
    };

    let mut config = qt_client::ClientConfig::new()
        .with_server_addr(server_addr)
        .with_local_target(local_target)
        .with_mode(mode)
        .with_host_header(host_header)
        .with_secret(args.secret);

    if let Some(subdomain) = args.subdomain {
        config = config.with_subdomain(subdomain);
    }
    if let Some(remote_port) = args.remote_port {
        config = config.with_remote_port(remote_port);
    }

    let inspector_setup = if !args.no_inspect && mode == qt_proto::TunnelMode::Http {
        let store = Arc::new(qt_inspector_ui::InspectorStore::new(1000, 64 * 1024 * 1024));
        let (tap_sender, _tap_handle) = qt_inspector_ui::HttpTapSender::new(store.clone());
        let inspect_addr = SocketAddr::from(([127, 0, 0, 1], args.inspect_port));
        let inspector_server =
            qt_inspector_ui::InspectorServer::new(inspect_addr, store.clone(), local_target);
        let srv_clone = inspector_server.clone();
        tokio::spawn(async move {
            if let Err(e) = srv_clone.run().await {
                tracing::error!("Inspector server error on {}: {e}", srv_clone.bind_addr());
            }
        });

        // Spawn live request log streamer
        let mut rx = store.subscribe();
        let log_format = args.log.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(req) => {
                        if req.response.is_some() {
                            let line = format_request_log(&req, &log_format);
                            println!("{line}");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!("Request log stream lagged, skipped {skipped} requests");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Some((store, tap_sender, inspector_server))
    } else {
        None
    };

    let mut tunnel = qt_client::ClientTunnel::new(config);
    if let Some((_, ref tap_sender, _)) = inspector_setup {
        tunnel = tunnel.with_tap(tap_sender.clone());
    }
    let tunnel = Arc::new(tunnel);

    let tunnel_clone = tunnel.clone();
    let is_no_inspect = args.no_inspect;
    let inspect_port = args.inspect_port;

    // Spawn banner printer on connection
    let connected_notify = tunnel.connected_notify();
    tokio::spawn(async move {
        connected_notify.notified().await;
        if tunnel_clone.is_running() {
            let pub_url = tunnel_clone.public_url().unwrap_or_else(|| {
                if let Some(port) = tunnel_clone.assigned_port() {
                    format!("tcp:{}", port)
                } else {
                    "online".into()
                }
            });
            let inspector_url = if !is_no_inspect && mode == qt_proto::TunnelMode::Http {
                Some(format!("http://127.0.0.1:{}", inspect_port))
            } else {
                None
            };
            let banner = format_banner("Online", &pub_url, &local_target, inspector_url.as_deref());
            println!("{banner}");
        }
    });

    let tunnel_run = tunnel.clone();
    tokio::select! {
        res = tunnel_run.run() => {
            if let Err(e) = res {
                return Err(anyhow::anyhow!("Client tunnel error: {}", e));
            }
        }
        _ = shutdown_signal => {
            tracing::info!("Shutdown signal received, shutting down client...");
            tunnel.shutdown();
            if let Some((_, _, ref srv)) = inspector_setup {
                srv.shutdown();
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_genkey_generates_valid_hex_secret() {
        let key = generate_token();
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(key.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_genkey_randomness() {
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..10 {
            let key = generate_token();
            assert_eq!(key.len(), 64);
            assert!(tokens.insert(key));
        }
    }

    #[test]
    fn test_cli_parsing_defaults() {
        let args = Cli::parse_from([
            "quicktunnel",
            "client",
            "--local",
            "3000",
            "--secret",
            "test",
        ]);
        match args.command {
            Commands::Client(c) => {
                assert_eq!(c.local, "3000");
                assert_eq!(c.to, "127.0.0.1:7000");
                assert_eq!(c.secret, "test");
                assert_eq!(c.mode, "http");
                assert_eq!(c.host_header, "rewrite");
                assert_eq!(c.inspect_port, 4040);
                assert!(!c.no_inspect);
                assert_eq!(c.log, "pretty");
                assert!(c.subdomain.is_none());
                assert!(c.remote_port.is_none());
            }
            _ => panic!("expected Client command"),
        }

        let server_args = Cli::parse_from(["quicktunnel", "server", "--secret", "s3cr3t"]);
        match server_args.command {
            Commands::Server(s) => {
                assert_eq!(
                    s.control_bind,
                    "0.0.0.0:7000".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(s.http_bind, "0.0.0.0:80".parse::<SocketAddr>().unwrap());
                assert_eq!(s.domain, "tunnel.local");
                assert_eq!(s.tcp_port_range, "20000-29999");
                assert_eq!(s.secret, "s3cr3t");
            }
            _ => panic!("expected Server command"),
        }
    }

    #[test]
    fn test_cli_parsing_custom() {
        let args = Cli::parse_from([
            "quicktunnel",
            "client",
            "--to",
            "192.168.1.1:9000",
            "--local",
            "127.0.0.1:8080",
            "--mode",
            "tcp",
            "--subdomain",
            "api",
            "--remote-port",
            "25000",
            "--secret",
            "custom-secret",
            "--host-header",
            "custom:myhost.com",
            "--inspect-port",
            "5050",
            "--no-inspect",
            "--log",
            "json",
        ]);

        match args.command {
            Commands::Client(c) => {
                assert_eq!(c.to, "192.168.1.1:9000");
                assert_eq!(c.local, "127.0.0.1:8080");
                assert_eq!(c.mode, "tcp");
                assert_eq!(c.subdomain, Some("api".into()));
                assert_eq!(c.remote_port, Some(25000));
                assert_eq!(c.secret, "custom-secret");
                assert_eq!(c.host_header, "custom:myhost.com");
                assert_eq!(c.inspect_port, 5050);
                assert!(c.no_inspect);
                assert_eq!(c.log, "json");
            }
            _ => panic!("expected Client command"),
        }

        let srv = Cli::parse_from([
            "quicktunnel",
            "server",
            "--control-bind",
            "127.0.0.1:7777",
            "--http-bind",
            "127.0.0.1:8888",
            "--domain",
            "custom.dev",
            "--tcp-port-range",
            "30000-35000",
            "--secret",
            "srv-secret",
        ]);
        match srv.command {
            Commands::Server(s) => {
                assert_eq!(
                    s.control_bind,
                    "127.0.0.1:7777".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(s.http_bind, "127.0.0.1:8888".parse::<SocketAddr>().unwrap());
                assert_eq!(s.domain, "custom.dev");
                assert_eq!(s.tcp_port_range, "30000-35000");
                assert_eq!(s.secret, "srv-secret");
            }
            _ => panic!("expected Server command"),
        }

        let genkey = Cli::parse_from(["quicktunnel", "genkey"]);
        assert!(matches!(genkey.command, Commands::Genkey));
    }

    #[test]
    fn test_cli_parsing_env_var() {
        std::env::set_var("QT_SECRET", "env-secret-val");
        let client = Cli::parse_from(["quicktunnel", "client", "--local", "3000"]);
        match client.command {
            Commands::Client(c) => {
                assert_eq!(c.secret, "env-secret-val");
            }
            _ => panic!("expected Client command"),
        }

        let server = Cli::parse_from(["quicktunnel", "server"]);
        match server.command {
            Commands::Server(s) => {
                assert_eq!(s.secret, "env-secret-val");
            }
            _ => panic!("expected Server command"),
        }
        std::env::remove_var("QT_SECRET");
    }

    #[test]
    fn test_parse_local_target() {
        assert_eq!(
            parse_local_target("3000").unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("8080").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("127.0.0.1:8080").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("0.0.0.0:4000").unwrap(),
            "0.0.0.0:4000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("[::1]:8080").unwrap(),
            "[::1]:8080".parse::<SocketAddr>().unwrap()
        );

        // URL schemes and trailing slashes
        assert_eq!(
            parse_local_target("http://localhost:3000").unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("http://localhost:3000/").unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("https://localhost:3000/").unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("http://127.0.0.1:8080").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("http://127.0.0.1:8080/").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("https://127.0.0.1:8080/").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("http://3000").unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_local_target("http://[::1]:8080/").unwrap(),
            "[::1]:8080".parse::<SocketAddr>().unwrap()
        );

        assert!(parse_local_target("").is_err());
        assert!(parse_local_target("   ").is_err());
        assert!(parse_local_target("invalid").is_err());
        assert!(parse_local_target("99999").is_err());
        assert!(parse_local_target("localhost:invalid").is_err());
        assert!(parse_local_target("127.0.0.1").is_err());
        assert!(parse_local_target("http://").is_err());
        assert!(parse_local_target("https:///").is_err());
    }

    #[test]
    fn test_parse_host_header_rewrite() {
        assert_eq!(
            parse_host_header_rewrite("rewrite").unwrap(),
            HostHeaderRewrite::Rewrite
        );
        assert_eq!(
            parse_host_header_rewrite("REWRITE").unwrap(),
            HostHeaderRewrite::Rewrite
        );
        assert_eq!(
            parse_host_header_rewrite("preserve").unwrap(),
            HostHeaderRewrite::Preserve
        );
        assert_eq!(
            parse_host_header_rewrite("PRESERVE").unwrap(),
            HostHeaderRewrite::Preserve
        );
        assert_eq!(
            parse_host_header_rewrite("custom:example.com").unwrap(),
            HostHeaderRewrite::Custom("example.com".into())
        );
        assert_eq!(
            parse_host_header_rewrite("custom:api.domain:8080").unwrap(),
            HostHeaderRewrite::Custom("api.domain:8080".into())
        );
        assert_eq!(
            parse_host_header_rewrite("custom").unwrap(),
            HostHeaderRewrite::Custom("custom".into())
        );

        assert!(parse_host_header_rewrite("custom:").is_err());
        assert!(parse_host_header_rewrite("custom:  ").is_err());
        assert!(parse_host_header_rewrite("invalid").is_err());
        assert!(parse_host_header_rewrite("other").is_err());
    }

    #[test]
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("20000-29999").unwrap(), 20000..=29999);
        assert_eq!(parse_port_range("1000-1000").unwrap(), 1000..=1000);
        assert_eq!(parse_port_range("  80-443  ").unwrap(), 80..=443);

        assert!(parse_port_range("30000-20000").is_err());
        assert!(parse_port_range("20000").is_err());
        assert!(parse_port_range("20000-25000-30000").is_err());
        assert!(parse_port_range("abc-def").is_err());
        assert!(parse_port_range("20000-abc").is_err());
        assert!(parse_port_range("abc-20000").is_err());
        assert!(parse_port_range("0-70000").is_err());
    }

    #[test]
    fn test_request_logger_formatting() {
        let mut req = CapturedRequest::new_mock("GET", "/api/v1/users");
        req.response = Some(qt_inspector_ui::store::ResponseDetails {
            status: 200,
            status_text: "OK".into(),
            headers: vec![],
            body: Some("users list".into()),
            body_size: 10,
            body_truncated: false,
        });
        req.timing.total_ms = 42;

        // Pretty format
        let pretty = format_request_log(&req, "pretty");
        assert_eq!(pretty, "GET /api/v1/users 200 OK 42ms");

        // In flight (no response)
        let mut in_flight = CapturedRequest::new_mock("POST", "/login");
        in_flight.response = None;
        let in_flight_pretty = format_request_log(&in_flight, "pretty");
        assert_eq!(in_flight_pretty, "POST /login (in flight)");

        // JSON format
        let json_line = format_request_log(&req, "json");
        let parsed: serde_json::Value = serde_json::from_str(&json_line).unwrap();
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["path"], "/api/v1/users");
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["status_text"], "OK");
        assert_eq!(parsed["duration_ms"], 42);

        let json_in_flight = format_request_log(&in_flight, "json");
        let parsed_in_flight: serde_json::Value = serde_json::from_str(&json_in_flight).unwrap();
        assert_eq!(parsed_in_flight["method"], "POST");
        assert_eq!(parsed_in_flight["path"], "/login");
        assert!(parsed_in_flight["status"].is_null());
    }

    #[test]
    fn test_banner_formatting() {
        let target = "127.0.0.1:3000".parse::<SocketAddr>().unwrap();
        let with_inspector = format_banner(
            "Online",
            "https://test.tunnel.local",
            &target,
            Some("http://127.0.0.1:4040"),
        );
        assert!(with_inspector.contains("QuickTunnel Client"));
        assert!(with_inspector.contains("Status:       Online"));
        assert!(with_inspector.contains("https://test.tunnel.local -> 127.0.0.1:3000"));
        assert!(with_inspector.contains("Web Inspector: http://127.0.0.1:4040"));

        let without_inspector = format_banner("Online", "tunnel.local:20005", &target, None);
        assert!(without_inspector.contains("Status:       Online"));
        assert!(without_inspector.contains("tunnel.local:20005 -> 127.0.0.1:3000"));
        assert!(!without_inspector.contains("Web Inspector:"));
    }

    #[tokio::test]
    async fn test_run_server_and_client_e2e_with_inspector() {
        // 1. Mock local backend HTTP server
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            loop {
                if let Ok((mut socket, _)) = local_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let n = socket.read(&mut buf).await.unwrap();
                        let req_text = String::from_utf8_lossy(&buf[..n]);
                        assert!(req_text.contains("GET /api/hello"));

                        let body = "Hello From Mock Backend!";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        socket.write_all(resp.as_bytes()).await.unwrap();
                        socket.flush().await.unwrap();
                    });
                }
            }
        });

        // 2. Setup server on ephemeral ports
        let ctrl_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = ctrl_probe.local_addr().unwrap();
        drop(ctrl_probe);

        let http_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_probe.local_addr().unwrap();
        drop(http_probe);

        let inspect_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inspect_addr = inspect_probe.local_addr().unwrap();
        drop(inspect_probe);

        let server_shutdown = Arc::new(tokio::sync::Notify::new());
        let server_shutdown_clone = server_shutdown.clone();

        let server_args = ServerArgs {
            control_bind: ctrl_addr,
            http_bind: http_addr,
            domain: "tunnel.local".into(),
            tcp_port_range: "21000-21010".into(),
            secret: "e2e-token-secret".into(),
        };

        let server_task = tokio::spawn(async move {
            run_server_with_shutdown(server_args, server_shutdown_clone.notified())
                .await
                .unwrap();
        });

        // Let server start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Setup client with inspector
        let client_shutdown = Arc::new(tokio::sync::Notify::new());
        let client_shutdown_clone = client_shutdown.clone();

        let client_args = ClientArgs {
            to: ctrl_addr.to_string(),
            local: local_addr.to_string(),
            mode: "http".into(),
            subdomain: Some("e2e-sub".into()),
            remote_port: None,
            secret: "e2e-token-secret".into(),
            host_header: "rewrite".into(),
            inspect_port: inspect_addr.port(),
            no_inspect: false,
            log: "json".into(),
        };

        let client_task = tokio::spawn(async move {
            run_client_with_shutdown(client_args, client_shutdown_clone.notified())
                .await
                .unwrap();
        });

        // Wait for connection to establish and inspector to bind
        let mut connected = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            if tokio::net::TcpStream::connect(inspect_addr).await.is_ok() {
                connected = true;
                break;
            }
        }
        assert!(connected, "Client and inspector failed to start in time");

        // 4. Send visitor request through server HTTP proxy
        let mut visitor = tokio::net::TcpStream::connect(http_addr).await.unwrap();
        let req_msg =
            b"GET /api/hello HTTP/1.1\r\nHost: e2e-sub.tunnel.local\r\nConnection: close\r\n\r\n";
        visitor.write_all(req_msg).await.unwrap();
        visitor.flush().await.unwrap();

        let mut resp_buf = Vec::new();
        visitor.read_to_end(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("Hello From Mock Backend!"));

        // 5. Query Web Inspector API to verify request capture
        let mut inspect_client = tokio::net::TcpStream::connect(inspect_addr).await.unwrap();
        inspect_client
            .write_all(
                b"GET /api/requests HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        inspect_client.flush().await.unwrap();

        let mut inspect_resp = Vec::new();
        inspect_client.read_to_end(&mut inspect_resp).await.unwrap();
        let inspect_str = String::from_utf8_lossy(&inspect_resp);
        assert!(inspect_str.contains("200 OK"));
        assert!(inspect_str.contains("/api/hello"));

        // 6. Graceful shutdown
        client_shutdown.notify_waiters();
        server_shutdown.notify_waiters();

        let _ = tokio::time::timeout(Duration::from_secs(3), client_task)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .unwrap();
        backend_task.abort();
    }

    #[tokio::test]
    async fn test_run_server_and_client_e2e_tcp_mode() {
        // 1. Mock local backend TCP echo server
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = local_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // 2. Setup server on ephemeral ports
        let ctrl_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = ctrl_probe.local_addr().unwrap();
        drop(ctrl_probe);

        let http_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_probe.local_addr().unwrap();
        drop(http_probe);

        let tcp_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_probe.local_addr().unwrap().port();
        drop(tcp_probe);

        let server_shutdown = Arc::new(tokio::sync::Notify::new());
        let server_shutdown_clone = server_shutdown.clone();

        let server_args = ServerArgs {
            control_bind: ctrl_addr,
            http_bind: http_addr,
            domain: "tunnel.local".into(),
            tcp_port_range: format!("{}-{}", tcp_port, tcp_port + 2),
            secret: "tcp-token-secret".into(),
        };

        let server_task = tokio::spawn(async move {
            run_server_with_shutdown(server_args, server_shutdown_clone.notified())
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Setup client in TCP mode
        let client_shutdown = Arc::new(tokio::sync::Notify::new());
        let client_shutdown_clone = client_shutdown.clone();

        let client_args = ClientArgs {
            to: ctrl_addr.to_string(),
            local: local_addr.to_string(),
            mode: "tcp".into(),
            subdomain: None,
            remote_port: Some(tcp_port),
            secret: "tcp-token-secret".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };

        let client_task = tokio::spawn(async move {
            run_client_with_shutdown(client_args, client_shutdown_clone.notified())
                .await
                .unwrap();
        });

        // Wait for client to connect to server
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 4. Graceful shutdown
        client_shutdown.notify_waiters();
        server_shutdown.notify_waiters();

        let _ = tokio::time::timeout(Duration::from_secs(3), client_task)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .unwrap();
        backend_task.abort();
    }

    #[tokio::test]
    async fn test_run_server_and_client_e2e_http_no_inspect_and_pretty() {
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            if let Ok((mut socket, _)) = local_listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                let _ = socket.write_all(resp).await;
            }
        });

        let ctrl_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = ctrl_probe.local_addr().unwrap();
        drop(ctrl_probe);

        let http_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_probe.local_addr().unwrap();
        drop(http_probe);

        let server_shutdown = Arc::new(tokio::sync::Notify::new());
        let server_shutdown_clone = server_shutdown.clone();

        let server_args = ServerArgs {
            control_bind: ctrl_addr,
            http_bind: http_addr,
            domain: "tunnel.local".into(),
            tcp_port_range: "23000-23010".into(),
            secret: "no-inspect-sec".into(),
        };

        let server_task = tokio::spawn(async move {
            let _ = run_server_with_shutdown(server_args, server_shutdown_clone.notified()).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_shutdown = Arc::new(tokio::sync::Notify::new());
        let client_shutdown_clone = client_shutdown.clone();

        let client_args = ClientArgs {
            to: ctrl_addr.to_string(),
            local: local_addr.to_string(),
            mode: "http".into(),
            subdomain: Some("no-inspect-sub".into()),
            remote_port: None,
            secret: "no-inspect-sec".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };

        let client_task = tokio::spawn(async move {
            let _ = run_client_with_shutdown(client_args, client_shutdown_clone.notified()).await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut visitor = tokio::net::TcpStream::connect(http_addr).await.unwrap();
        visitor
            .write_all(
                b"GET / HTTP/1.1\r\nHost: no-inspect-sub.tunnel.local\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut resp_buf = Vec::new();
        visitor.read_to_end(&mut resp_buf).await.unwrap();
        assert!(String::from_utf8_lossy(&resp_buf).contains("200 OK"));

        client_shutdown.notify_waiters();
        server_shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(3), client_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task).await;
        backend_task.abort();
    }

    #[tokio::test]
    async fn test_run_server_invalid_port_range_returns_error() {
        let server_args = ServerArgs {
            control_bind: "127.0.0.1:7000".parse().unwrap(),
            http_bind: "127.0.0.1:80".parse().unwrap(),
            domain: "tunnel.local".into(),
            tcp_port_range: "invalid-range".into(),
            secret: "sec".into(),
        };
        let res = run_server_with_shutdown(server_args, async {}).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Invalid port range"));
    }

    #[tokio::test]
    async fn test_run_client_invalid_target_returns_error() {
        let client_args = ClientArgs {
            to: "127.0.0.1:7000".into(),
            local: "invalid-target".into(),
            mode: "http".into(),
            subdomain: None,
            remote_port: None,
            secret: "sec".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };
        let res = run_client_with_shutdown(client_args, async {}).await;
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Invalid local target"));
    }

    #[tokio::test]
    async fn test_run_client_invalid_mode_returns_error() {
        let client_args = ClientArgs {
            to: "127.0.0.1:7000".into(),
            local: "3000".into(),
            mode: "ftp".into(),
            subdomain: None,
            remote_port: None,
            secret: "sec".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };
        let res = run_client_with_shutdown(client_args, async {}).await;
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Invalid tunnel mode 'ftp'"));
    }

    #[tokio::test]
    async fn test_run_client_invalid_server_addr_returns_error() {
        let client_args = ClientArgs {
            to: "invalid-server-addr:999999".into(),
            local: "3000".into(),
            mode: "http".into(),
            subdomain: None,
            remote_port: None,
            secret: "sec".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };
        let res = run_client_with_shutdown(client_args, async {}).await;
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Invalid server address"));
    }

    #[tokio::test]
    async fn test_run_client_resolves_localhost_hostname() {
        let client_args = ClientArgs {
            to: "localhost:7999".into(),
            local: "3000".into(),
            mode: "http".into(),
            subdomain: None,
            remote_port: None,
            secret: "sec".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };
        // This will attempt to connect to localhost:7999 (which isn't running),
        // but hostname resolution succeeds and it enters the client reconnect loop.
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(async move {
            run_client_with_shutdown(client_args, shutdown_clone.notified()).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn test_run_server_and_client_spawns() {
        let s_args = ServerArgs {
            control_bind: "127.0.0.1:0".parse().unwrap(),
            http_bind: "127.0.0.1:0".parse().unwrap(),
            domain: "tunnel.local".into(),
            tcp_port_range: "22000-22010".into(),
            secret: "sec".into(),
        };
        let s_handle = tokio::spawn(async move {
            let _ = run_server(s_args).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        s_handle.abort();

        let c_args = ClientArgs {
            to: "127.0.0.1:7000".into(),
            local: "3000".into(),
            mode: "http".into(),
            subdomain: None,
            remote_port: None,
            secret: "sec".into(),
            host_header: "rewrite".into(),
            inspect_port: 4040,
            no_inspect: true,
            log: "pretty".into(),
        };
        let c_handle = tokio::spawn(async move {
            let _ = run_client(c_args).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        c_handle.abort();
    }

    #[tokio::test]
    async fn test_wait_for_shutdown_signal_registers_cleanly() {
        let fut = wait_for_shutdown_signal();
        let timeout_res = tokio::time::timeout(Duration::from_millis(50), fut).await;
        assert!(
            timeout_res.is_err(),
            "expected timeout while waiting for external signal"
        );
    }
}
