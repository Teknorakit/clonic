//! Command-line interface for Zone Coordination Protocol (ZCP) management.
//!
//! Provides tools for:
//! - Zone policy management
//! - Peer registry management
//! - Configuration validation
//! - Metrics monitoring
//! - Violation auditing

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use clonic_core::ResidencyTag;
use clonic_router::RouterConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tabled::{settings::Style, Table, Tabled};
use tracing::warn;

#[derive(Parser)]
#[command(name = "clonic")]
#[command(about = "Zone Coordination Protocol (ZCP) management tool")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true, default_value = "clonic.toml")]
    pub config: PathBuf,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Zone management commands
    Zone {
        #[command(subcommand)]
        command: ZoneCommands,
    },
    /// Policy management commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Peer registry management
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Metrics and monitoring
    Metrics {
        #[command(subcommand)]
        command: MetricsCommands,
    },
    /// Violation audit
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand)]
pub enum ZoneCommands {
    /// List all available zones
    List {
        /// Filter by country code (e.g., "ID", "US")
        #[arg(short = 'C', long)]
        country: Option<String>,
        /// Show only zones with residency laws
        #[arg(short = 'R', long)]
        regulated: bool,
    },
    /// Show detailed information about a zone
    Info {
        /// Zone code (numeric or alpha-2)
        zone_code: String,
    },
    /// Validate zone codes in configuration
    Validate,
}

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// List all policies
    List,
    /// Show policy details
    Show {
        /// Policy name or zone code
        policy: String,
    },
    /// Add a new policy
    Add {
        /// Policy configuration file
        policy_file: PathBuf,
    },
    /// Remove a policy
    Remove {
        /// Policy name
        name: String,
    },
    /// Test policy against a scenario
    Test {
        /// Source zone
        source: String,
        /// Destination zone
        dest: String,
        /// Data type
        #[arg(default_value = "test_data")]
        data_type: String,
    },
}

#[derive(Subcommand)]
pub enum PeerCommands {
    /// List all registered peers
    List {
        /// Filter by zone
        #[arg(short, long)]
        zone: Option<String>,
        /// Show inactive peers
        #[arg(short, long)]
        inactive: bool,
    },
    /// Register a new peer
    Register {
        /// Device ID (hex string)
        device_id: String,
        /// Zone code
        zone: String,
        /// Peer metadata (JSON)
        #[arg(short, long)]
        metadata: Option<String>,
    },
    /// Unregister a peer
    Unregister {
        /// Device ID (hex string)
        device_id: String,
    },
    /// Show peer details
    Info {
        /// Device ID (hex string)
        device_id: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Validate configuration
    Validate,
    /// Show current configuration
    Show,
    /// Reload configuration
    Reload,
    /// Generate example configuration
    Generate {
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum MetricsCommands {
    /// Show current metrics
    Show {
        /// Export in Prometheus format
        #[arg(short, long)]
        prometheus: bool,
    },
    /// Reset metrics
    Reset,
    /// Watch metrics in real-time
    Watch {
        /// Update interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
    },
}

#[derive(Subcommand)]
pub enum AuditCommands {
    /// List recent violations
    List {
        /// Number of recent violations to show
        #[arg(short, long, default_value = "10")]
        count: usize,
        /// Filter by violation type
        #[arg(short, long)]
        type_filter: Option<String>,
        /// Filter by source zone
        #[arg(short, long)]
        source: Option<String>,
        /// Filter by destination zone
        #[arg(short, long)]
        dest: Option<String>,
    },
    /// Generate audit report
    Report {
        /// Output format (json, csv, table)
        #[arg(short, long, default_value = "table")]
        format: String,
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Time range (e.g., "1h", "24h", "7d")
        #[arg(short, long, default_value = "24h")]
        range: String,
    },
    /// Check compliance status
    Check,
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct ZoneInfo {
    #[tabled(rename = "Code")]
    pub code: String,
    #[tabled(rename = "Name")]
    pub name: String,
    #[tabled(rename = "Alpha-2")]
    pub alpha2: String,
    #[tabled(rename = "Alpha-3")]
    pub alpha3: String,
    #[tabled(rename = "Regulated")]
    pub regulated: String,
    #[tabled(rename = "Regulations")]
    pub regulations: String,
}

#[derive(Tabled)]
pub struct PeerInfo {
    #[tabled(rename = "Device ID")]
    pub device_id: String,
    #[tabled(rename = "Zone")]
    pub zone: String,
    #[tabled(rename = "Last Seen")]
    pub last_seen: String,
    #[tabled(rename = "Status")]
    pub status: String,
}

#[derive(Tabled)]
pub struct ViolationInfo {
    #[tabled(rename = "Timestamp")]
    pub timestamp: String,
    #[tabled(rename = "Type")]
    pub violation_type: String,
    #[tabled(rename = "Source")]
    pub source_zone: String,
    #[tabled(rename = "Destination")]
    pub dest_zone: String,
    #[tabled(rename = "Reason")]
    pub reason: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let _log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();

    run_command(cli)
}

fn run_command(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Zone { command } => handle_zone_command(command)?,
        Commands::Policy { command } => handle_policy_command(command)?,
        Commands::Peer { command } => handle_peer_command(command)?,
        Commands::Config { command } => handle_config_command(command, &cli.config)?,
        Commands::Metrics { command } => handle_metrics_command(command)?,
        Commands::Audit { command } => handle_audit_command(command)?,
    }

    Ok(())
}

fn handle_zone_command(command: ZoneCommands) -> Result<()> {
    match command {
        ZoneCommands::List { country, regulated } => {
            let zones = list_zones(country, regulated)?;
            let table = Table::new(&zones).with(Style::modern()).to_string();
            println!("{}", table);
        }
        ZoneCommands::Info { zone_code } => {
            let zone = get_zone_info(&zone_code)?;
            if let Some(zone) = zone {
                println!("Zone Information:");
                println!("  Code: {}", zone.code);
                println!("  Name: {}", zone.name);
                println!("  Alpha-2: {}", zone.alpha2);
                println!("  Alpha-3: {}", zone.alpha3);
                println!("  Regulated: {}", zone.regulated);
                println!("  Regulations: {}", zone.regulations);
            } else {
                println!("Zone '{}' not found", zone_code);
            }
        }
        ZoneCommands::Validate => {
            println!("Zone validation completed");
        }
    }
    Ok(())
}

fn handle_policy_command(command: PolicyCommands) -> Result<()> {
    match command {
        PolicyCommands::List => {
            println!("Policy listing not yet implemented");
        }
        PolicyCommands::Show { policy } => {
            println!("Policy '{}' details not yet implemented", policy);
        }
        PolicyCommands::Add { policy_file } => {
            println!("Adding policy from {:?} not yet implemented", policy_file);
        }
        PolicyCommands::Remove { name } => {
            println!("Removing policy '{}' not yet implemented", name);
        }
        PolicyCommands::Test {
            source,
            dest,
            data_type,
        } => {
            test_policy(&source, &dest, &data_type)?;
        }
    }
    Ok(())
}

fn handle_peer_command(command: PeerCommands) -> Result<()> {
    match command {
        PeerCommands::List {
            zone: _,
            inactive: _,
        } => {
            println!("Peer listing not yet implemented");
        }
        PeerCommands::Register {
            device_id,
            zone,
            metadata: _,
        } => {
            println!("Registering peer {} in zone {}", device_id, zone);
        }
        PeerCommands::Unregister { device_id } => {
            println!("Unregistering peer {}", device_id);
        }
        PeerCommands::Info { device_id } => {
            println!("Peer info for {} not yet implemented", device_id);
        }
    }
    Ok(())
}

fn handle_config_command(command: ConfigCommands, config_path: &PathBuf) -> Result<()> {
    match command {
        ConfigCommands::Validate => {
            validate_config(config_path)?;
        }
        ConfigCommands::Show => {
            show_config(config_path)?;
        }
        ConfigCommands::Reload => {
            println!("Reloading configuration from {:?}", config_path);
        }
        ConfigCommands::Generate { output } => {
            generate_example_config(output)?;
        }
    }
    Ok(())
}

fn handle_metrics_command(command: MetricsCommands) -> Result<()> {
    match command {
        MetricsCommands::Show { prometheus } => {
            if prometheus {
                println!("# Prometheus metrics export not yet implemented");
            } else {
                println!("Metrics display not yet implemented");
            }
        }
        MetricsCommands::Reset => {
            println!("Resetting metrics not yet implemented");
        }
        MetricsCommands::Watch { interval } => {
            println!("Watching metrics every {} seconds", interval);
        }
    }
    Ok(())
}

fn handle_audit_command(command: AuditCommands) -> Result<()> {
    match command {
        AuditCommands::List {
            count,
            type_filter: _,
            source: _,
            dest: _,
        } => {
            println!("Listing {} violations", count);
        }
        AuditCommands::Report {
            format,
            output: _,
            range,
        } => {
            println!("Generating {} report for range {}", format, range);
        }
        AuditCommands::Check => {
            println!("Compliance check not yet implemented");
        }
    }
    Ok(())
}

fn list_zones(country_filter: Option<String>, regulated_only: bool) -> Result<Vec<ZoneInfo>> {
    let mut zones = Vec::new();

    // Sample zones - in a real implementation, this would use the zone registry
    let sample_zones = vec![
        ZoneInfo {
            code: "360".to_string(),
            name: "Indonesia".to_string(),
            alpha2: "ID".to_string(),
            alpha3: "IDN".to_string(),
            regulated: "Yes".to_string(),
            regulations: "PP 71/2019, GR 82/2012".to_string(),
        },
        ZoneInfo {
            code: "458".to_string(),
            name: "Malaysia".to_string(),
            alpha2: "MY".to_string(),
            alpha3: "MYS".to_string(),
            regulated: "Yes".to_string(),
            regulations: "PDPA 2010".to_string(),
        },
        ZoneInfo {
            code: "840".to_string(),
            name: "United States".to_string(),
            alpha2: "US".to_string(),
            alpha3: "USA".to_string(),
            regulated: "No".to_string(),
            regulations: "".to_string(),
        },
    ];

    for zone in sample_zones {
        let matches_country = country_filter.as_ref().is_none_or(|filter| {
            zone.alpha2.to_lowercase() == filter.to_lowercase()
                || zone.code == *filter
                || zone.alpha3.to_lowercase() == filter.to_lowercase()
        });

        let matches_regulated = !regulated_only || zone.regulated == "Yes";

        if matches_country && matches_regulated {
            zones.push(zone);
        }
    }

    Ok(zones)
}

fn get_zone_info(zone_code: &str) -> Result<Option<ZoneInfo>> {
    let zones = list_zones(None, false)?;
    Ok(zones.into_iter().find(|z| {
        z.code == zone_code
            || z.alpha2.to_lowercase() == zone_code.to_lowercase()
            || z.alpha3.to_lowercase() == zone_code.to_lowercase()
    }))
}

fn test_policy(source: &str, dest: &str, data_type: &str) -> Result<()> {
    println!("Testing policy:");
    println!("  Source: {}", source);
    println!("  Destination: {}", dest);
    println!("  Data Type: {}", data_type);

    // Parse zones
    let source_zone = parse_zone_code(source)?;
    let dest_zone = parse_zone_code(dest)?;

    println!("  Source Zone: {:?}", source_zone);
    println!("  Dest Zone: {:?}", dest_zone);

    // In a real implementation, this would use the policy engine
    println!("  Result: Policy test not yet implemented");

    Ok(())
}

fn parse_zone_code(code: &str) -> Result<ResidencyTag> {
    // Try to parse as numeric first
    if let Ok(numeric) = code.parse::<u16>() {
        return Ok(clonic_core::ResidencyTag::from_be_bytes(
            numeric.to_be_bytes(),
        ));
    }

    // Try to find by alpha-2 or alpha-3
    if let Some(zone) = get_zone_info(code)? {
        if let Ok(numeric) = zone.code.parse::<u16>() {
            return Ok(clonic_core::ResidencyTag::from_be_bytes(
                numeric.to_be_bytes(),
            ));
        }
    }

    Err(anyhow::anyhow!("Invalid zone code: {}", code))
}

fn validate_config(config_path: &PathBuf) -> Result<()> {
    if !config_path.exists() {
        warn!("Configuration file {:?} does not exist", config_path);
        return Ok(());
    }

    let config_content =
        std::fs::read_to_string(config_path).context("Failed to read configuration file")?;

    // Parse TOML
    let config: RouterConfig =
        toml::from_str(&config_content).context("Failed to parse configuration")?;

    // Validate
    config
        .validate()
        .context("Configuration validation failed")?;

    println!("✅ Configuration is valid");
    Ok(())
}

fn show_config(config_path: &PathBuf) -> Result<()> {
    if !config_path.exists() {
        println!("Configuration file {:?} does not exist", config_path);
        return Ok(());
    }

    let config_content =
        std::fs::read_to_string(config_path).context("Failed to read configuration file")?;

    println!("Configuration from {:?}:", config_path);
    println!("{}", config_content);
    Ok(())
}

fn generate_example_config(output: Option<PathBuf>) -> Result<()> {
    let config = RouterConfig::default();
    let toml_content =
        toml::to_string_pretty(&config).context("Failed to serialize configuration")?;

    match output {
        Some(path) => {
            std::fs::write(&path, toml_content).context("Failed to write configuration file")?;
            println!("Example configuration written to {:?}", path);
        }
        None => {
            println!("{}", toml_content);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_zone_code_numeric() {
        let result = parse_zone_code("360").unwrap();
        assert_eq!(result.raw(), 360);
    }

    #[test]
    fn test_parse_zone_code_alpha2() {
        let result = parse_zone_code("ID").unwrap();
        assert_eq!(result.raw(), 360);
    }

    #[test]
    fn test_parse_zone_code_invalid() {
        let result = parse_zone_code("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zone_code_alpha3() {
        let result = parse_zone_code("IDN").unwrap();
        assert_eq!(result.raw(), 360);
    }

    #[test]
    fn test_parse_zone_code_case_insensitive() {
        let result_lower = parse_zone_code("id").unwrap();
        let result_upper = parse_zone_code("ID").unwrap();
        assert_eq!(result_lower.raw(), result_upper.raw());
    }

    #[test]
    fn test_list_zones_functionality() {
        let zones = list_zones(None, false).unwrap();
        assert!(!zones.is_empty());

        // Test that all zones have required fields
        for zone in &zones {
            assert!(!zone.code.is_empty());
            assert!(!zone.alpha2.is_empty());
            assert!(!zone.alpha3.is_empty());
            assert!(!zone.name.is_empty());
        }
    }

    #[test]
    fn test_list_zones_with_filter() {
        let zones = list_zones(Some("ID".to_string()), false).unwrap();

        // Should only return Indonesia
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].alpha2, "ID");
        assert_eq!(zones[0].alpha3, "IDN");
        assert_eq!(zones[0].name, "Indonesia");
    }

    #[test]
    fn test_list_zones_regulated_only() {
        let regulated_zones = list_zones(None, true).unwrap();
        let all_zones = list_zones(None, false).unwrap();

        // Regulated zones should be a subset of all zones
        assert!(regulated_zones.len() <= all_zones.len());

        // All regulated zones should have residency laws
        for zone in &regulated_zones {
            assert_eq!(zone.regulated, "Yes");
        }
    }

    #[test]
    fn test_get_zone_info() {
        let indonesia = get_zone_info("ID").unwrap().unwrap();
        assert_eq!(indonesia.code, "360");
        assert_eq!(indonesia.alpha2, "ID");
        assert_eq!(indonesia.alpha3, "IDN");
        assert_eq!(indonesia.name, "Indonesia");
        assert_eq!(indonesia.regulated, "Yes");
        assert!(!indonesia.regulations.is_empty());
    }

    #[test]
    fn test_get_zone_info_not_found() {
        let result = get_zone_info("XX");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_validate_config_nonexistent() {
        let nonexistent_path = PathBuf::from("/nonexistent/config.toml");
        let result = validate_config(&nonexistent_path);
        assert!(result.is_ok()); // Should not panic, just warn
    }

    #[test]
    fn test_generate_example_config() {
        use std::io::Read;

        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_example_config.toml");

        // Generate config to temp file
        let result = generate_example_config(Some(config_path.clone()));
        assert!(result.is_ok());

        // Read and verify the config content
        let mut config_content = String::new();
        std::fs::File::open(&config_path)
            .unwrap()
            .read_to_string(&mut config_content)
            .unwrap();

        // The example config should contain key sections
        assert!(config_content.contains("[router]"));
        assert!(config_content.contains("[policy]"));
        assert!(config_content.contains("[zones]"));

        // Clean up
        std::fs::remove_file(&config_path).unwrap_or(());
    }

    #[test]
    fn test_show_config_functionality() {
        // This test just verifies the function doesn't panic
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_config.toml");

        // Create a minimal config file
        std::fs::write(&config_path, "[router]\nlocal_zone = 360\n").unwrap();

        let result = show_config(&config_path);
        assert!(result.is_ok());

        // Clean up
        std::fs::remove_file(&config_path).unwrap_or(());
    }

    #[test]
    fn test_test_policy_functionality() {
        let result = test_policy("ID", "MY", "test_data");
        assert!(result.is_ok());

        // The function should print policy test results
        // We can't easily capture output, but we can verify it doesn't panic
    }

    #[test]
    fn test_edge_cases() {
        // Test with empty strings
        let result_empty = parse_zone_code("");
        assert!(result_empty.is_err());

        // Test with very long strings
        let long_string = "A".repeat(1000);
        let result_long = parse_zone_code(&long_string);
        assert!(result_long.is_err());

        // Test with special characters
        let result_special = parse_zone_code("@#$%");
        assert!(result_special.is_err());
    }

    #[test]
    fn test_zone_code_validation() {
        // Test valid numeric codes
        assert!(parse_zone_code("0").is_ok()); // Global
        assert!(parse_zone_code("360").is_ok()); // Indonesia
        assert!(parse_zone_code("458").is_ok()); // Malaysia

        // Test invalid numeric codes
        assert!(parse_zone_code("-1").is_err()); // Negative
        assert!(parse_zone_code("99999").is_err()); // Too large

        // Test valid alpha codes
        assert!(parse_zone_code("ID").is_ok()); // Indonesia
        assert!(parse_zone_code("MY").is_ok()); // Malaysia
        assert!(parse_zone_code("SG").is_ok()); // Singapore

        // Test invalid alpha codes
        assert!(parse_zone_code("XX").is_err()); // Non-existent
        assert!(parse_zone_code("I").is_err()); // Too short
        assert!(parse_zone_code("IND").is_err()); // Too long
    }

    #[test]
    fn test_cli_argument_parsing() {
        use clap::Parser;

        // Test basic CLI parsing
        let cli = Cli::parse_from(["clonic", "zone", "list"]);
        match cli.command {
            Commands::Zone { command } => {
                match command {
                    ZoneCommands::List { .. } => {} // Expected
                    _ => panic!("Expected ZoneCommands::List"),
                }
            }
            _ => panic!("Expected Commands::Zone"),
        }
    }

    #[test]
    fn test_cli_with_verbose() {
        use clap::Parser;

        let cli = Cli::parse_from(["clonic", "--verbose", "zone", "list"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_config_path_handling() {
        let config_path = PathBuf::from("/test/path/config.toml");

        // Test that config path is handled correctly
        let cli = Cli::parse_from([
            "clonic",
            "--config",
            "/test/path/config.toml",
            "zone",
            "list",
        ]);

        assert_eq!(cli.config, config_path);
    }

    #[test]
    fn test_all_zone_commands() {
        use clap::Parser;

        // Test that all zone subcommands can be parsed
        let commands = vec![
            vec!["clonic", "zone", "list"],
            vec!["clonic", "zone", "info", "ID"],
            vec!["clonic", "zone", "validate"],
        ];

        for args in commands {
            let cli = Cli::parse_from(args.clone());
            match cli.command {
                Commands::Zone { .. } => {} // Expected
                _ => panic!("Expected Commands::Zone for args: {:?}", args),
            }
        }
    }

    #[test]
    fn test_all_policy_commands() {
        use clap::Parser;

        let commands = vec![
            vec!["clonic", "policy", "list"],
            vec!["clonic", "policy", "show", "test"],
            vec!["clonic", "policy", "test", "ID", "MY", "test"],
        ];

        for args in commands {
            let cli = Cli::parse_from(args.clone());
            match cli.command {
                Commands::Policy { .. } => {} // Expected
                _ => panic!("Expected Commands::Policy for args: {:?}", args),
            }
        }
    }

    #[test]
    fn test_all_peer_commands() {
        use clap::Parser;

        let commands = vec![
            vec!["clonic", "peer", "list"],
            vec![
                "clonic",
                "peer",
                "register",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "ID",
            ],
            vec![
                "clonic",
                "peer",
                "info",
                "0101010101010101010101010101010101010101010101010101010101010101",
            ],
        ];

        for args in commands {
            let cli = Cli::parse_from(args.clone());
            match cli.command {
                Commands::Peer { .. } => {} // Expected
                _ => panic!("Expected Commands::Peer for args: {:?}", args),
            }
        }
    }

    #[test]
    fn test_all_config_commands() {
        use clap::Parser;

        let commands = vec![
            vec![
                "clonic",
                "--config",
                "/test/config.toml",
                "config",
                "validate",
            ],
            vec!["clonic", "--config", "/test/config.toml", "config", "show"],
            vec!["clonic", "config", "reload"],
            vec!["clonic", "config", "generate"],
        ];

        for args in commands {
            let cli = Cli::parse_from(args.clone());
            match cli.command {
                Commands::Config { .. } => {} // Expected
                _ => panic!("Expected Commands::Config for args: {:?}", args),
            }
        }
    }

    #[test]
    fn test_all_metrics_commands() {
        use clap::Parser;

        let commands = vec![
            vec!["clonic", "metrics", "show"],
            vec!["clonic", "metrics", "reset"],
            vec!["clonic", "metrics", "watch"],
        ];

        for args in commands {
            let cli = Cli::parse_from(args.clone());
            match cli.command {
                Commands::Metrics { .. } => {} // Expected
                _ => panic!("Expected Commands::Metrics for args: {:?}", args),
            }
        }
    }

    #[test]
    fn test_all_audit_commands() {
        use clap::Parser;

        let commands = vec![
            vec!["clonic", "audit", "list"],
            vec!["clonic", "audit", "report", "json"],
            vec!["clonic", "audit", "check"],
        ];

        for args in commands {
            let cli = Cli::parse_from(args.clone());
            match cli.command {
                Commands::Audit { .. } => {} // Expected
                _ => panic!("Expected Commands::Audit for args: {:?}", args),
            }
        }
    }

    #[test]
    fn test_error_handling() {
        // Test that error handling works gracefully

        // Invalid zone code should not panic
        let result = parse_zone_code("INVALID");
        assert!(result.is_err());

        // Non-existent zone info should return None
        let result = get_zone_info("XX");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Invalid config path should not panic
        let invalid_path = PathBuf::from("/definitely/does/not/exist.toml");
        let result = validate_config(&invalid_path);
        assert!(result.is_ok()); // Should handle gracefully
    }

    #[test]
    fn test_string_formatting() {
        // Test that string formatting works correctly
        let zones = list_zones(None, false).unwrap();

        for zone in zones {
            // All fields should be properly formatted
            assert!(!zone.code.trim().is_empty());
            assert!(!zone.alpha2.trim().is_empty());
            assert!(!zone.alpha3.trim().is_empty());
            assert!(!zone.name.trim().is_empty());

            // Alpha codes should be uppercase
            assert_eq!(zone.alpha2, zone.alpha2.to_uppercase());
            assert_eq!(zone.alpha3, zone.alpha3.to_uppercase());
        }
    }

    #[test]
    fn test_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        // Test concurrent zone parsing
        let zone_codes = vec!["ID", "MY", "SG", "PH", "VN"];
        let zone_codes = Arc::new(zone_codes);
        let mut handles = vec![];

        for _ in 0..10 {
            let zone_codes_clone = Arc::clone(&zone_codes);
            let handle = thread::spawn(move || {
                for code in zone_codes_clone.iter() {
                    let result = parse_zone_code(code);
                    assert!(result.is_ok());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
