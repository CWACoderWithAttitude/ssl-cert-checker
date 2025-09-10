/*--------------------------------------------------------------------------------------------------------------
 * Copyright (c) Volker Benders. All rights reserved.
 * Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
 *-------------------------------------------------------------------------------------------------------------*/

extern crate openssl;
extern crate chrono;
use chrono::Local;
use openssl::ssl::{SslConnector, SslMethod};
use openssl::x509::X509;
use std::fs::File;
use std::io::{Write, BufRead, BufReader};
use std::net::TcpStream;

fn main() {
    let hosts = match read_hosts_from_file("hosts.txt") {
        Ok(hosts) => hosts,
        Err(e) => {
            eprintln!("Warning: Could not read hosts.txt ({}), using default hosts", e);
            get_default_hosts()
        }
    };
    
    let host_refs: Vec<&str> = hosts.iter().map(|s| s.as_str()).collect();
    println!("host_refs, {}!", host_refs.join(", "));
    match check_certs_and_write_to_file(&host_refs, "certificates") {
        Ok(_) => println!("Certificate data written to certificates.csv"),
        Err(e) => eprintln!("Error processing certificates: {}", e),
}
}

pub fn get_default_hosts() -> Vec<String> {
    vec![
        "www.apple.com".to_string(),
        "www.apple.de".to_string(),
        "www.heise.de".to_string(),
        "www.github.com".to_string(),
        "www.gitlab.com".to_string(),
        "github.com".to_string(),
        "siemens.de".to_string(),
        "cwacoderwithattitiude.github.io".to_string(),
        "primevideo.com".to_string()
    ]
}

pub fn read_hosts_from_file(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut hosts = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            hosts.push(trimmed.to_string());
        }
    }

    Ok(hosts)
}
pub fn check_certs_and_write_to_file(hosts: &[&str], output_file_prefix: &str) -> std::io::Result<()> {
    // Generate timestamp string
    let timestamp = Local::now().format("%Y%m%d-%H%M").to_string();
    let output_file = format!("{}_{}.csv", timestamp, output_file_prefix);

    let mut file = File::create(&output_file)?;
    writeln!(file, "Host;Not Before;Not After;Common Name;SANs")?;

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE); // Allow self-signed and expired certs
    let connector = builder.build();

    for &host in hosts {
        let (hostname, port) = split_host_port(host);
        let addr = format!("{}:{}", hostname, port);
        match TcpStream::connect(&addr) {
            Ok(stream) => {
                match connector.connect(hostname, stream) {
                    Ok(ssl_stream) => {
                        let cert = ssl_stream.ssl().peer_certificate();
                        if let Some(cert) = cert {
                            let not_before = get_cert_not_before(&cert);
                            let not_after = get_cert_not_after(&cert);
                            let common_name = get_cert_common_name(&cert);
                            let sans = get_cert_sans(&cert);
                            writeln!(file, "{};{};{};{};{}", host, not_before, not_after, common_name, sans)?;
                        } else {
                            writeln!(file, "{};NO CERT;NO CERT;NO CERT;NO CERT", host)?;
                        }
                    }
                    Err(e) => {
                        eprintln!("SSL error for {}: {}", host, e);
                        writeln!(file, "{};SSL ERROR;SSL ERROR;SSL ERROR;SSL ERROR", host)?;
                    }
                }
            }
            Err(e) => {
                eprintln!("TCP error for {}: {}", host, e);
                writeln!(file, "{};-;-;-;-", host)?;
            }
        }
    }

    println!("Certificate data written to {}", output_file);
    Ok(())
}

fn split_host_port(host: &str) -> (&str, &str) {
    match host.split_once(':') {
        Some((h, p)) => (h, p),
        None => (host, "443"),
    }
}

fn get_cert_not_before(cert: &X509) -> String {
    cert.not_before().to_string()
}

fn get_cert_not_after(cert: &X509) -> String {
    cert.not_after().to_string()
}

fn get_cert_common_name(cert: &X509) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "".to_string())
}

fn get_cert_sans(cert: &X509) -> String {
    cert.subject_alt_names()
        .map(|names| {
            names.iter()
                .filter_map(|name| name.dnsname())
                .map(|dns| dns.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "".to_string())
}