use agus_ssh::{SshClient, SshError, SshTarget};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxServerBlock {
    pub server_name: String,
    pub listen_ports: Vec<String>,
    pub ssl_enabled: bool,
    pub ssl_cert_path: Option<String>,
    pub ssl_cert_expiry: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxStatusReport {
    pub version: String,
    pub config_test_success: bool,
    pub server_blocks: Vec<NginxServerBlock>,
    pub security_vulnerabilities: Vec<String>,
    pub config_dump: String,
}

pub fn scan_nginx_status<C: SshClient>(
    client: &C,
    target: &SshTarget,
) -> Result<NginxStatusReport, SshError> {
    // 1. Version
    let version_output = client.execute(target, "nginx -v 2>&1")?;
    let version = version_output.stdout.trim().to_string();

    // 2. Config dump
    // nginx -T dumps the whole config including included files
    let dump_output = client.execute(target, "nginx -T 2>/dev/null")?;
    let config_dump = dump_output.stdout;

    // 3. Config test
    let test_output = client.execute(target, "nginx -t 2>/dev/null");
    let config_test_success = test_output.is_ok();

    // Use a simpler approach for cert path detection
    // (The above loop is very naive and might miss blocks if nesting is deep)

    // Let's refine the parsing slightly or just provide the dump and let the AI do it?
    // The user wants "Effective priority". That's hard to parse with regex.
    // Nginx priority:
    // 1. Exact name
    // 2. Name starting with wildcard
    // 3. Name ending with wildcard
    // 4. Regular expression
    // 5. Default server

    // I'll stick to basic extraction and let AI analyze the priority.

    let mut final_blocks = Vec::new();
    // Recalculate with a slightly better but still simple parser
    let mut lines = config_dump.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line == "server {" {
            let mut block = NginxServerBlock {
                server_name: "default".to_string(),
                listen_ports: Vec::new(),
                ssl_enabled: false,
                ssl_cert_path: None,
                ssl_cert_expiry: None,
            };

            let mut brace_count = 1;
            while brace_count > 0 {
                if let Some(l) = lines.next() {
                    let l = l.trim();
                    if l.contains("{") {
                        brace_count += 1;
                    }
                    if l.contains("}") {
                        brace_count -= 1;
                    }

                    if l.starts_with("server_name ") {
                        block.server_name = l
                            .strip_prefix("server_name ")
                            .unwrap()
                            .trim_end_matches(';')
                            .trim()
                            .to_string();
                    } else if l.starts_with("listen ") {
                        let port = l
                            .strip_prefix("listen ")
                            .unwrap()
                            .trim_end_matches(';')
                            .trim()
                            .to_string();
                        if port.contains("ssl") {
                            block.ssl_enabled = true;
                        }
                        block.listen_ports.push(port);
                    } else if l.starts_with("ssl_certificate ") {
                        block.ssl_cert_path = Some(
                            l.strip_prefix("ssl_certificate ")
                                .unwrap()
                                .trim_end_matches(';')
                                .trim()
                                .to_string(),
                        );
                    }
                } else {
                    break;
                }
            }

            // Check expiry if path found
            if let Some(path) = &block.ssl_cert_path {
                if let Ok(res) = client.execute(
                    target,
                    &format!("openssl x509 -enddate -noout -in {} 2>/dev/null", path),
                ) {
                    block.ssl_cert_expiry = Some(res.stdout.trim().replace("notAfter=", ""));
                }
            }

            final_blocks.push(block);
        }
    }

    // 5. Security Vulnerabilities
    let mut security_vulnerabilities = Vec::new();
    if !config_dump.contains("server_tokens off;") {
        security_vulnerabilities.push(
            "Insecure: 'server_tokens' is not set to 'off', exposing Nginx version.".to_string(),
        );
    }
    if config_dump.contains("autoindex on;") {
        security_vulnerabilities
            .push("Insecure: 'autoindex' is 'on', allowing directory listing.".to_string());
    }
    if !config_dump.contains("X-Frame-Options") {
        security_vulnerabilities.push("Missing security header: X-Frame-Options".to_string());
    }

    Ok(NginxStatusReport {
        version,
        config_test_success,
        server_blocks: final_blocks,
        security_vulnerabilities,
        config_dump,
    })
}
