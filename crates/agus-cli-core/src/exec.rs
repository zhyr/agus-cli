use std::process::Command;

use agus_core_domain::Host;
use agus_ssh::{ProcessSshClient, SshClient, SshOutputStream, SshTarget};

use crate::CliError;

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn ssh_target_from_host(host: &Host) -> SshTarget {
    SshTarget {
        host: host.address.clone(),
        user: host.user.clone(),
        port: host.port,
        identity_file: host.identity_file.as_ref().map(|p| p.into()),
        password: host.password.clone(),
    }
}

pub fn build_shell_command(command: &str) -> String {
    format!("sh -lc {}", shell_quote(command))
}

fn shell_quote(input: &str) -> String {
    let mut quoted = String::from("'");
    for ch in input.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

pub fn execute_local(
    command: &str,
    args: &[String],
    use_shell: bool,
) -> Result<ExecOutput, CliError> {
    let output = if use_shell {
        Command::new("sh").arg("-lc").arg(command).output()?
    } else {
        Command::new(command).args(args).output()?
    };

    Ok(ExecOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn execute_local_interactive(
    command: &str,
    args: &[String],
    use_shell: bool,
) -> Result<i32, CliError> {
    let status = if use_shell {
        Command::new("sh").arg("-lc").arg(command).status()?
    } else {
        Command::new(command).args(args).status()?
    };
    Ok(status.code().unwrap_or(-1))
}

pub fn execute_remote(host: &Host, command: &str, use_shell: bool) -> Result<ExecOutput, CliError> {
    let target = ssh_target_from_host(host);
    let client = ProcessSshClient::new();
    let final_command = if use_shell {
        build_shell_command(command)
    } else {
        command.to_string()
    };

    let mut stdout = String::new();
    let mut stderr = String::new();

    let result =
        client.execute_streaming(&target, &final_command, &mut |stream, line| match stream {
            SshOutputStream::Stdout => {
                stdout.push_str(line);
                stdout.push('\n');
            }
            SshOutputStream::Stderr => {
                stderr.push_str(line);
                stderr.push('\n');
            }
        })?;

    Ok(ExecOutput {
        status: result.exit_code,
        stdout,
        stderr,
    })
}
