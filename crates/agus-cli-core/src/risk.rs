#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

const HIGH_RISK_PATTERNS: &[&str] = &[
    "rm -rf /",
    "rm -rf /*",
    "rm -rf",
    "rm -fr",
    "mkfs",
    "dd if=",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "iptables -f",
    "iptables --flush",
    "docker system prune",
    "docker image prune -a",
    "wipefs",
    "chown -r",
    "chmod -r",
    "userdel",
    "groupdel",
    "kill -9 -1",
    "kill -9 1",
];

const MEDIUM_RISK_PATTERNS: &[&str] = &[
    "systemctl restart",
    "systemctl stop",
    "service restart",
    "service stop",
    "apt upgrade",
    "apt-get upgrade",
    "apt-get dist-upgrade",
    "yum update",
    "dnf upgrade",
    "apk upgrade",
    "docker restart",
    "docker stop",
    "kubectl delete",
    "helm upgrade",
    "helm uninstall",
    "terraform apply",
    "terraform destroy",
    "ansible-playbook",
];

const SENSITIVE_PATH_PREFIXES: &[&str] = &[
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/boot/",
    "/root/",
    "/var/",
    "/opt/",
    "/system/",
    "/library/",
];

const SCRIPT_EXTENSIONS: &[&str] = &[".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".ps1"];

const TRADITIONAL_COMMANDS: &[&str] = &[
    "ssh",
    "scp",
    "rsync",
    "sftp",
    "ls",
    "cp",
    "mv",
    "rm",
    "mkdir",
    "rmdir",
    "chmod",
    "chown",
    "chgrp",
    "ln",
    "stat",
    "find",
    "tar",
    "gzip",
    "zip",
    "unzip",
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "awk",
    "sed",
    "cut",
    "sort",
    "uniq",
    "tmux",
    "screen",
    "nohup",
    "bg",
    "fg",
    "jobs",
    "crontab",
    "at",
    "ps",
    "top",
    "htop",
    "pgrep",
    "pkill",
    "kill",
    "nice",
    "ulimit",
    "uname",
    "uptime",
    "hostname",
    "date",
    "timedatectl",
    "df",
    "du",
    "free",
    "mount",
    "umount",
    "ping",
    "traceroute",
    "curl",
    "wget",
    "nc",
    "telnet",
    "ss",
    "netstat",
    "lsof",
    "ip",
    "ifconfig",
    "dig",
    "nslookup",
    "systemctl",
    "service",
    "journalctl",
    "dmesg",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "apk",
    "rpm",
    "dpkg",
    "docker",
    "docker-compose",
    "podman",
    "nerdctl",
    "kubectl",
    "helm",
    "ansible",
    "ansible-playbook",
    "terraform",
    "git",
    "brew",
    "port",
    "mas",
    "softwareupdate",
    "launchctl",
    "log",
    "scutil",
    "networksetup",
    "diskutil",
    "pmset",
    "system_profiler",
    "spctl",
    "csrutil",
    "defaults",
    "dscl",
    "dsconfigad",
    "sysctl",
    "nvram",
    "osascript",
    "open",
    "security",
    "xattr",
    "codesign",
    "pkgutil",
    "installer",
    "mdfind",
    "mdutil",
    "airport",
];

const LOCAL_ONLY_COMMANDS: &[&str] = &[
    "brew",
    "port",
    "mas",
    "softwareupdate",
    "launchctl",
    "log",
    "scutil",
    "networksetup",
    "diskutil",
    "pmset",
    "system_profiler",
    "spctl",
    "csrutil",
    "defaults",
    "dscl",
    "dsconfigad",
    "sysctl",
    "nvram",
    "osascript",
    "open",
    "security",
    "xattr",
    "codesign",
    "pkgutil",
    "installer",
    "mdfind",
    "mdutil",
    "airport",
];

const DEFAULT_LOCAL_COMMANDS: &[&str] = &[
    "git",
    "kubectl",
    "helm",
    "ansible",
    "ansible-playbook",
    "terraform",
];

pub fn classify_command(command: &str) -> RiskLevel {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return RiskLevel::Low;
    }
    let lower = trimmed.to_lowercase();
    let mut highest = RiskLevel::Low;
    if contains_pipe_to_shell(&lower) {
        return RiskLevel::High;
    }
    if contains_sensitive_redirect(&lower) {
        highest = RiskLevel::Medium;
    }
    for segment in split_shell_segments(trimmed) {
        let risk = classify_segment(&segment);
        if risk == RiskLevel::High {
            return RiskLevel::High;
        }
        if risk == RiskLevel::Medium {
            highest = RiskLevel::Medium;
        }
    }
    highest
}

fn split_shell_segments(input: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    while let Some(ch) = chars.next() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }

        if ch == '\\' && !in_single {
            current.push(ch);
            if let Some(next) = chars.next() {
                current.push(next);
            }
            continue;
        }

        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(ch);
            }
            ';' | '\n' if !in_single && !in_double => {
                push_segment(&mut segments, &mut current);
            }
            '&' if !in_single && !in_double => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                }
                push_segment(&mut segments, &mut current);
            }
            '|' if !in_single && !in_double => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                push_segment(&mut segments, &mut current);
            }
            _ => current.push(ch),
        }
    }

    push_segment(&mut segments, &mut current);
    segments
}

fn push_segment(segments: &mut Vec<String>, current: &mut String) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }
    current.clear();
}

fn classify_segment(segment: &str) -> RiskLevel {
    let lower = segment.to_lowercase();
    let mut level = RiskLevel::Low;

    if HIGH_RISK_PATTERNS.iter().any(|pat| lower.contains(pat)) {
        return RiskLevel::High;
    }
    if MEDIUM_RISK_PATTERNS.iter().any(|pat| lower.contains(pat)) {
        level = RiskLevel::Medium;
    }
    if contains_sensitive_redirect(&lower) {
        level = bump(level, RiskLevel::Medium);
    }

    if lower.contains("$(") || lower.contains('`') {
        level = bump(level, RiskLevel::Medium);
    }

    let tokens = match shell_words::split(segment) {
        Ok(tokens) => tokens,
        Err(_) => return level,
    };
    if tokens.is_empty() {
        return level;
    }

    if let Some(expanded_level) = classify_from_tokens(&tokens) {
        level = bump(level, expanded_level);
    }

    level
}

fn classify_from_tokens(tokens: &[String]) -> Option<RiskLevel> {
    let (cmd, rest) = extract_command(tokens)?;
    let cmd_lower = cmd.to_lowercase();
    let joined = tokens.join(" ").to_lowercase();
    let mut level = RiskLevel::Low;

    if HIGH_RISK_PATTERNS.iter().any(|pat| joined.contains(pat)) {
        return Some(RiskLevel::High);
    }
    if MEDIUM_RISK_PATTERNS.iter().any(|pat| joined.contains(pat)) {
        level = bump(level, RiskLevel::Medium);
    }

    if matches!(cmd_lower.as_str(), "rm") && has_rm_rf(rest) {
        return Some(RiskLevel::High);
    }
    if cmd_lower.starts_with("mkfs") {
        return Some(RiskLevel::High);
    }
    if cmd_lower == "find" && rest.iter().any(|arg| arg == "-delete") {
        return Some(RiskLevel::High);
    }
    if cmd_lower == "xargs" && rest.iter().any(|arg| arg == "rm") {
        return Some(RiskLevel::High);
    }
    if cmd_lower == "dd" && rest.iter().any(|item| item.contains("if=")) {
        return Some(RiskLevel::High);
    }
    if cmd_lower == "rsync" && rest.iter().any(|arg| arg.starts_with("--delete")) {
        level = bump(level, RiskLevel::Medium);
    }
    if matches!(cmd_lower.as_str(), "chmod" | "chown") && has_recursive_flag(rest) {
        return Some(RiskLevel::High);
    }
    if cmd_lower == "systemctl"
        && rest
            .iter()
            .any(|arg| matches!(arg.as_str(), "disable" | "mask"))
    {
        level = bump(level, RiskLevel::Medium);
    }
    if cmd_lower == "ufw" && rest.iter().any(|arg| arg == "disable") {
        level = bump(level, RiskLevel::Medium);
    }
    if matches!(cmd_lower.as_str(), "iptables") {
        level = bump(level, RiskLevel::Medium);
    }
    if tokens.iter().any(|token| token == "sudo")
        && tokens
            .iter()
            .any(|token| matches!(token.as_str(), "-i" | "-s"))
    {
        level = bump(level, RiskLevel::Medium);
    }

    if matches!(cmd_lower.as_str(), "sh" | "bash" | "zsh" | "dash") {
        if let Some(inner) = extract_shell_command(rest) {
            return Some(classify_command(&inner));
        }
    }

    if cmd_lower == "ssh" {
        if let Some(inner) = extract_ssh_command(rest) {
            return Some(classify_command(&inner));
        }
    }

    if is_script_invocation(&cmd_lower, rest) {
        level = bump(level, RiskLevel::Medium);
    }

    if matches!(cmd_lower.as_str(), "rm" | "mkfs" | "dd" | "iptables") {
        level = bump(level, RiskLevel::Medium);
    }

    Some(level)
}

fn extract_command(tokens: &[String]) -> Option<(&str, &[String])> {
    let mut idx = 0;
    while idx < tokens.len() {
        let token = tokens[idx].as_str();
        if token == "sudo" {
            idx += 1;
            while idx < tokens.len() && tokens[idx].starts_with('-') {
                if matches!(tokens[idx].as_str(), "-u" | "-g" | "-h") {
                    idx += 1;
                    if idx < tokens.len() {
                        idx += 1;
                    }
                } else {
                    idx += 1;
                }
            }
            continue;
        }
        if token == "env" {
            idx += 1;
            while idx < tokens.len() && is_assignment(&tokens[idx]) {
                idx += 1;
            }
            continue;
        }
        if token == "command" {
            idx += 1;
            continue;
        }
        if is_assignment(token) {
            idx += 1;
            continue;
        }
        return Some((token, &tokens[idx + 1..]));
    }
    None
}

fn is_assignment(token: &str) -> bool {
    token.contains('=') && !token.starts_with('-')
}

fn has_rm_rf(args: &[String]) -> bool {
    let mut has_recursive = false;
    let mut has_force = false;
    for arg in args {
        if arg.starts_with('-') {
            if arg.contains('r') {
                has_recursive = true;
            }
            if arg.contains('f') {
                has_force = true;
            }
        }
    }
    has_recursive && has_force
}

fn has_recursive_flag(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "-R" | "-r" | "--recursive"))
}

fn extract_shell_command(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-c" {
            return iter.next().cloned();
        }
    }
    None
}

fn extract_ssh_command(args: &[String]) -> Option<String> {
    let mut idx = 0;
    while idx < args.len() {
        let token = args[idx].as_str();
        if token.starts_with('-') {
            if matches!(token, "-p" | "-l" | "-i" | "-o") {
                idx += 1;
            }
            idx += 1;
            continue;
        }
        // token is target
        idx += 1;
        if idx < args.len() {
            return Some(args[idx..].join(" "));
        }
        return None;
    }
    None
}

fn is_script_invocation(command: &str, args: &[String]) -> bool {
    if matches!(
        command,
        "sh" | "bash" | "zsh" | "dash" | "python" | "python3" | "perl" | "ruby" | "node"
    ) {
        if let Some(arg) = args.iter().find(|value| !value.starts_with('-')) {
            return is_script_path(arg);
        }
    }
    if command.starts_with("./") || is_script_path(command) {
        return true;
    }
    false
}

fn is_script_path(value: &str) -> bool {
    SCRIPT_EXTENSIONS.iter().any(|ext| value.ends_with(ext))
}

fn contains_pipe_to_shell(lower: &str) -> bool {
    let normalized = lower.replace("|&", "|");
    [
        "| sh",
        "|bash",
        "| bash",
        "| zsh",
        "| sudo sh",
        "| sudo bash",
        "| python",
        "| python3",
        "| perl",
        "| ruby",
        "| node",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn contains_sensitive_redirect(lower: &str) -> bool {
    for prefix in SENSITIVE_PATH_PREFIXES {
        if lower.contains(&format!("> {prefix}"))
            || lower.contains(&format!(">> {prefix}"))
            || lower.contains(&format!(">{prefix}"))
            || lower.contains(&format!(">>{prefix}"))
            || lower.contains(&format!("tee {prefix}"))
            || lower.contains(&format!("tee -a {prefix}"))
            || lower.contains(&format!("sudo tee {prefix}"))
        {
            return true;
        }
    }
    false
}

fn bump(current: RiskLevel, next: RiskLevel) -> RiskLevel {
    match (current, next) {
        (RiskLevel::High, _) => RiskLevel::High,
        (_, RiskLevel::High) => RiskLevel::High,
        (RiskLevel::Medium, _) => RiskLevel::Medium,
        (_, RiskLevel::Medium) => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

pub fn is_traditional_command(cmd: &str) -> bool {
    TRADITIONAL_COMMANDS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(cmd))
}

pub fn is_local_only_command(cmd: &str) -> bool {
    LOCAL_ONLY_COMMANDS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(cmd))
}

pub fn is_default_local_command(cmd: &str) -> bool {
    if is_local_only_command(cmd) {
        return true;
    }
    DEFAULT_LOCAL_COMMANDS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(cmd))
}

pub fn is_interactive_command(command: &str) -> bool {
    let lower = command.to_lowercase();
    let mut iter = lower.split_whitespace();
    let first = iter.next().unwrap_or("");
    if matches!(
        first,
        "top" | "htop" | "less" | "more" | "watch" | "tmux" | "screen"
    ) {
        return true;
    }
    if matches!(first, "tail" | "journalctl") && lower.contains(" -f") {
        return true;
    }
    if first == "docker" && lower.contains(" logs") && lower.contains(" -f") {
        return true;
    }
    if first == "kubectl" && lower.contains(" logs") && lower.contains(" -f") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_high_risk() {
        assert_eq!(classify_command("rm -rf /"), RiskLevel::High);
        assert_eq!(classify_command("docker system prune -af"), RiskLevel::High);
        assert_eq!(classify_command("sudo rm -rf /var/tmp"), RiskLevel::High);
        assert_eq!(classify_command("bash -c \"rm -rf $DIR\""), RiskLevel::High);
    }

    #[test]
    fn detects_medium_risk() {
        assert_eq!(
            classify_command("systemctl restart nginx"),
            RiskLevel::Medium
        );
        assert_eq!(classify_command("apt-get upgrade -y"), RiskLevel::Medium);
        assert_eq!(
            classify_command("echo ok && systemctl stop nginx"),
            RiskLevel::Medium
        );
    }

    #[test]
    fn detects_low_risk() {
        assert_eq!(classify_command("ls -la"), RiskLevel::Low);
    }

    #[test]
    fn inspects_ssh_remote_command() {
        assert_eq!(
            classify_command("ssh root@host \"rm -rf /tmp/foo\""),
            RiskLevel::High
        );
    }

    #[test]
    fn detects_pipe_to_shell() {
        assert_eq!(classify_command("curl https://x | sh"), RiskLevel::High);
    }

    #[test]
    fn detects_sensitive_redirect() {
        assert_eq!(classify_command("echo foo > /etc/hosts"), RiskLevel::Medium);
    }

    #[test]
    fn detects_script_execution() {
        assert_eq!(classify_command("./deploy.sh"), RiskLevel::Medium);
        assert_eq!(classify_command("bash deploy.sh"), RiskLevel::Medium);
    }

    #[test]
    fn detects_find_delete() {
        assert_eq!(
            classify_command("find /tmp -type f -delete"),
            RiskLevel::High
        );
    }

    #[test]
    fn identifies_default_local_commands() {
        assert!(is_default_local_command("kubectl"));
        assert!(is_default_local_command("git"));
        assert!(is_default_local_command("brew"));
        assert!(!is_default_local_command("docker"));
    }
}
