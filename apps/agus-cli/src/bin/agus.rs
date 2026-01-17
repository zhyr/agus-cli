use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agus_cli_core::{admin, audit, context, exec, executions, hosts, plan, risk, CliError};
use agus_core_domain::{
    DeploymentAction, DeploymentPlan, Environment, ExecutionRecord, ExecutionStatus, Host,
    HostContext, OpsEvent,
};
use agus_executor::{log_stream, ExecutionSession, Executor};
use agus_observer::{
    collect_system_metrics, container_health, container_logs, scan_junk_files, scan_nginx_status,
    scan_repo_basic, scan_vulnerability_context, Alert, AlertMetrics, AlertRule, AlertSeverity,
    Comparison, ContainerLogMonitor, MetricType, SystemMetrics,
};
use agus_planner::{
    generate_deployment_plan, generate_deployment_plan_with_llm,
    llm::{self, LlmProviderType, PerformanceMetrics},
};
use agus_secret_store::create_secret_store;
use agus_ssh::{ProcessSshClient, SshClient};
use agus_storage::create_storage_backend;
use chrono::{
    DateTime, Datelike, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "agus")]
#[command(about = "Agus CLI", long_about = None)]
struct AgusCli {
    #[command(subcommand)]
    command: Option<AgusCommand>,
}

#[derive(Subcommand)]
enum AgusCommand {
    Exec(ExecCommand),
    #[command(subcommand)]
    Host(HostCommand),
    #[command(subcommand)]
    Context(ContextCommand),
    Ssh(SshCommand),
    #[command(subcommand)]
    Shell(ShellCommand),
    #[command(subcommand)]
    Plan(PlanCommand),
    #[command(subcommand)]
    Deploy(DeployCommand),
    #[command(subcommand)]
    Logs(LogsCommand),
    #[command(subcommand)]
    Monitor(MonitorCommand),
    #[command(subcommand)]
    Alert(AlertCommand),
    #[command(subcommand)]
    Container(ContainerCommand),
    #[command(subcommand)]
    Security(SecurityCommand),
    #[command(subcommand)]
    Diagnose(DiagnoseCommand),
}

#[derive(Args)]
struct ExecCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    local: bool,
    #[arg(long)]
    shell: bool,
    #[arg(long)]
    yes: bool,
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Args)]
struct SshCommand {
    target: String,
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

#[derive(Subcommand)]
enum HostCommand {
    List,
    Add(HostAddCommand),
    Remove(HostRemoveCommand),
    Show(HostShowCommand),
}

#[derive(Args)]
struct HostAddCommand {
    #[arg(long)]
    id: String,
    #[arg(long)]
    address: String,
    #[arg(long, default_value = "root")]
    user: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    #[arg(long, default_value = "dev")]
    env: String,
    #[arg(long)]
    label: Vec<String>,
    #[arg(long)]
    identity_file: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    group_id: Option<String>,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct HostRemoveCommand {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct HostShowCommand {
    #[arg(long)]
    id: String,
}

#[derive(Subcommand)]
enum ContextCommand {
    Use(ContextUseCommand),
    Show,
    Clear,
}

#[derive(Subcommand)]
enum ShellCommand {
    Init(ShellInitCommand),
}

#[derive(Args)]
struct ShellInitCommand {
    #[arg(long, default_value = "zsh")]
    shell: String,
}

#[derive(Subcommand)]
enum PlanCommand {
    Generate(PlanGenerateCommand),
    Show(PlanShowCommand),
    Dag(PlanDagCommand),
    Update(PlanUpdateCommand),
}

#[derive(Args)]
struct PlanGenerateCommand {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    output: Option<String>,
    #[arg(long)]
    llm: bool,
}

#[derive(Args)]
struct PlanShowCommand {
    #[arg(long)]
    file: String,
}

#[derive(Args)]
struct PlanDagCommand {
    #[arg(long)]
    file: String,
    #[arg(long, default_value = "dot")]
    format: String,
}

#[derive(Args)]
struct PlanUpdateCommand {
    #[arg(long)]
    file: String,
    #[arg(long)]
    step: String,
    #[arg(long)]
    approval_required: Option<bool>,
    #[arg(long, value_delimiter = ',')]
    depends_on: Option<Vec<String>>,
    #[arg(long)]
    memo: Option<String>,
}

#[derive(Subcommand)]
enum DeployCommand {
    Run(DeployRunCommand),
    Status(DeployStatusCommand),
    Logs(DeployLogsCommand),
    Resume(DeployResumeCommand),
    List,
    Clean(DeployCleanCommand),
}

#[derive(Args)]
struct DeployRunCommand {
    #[arg(long)]
    plan: String,
    #[arg(long, default_value = "compose")]
    mode: String,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    stream: bool,
    #[arg(long)]
    pause_on_approval: bool,
}

#[derive(Args)]
struct DeployStatusCommand {
    #[arg(long)]
    execution_id: String,
}

#[derive(Args)]
struct DeployLogsCommand {
    #[arg(long)]
    execution_id: String,
    #[arg(long)]
    follow: bool,
    #[arg(long)]
    step: Option<String>,
}

#[derive(Args)]
struct DeployResumeCommand {
    #[arg(long)]
    execution_id: String,
    #[arg(long)]
    stream: bool,
    #[arg(long)]
    pause_on_approval: bool,
}

#[derive(Args)]
struct DeployCleanCommand {
    #[arg(long)]
    execution_id: String,
}

#[derive(Subcommand)]
enum LogsCommand {
    System(SystemLogsCommand),
    Container(ContainerLogsCommand),
    Ops(OpsLogsCommand),
}

#[derive(Args)]
struct SystemLogsCommand {
    #[arg(long)]
    host: String,
    #[arg(long, default_value_t = 120)]
    lines: usize,
}

#[derive(Args)]
struct ContainerLogsCommand {
    #[arg(long)]
    host: String,
    #[arg(long)]
    container: String,
    #[arg(long)]
    lines: Option<usize>,
    #[arg(long)]
    since: Option<u64>,
}

#[derive(Args)]
struct OpsLogsCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    execution_id: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Subcommand)]
enum MonitorCommand {
    Metrics(MonitorMetricsCommand),
}

#[derive(Args)]
struct MonitorMetricsCommand {
    #[arg(long)]
    host: String,
}

#[derive(Subcommand)]
enum AlertCommand {
    #[command(subcommand)]
    Rules(AlertRulesCommand),
    Active,
    Ack(AlertAckCommand),
    Clear(AlertClearCommand),
    Evaluate(AlertEvaluateCommand),
}

#[derive(Subcommand)]
enum AlertRulesCommand {
    List,
    Add(AlertRuleAddCommand),
    Remove(AlertRuleRemoveCommand),
}

#[derive(Args)]
struct AlertRuleAddCommand {
    #[arg(long)]
    id: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    metric: String,
    #[arg(long)]
    threshold: f64,
    #[arg(long)]
    comparison: String,
    #[arg(long)]
    severity: String,
    #[arg(long)]
    disabled: bool,
}

#[derive(Args)]
struct AlertRuleRemoveCommand {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct AlertAckCommand {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct AlertClearCommand {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct AlertEvaluateCommand {
    #[arg(long)]
    host: String,
}

#[derive(Subcommand)]
enum ContainerCommand {
    Health(ContainerHealthCommand),
    Logs(ContainerLogsCommand),
}

#[derive(Args)]
struct ContainerHealthCommand {
    #[arg(long)]
    host: String,
    #[arg(long)]
    container: Option<String>,
}

#[derive(Subcommand)]
enum SecurityCommand {
    ScanJunk(SecurityScanJunkCommand),
    CleanJunk(SecurityCleanJunkCommand),
    Vulnerability(SecurityVulnerabilityCommand),
    Nginx(SecurityNginxCommand),
}

#[derive(Args)]
struct SecurityScanJunkCommand {
    #[arg(long)]
    host: String,
}

#[derive(Args)]
struct SecurityCleanJunkCommand {
    #[arg(long)]
    host: String,
    #[arg(long, value_delimiter = ',')]
    targets: Vec<String>,
}

#[derive(Args)]
struct SecurityVulnerabilityCommand {
    #[arg(long)]
    host: String,
}

#[derive(Args)]
struct SecurityNginxCommand {
    #[arg(long)]
    host: String,
}

#[derive(Subcommand)]
enum DiagnoseCommand {
    Error(DiagnoseErrorCommand),
    Performance(DiagnosePerformanceCommand),
    Dependencies(DiagnoseDependenciesCommand),
}

#[derive(Args)]
struct DiagnoseErrorCommand {
    #[arg(long)]
    message: String,
    #[arg(long, value_delimiter = ',')]
    logs: Vec<String>,
    #[arg(long)]
    context: Option<String>,
}

#[derive(Args)]
struct DiagnosePerformanceCommand {
    #[arg(long)]
    host: String,
    #[arg(long)]
    service: String,
}

#[derive(Args)]
struct DiagnoseDependenciesCommand {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    service: String,
}

#[derive(Args)]
struct ContextUseCommand {
    #[arg(long)]
    host: String,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, CliError> {
    let cli = AgusCli::parse();
    match cli.command {
        Some(command) => handle_command(command),
        None => {
            run_repl()?;
            Ok(0)
        }
    }
}

fn handle_command(command: AgusCommand) -> Result<i32, CliError> {
    match command {
        AgusCommand::Exec(cmd) => handle_exec(cmd),
        AgusCommand::Host(cmd) => handle_host(cmd).map(|_| 0),
        AgusCommand::Context(cmd) => handle_context(cmd).map(|_| 0),
        AgusCommand::Ssh(cmd) => handle_ssh(cmd).map(|_| 0),
        AgusCommand::Shell(cmd) => handle_shell(cmd).map(|_| 0),
        AgusCommand::Plan(cmd) => handle_plan(cmd).map(|_| 0),
        AgusCommand::Deploy(cmd) => handle_deploy(cmd).map(|_| 0),
        AgusCommand::Logs(cmd) => handle_logs(cmd).map(|_| 0),
        AgusCommand::Monitor(cmd) => handle_monitor(cmd).map(|_| 0),
        AgusCommand::Alert(cmd) => handle_alert(cmd).map(|_| 0),
        AgusCommand::Container(cmd) => handle_container(cmd).map(|_| 0),
        AgusCommand::Security(cmd) => handle_security(cmd).map(|_| 0),
        AgusCommand::Diagnose(cmd) => handle_diagnose(cmd).map(|_| 0),
    }
}

fn handle_exec(cmd: ExecCommand) -> Result<i32, CliError> {
    if cmd.cmd.is_empty() {
        return Err(CliError::InvalidInput("missing command".to_string()));
    }
    let command_line = join_tokens(&cmd.cmd);
    let first = cmd.cmd[0].as_str();

    if first.eq_ignore_ascii_case("ssh") {
        let target = cmd
            .cmd
            .get(1)
            .cloned()
            .ok_or_else(|| CliError::InvalidInput("ssh requires a target".to_string()))?;
        let args = cmd.cmd.iter().skip(2).cloned().collect::<Vec<_>>();
        handle_ssh(SshCommand { target, args })?;
        return Ok(0);
    }

    if is_transfer_command(first) {
        let ctx = context::load_context()?;
        let preferred_host = cmd.host.as_deref().or(ctx.current_host.as_deref());
        log_cli_event(&format!(
            "cli transfer cmd={} target_host={}",
            command_line,
            preferred_host.unwrap_or("local")
        ));
        let args = rewrite_transfer_args(&cmd.cmd, preferred_host)?;
        run_command_inherit(first, &args)?;
        return Ok(0);
    }

    if is_copy_command(first) && has_remote_path(&cmd.cmd) {
        let ctx = context::load_context()?;
        let preferred_host = cmd.host.as_deref().or(ctx.current_host.as_deref());
        log_cli_event(&format!(
            "cli transfer cmd={} target_host={}",
            command_line,
            preferred_host.unwrap_or("local")
        ));
        let mut args = cmd.cmd.clone();
        args[0] = "scp".to_string();
        let rewritten = rewrite_transfer_args(&args, preferred_host)?;
        run_command_inherit("scp", &rewritten)?;
        return Ok(0);
    }

    let risk_level = risk::classify_command(&command_line);
    enforce_approval(risk_level, cmd.yes)?;

    let prefer_local = risk::is_default_local_command(first);
    let target_host = resolve_target(cmd.local, cmd.host.as_deref(), prefer_local)?;

    log_exec_event("exec", &command_line, risk_level, cmd.shell, &target_host);

    if is_dry_run() {
        print_dry_run(&target_host, &command_line);
        return Ok(0);
    }

    if let Some(host) = target_host {
        let output = exec::execute_remote(&host, &command_line, cmd.shell)?;
        print_output(&output.stdout, &output.stderr);
        Ok(exit_code(output.status))
    } else {
        let output = if cmd.shell {
            exec::execute_local(&command_line, &[], true)?
        } else {
            exec::execute_local(&cmd.cmd[0], &cmd.cmd[1..], false)?
        };
        print_output(&output.stdout, &output.stderr);
        Ok(exit_code(output.status))
    }
}

fn handle_host(cmd: HostCommand) -> Result<(), CliError> {
    match cmd {
        HostCommand::List => {
            let hosts = hosts::load_hosts()?;
            if hosts.is_empty() {
                println!("No hosts configured.");
                return Ok(());
            }
            log_cli_event("cli host list");
            for host in hosts {
                println!(
                    "{}\t{}\t{}:{}\t{:?}\t{}",
                    host.id,
                    host.address,
                    host.user,
                    host.port,
                    host.environment,
                    host.labels.join(",")
                );
            }
        }
        HostCommand::Add(cmd) => {
            let env = parse_environment(&cmd.env)?;
            let mut existing = hosts::load_hosts()?;
            if existing.iter().any(|host| host.id == cmd.id) && !cmd.force {
                return Err(CliError::InvalidInput(
                    "host already exists; use --force to overwrite".to_string(),
                ));
            }
            let host_id = cmd.id.clone();
            let host_addr = cmd.address.clone();
            let host = Host {
                id: cmd.id,
                address: cmd.address,
                environment: env,
                labels: cmd.label,
                user: cmd.user,
                port: cmd.port,
                identity_file: cmd.identity_file,
                password: cmd.password,
                group_id: cmd.group_id,
            };
            existing.retain(|item| item.id != host.id);
            existing.push(host);
            hosts::save_hosts(&existing)?;
            log_cli_event(&format!("cli host add id={} addr={}", host_id, host_addr));
            println!("Host saved.");
        }
        HostCommand::Remove(cmd) => {
            let removed = hosts::remove_host(&cmd.id)?;
            if removed {
                log_cli_event(&format!("cli host remove id={}", cmd.id));
                println!("Host removed.");
            } else {
                println!("Host not found.");
            }
        }
        HostCommand::Show(cmd) => {
            let host = hosts::find_host(&cmd.id)?;
            log_cli_event(&format!("cli host show id={}", cmd.id));
            println!("id: {}", host.id);
            println!("address: {}", host.address);
            println!("user: {}", host.user);
            println!("port: {}", host.port);
            println!("environment: {:?}", host.environment);
            println!("labels: {}", host.labels.join(","));
            if let Some(group) = host.group_id {
                println!("group: {group}");
            }
            if let Some(identity) = host.identity_file {
                println!("identity_file: {identity}");
            }
        }
    }
    Ok(())
}

fn handle_context(cmd: ContextCommand) -> Result<(), CliError> {
    match cmd {
        ContextCommand::Use(cmd) => {
            let _ = hosts::find_host(&cmd.host)?;
            let mut ctx = context::load_context()?;
            ctx.current_host = Some(cmd.host);
            context::save_context(&ctx)?;
            log_cli_event("cli context use");
            println!("Context updated.");
        }
        ContextCommand::Show => {
            let ctx = context::load_context()?;
            log_cli_event("cli context show");
            match ctx.current_host {
                Some(host) => println!("Current host: {host}"),
                None => println!("No host context set."),
            }
        }
        ContextCommand::Clear => {
            let mut ctx = context::load_context()?;
            ctx.current_host = None;
            context::save_context(&ctx)?;
            log_cli_event("cli context clear");
            println!("Context cleared.");
        }
    }
    Ok(())
}

fn handle_ssh(cmd: SshCommand) -> Result<(), CliError> {
    let target = cmd.target;
    let host = hosts::find_host(&target).ok();
    log_cli_event(&format!(
        "cli ssh target={} args={}",
        target,
        cmd.args.join(" ")
    ));
    if let Some(host) = host {
        run_ssh_with_host(&host, &cmd.args)?;
    } else {
        run_command_inherit("ssh", &build_passthrough_args(&target, &cmd.args))?;
    }
    Ok(())
}

fn handle_shell(cmd: ShellCommand) -> Result<(), CliError> {
    match cmd {
        ShellCommand::Init(cmd) => shell_init(&cmd.shell),
    }
}

fn shell_init(shell: &str) -> Result<(), CliError> {
    let shell = shell.to_lowercase();
    if shell != "zsh" && shell != "bash" {
        return Err(CliError::InvalidInput(format!(
            "unsupported shell: {shell}. Use --shell zsh|bash"
        )));
    }
    print!("{}", SHELL_INIT_SCRIPT);
    Ok(())
}

fn handle_plan(cmd: PlanCommand) -> Result<(), CliError> {
    match cmd {
        PlanCommand::Generate(cmd) => {
            let repo_path = PathBuf::from(&cmd.repo);
            let graph = scan_repo_basic(&repo_path)
                .map_err(|e| CliError::InvalidInput(format!("scan repo failed: {e}")))?;
            let plan = if cmd.llm {
                let config = load_llm_config()?;
                let provider = llm::create_llm_provider(config)
                    .map_err(|e| CliError::Config(format!("failed to create LLM provider: {e}")))?;
                generate_deployment_plan_with_llm(&graph, Some(provider.as_ref()))
                    .map_err(|e| CliError::InvalidInput(format!("plan generation failed: {e}")))?
            } else {
                generate_deployment_plan(&graph)
                    .map_err(|e| CliError::InvalidInput(format!("plan generation failed: {e}")))?
            };

            if let Some(output) = cmd.output.as_deref() {
                plan::save_plan(output, &plan)?;
                println!("Plan saved: {output}");
            } else {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            }
        }
        PlanCommand::Show(cmd) => {
            let plan = plan::load_plan(&cmd.file)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        PlanCommand::Dag(cmd) => {
            let plan = plan::load_plan(&cmd.file)?;
            let format = cmd.format.trim().to_lowercase();
            let output = match format.as_str() {
                "dot" => plan::plan_to_dot(&plan),
                "mermaid" => plan::plan_to_mermaid(&plan),
                _ => {
                    return Err(CliError::InvalidInput(
                        "unsupported format; use dot|mermaid".to_string(),
                    ))
                }
            };
            print!("{output}");
        }
        PlanCommand::Update(cmd) => {
            let mut plan = plan::load_plan(&cmd.file)?;
            let mut updated = false;
            for step in &mut plan.steps {
                if step.id == cmd.step {
                    if let Some(value) = cmd.approval_required {
                        step.approval_required = value;
                        updated = true;
                    }
                    if let Some(depends) = cmd.depends_on.clone() {
                        step.depends_on = depends;
                        updated = true;
                    }
                    if let Some(memo) = cmd.memo.clone() {
                        step.memo = Some(memo);
                        updated = true;
                    }
                }
            }
            if !updated {
                return Err(CliError::InvalidInput(
                    "no updates applied; verify step id and flags".to_string(),
                ));
            }
            plan::save_plan(&cmd.file, &plan)?;
            println!("Plan updated.");
        }
    }
    Ok(())
}

fn handle_deploy(cmd: DeployCommand) -> Result<(), CliError> {
    match cmd {
        DeployCommand::Run(cmd) => handle_deploy_run(cmd),
        DeployCommand::Status(cmd) => handle_deploy_status(cmd),
        DeployCommand::Logs(cmd) => handle_deploy_logs(cmd),
        DeployCommand::Resume(cmd) => handle_deploy_resume(cmd),
        DeployCommand::List => handle_deploy_list(),
        DeployCommand::Clean(cmd) => handle_deploy_clean(cmd),
    }
}

#[derive(Debug, Clone, Copy)]
enum DeployMode {
    DryRun,
    Compose,
    SshReadonly,
    DockerReadonly,
}

impl DeployMode {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value.trim().to_lowercase().as_str() {
            "dry-run" | "dryrun" => Ok(Self::DryRun),
            "compose" => Ok(Self::Compose),
            "ssh-readonly" | "ssh" => Ok(Self::SshReadonly),
            "docker-readonly" | "docker" => Ok(Self::DockerReadonly),
            _ => Err(CliError::InvalidInput(format!(
                "unknown mode: {value}. Use dry-run|compose|ssh-readonly|docker-readonly"
            ))),
        }
    }

    fn from_checkpoint(value: &str) -> Result<Self, CliError> {
        match value {
            "DryRun" => Ok(Self::DryRun),
            "Compose" => Ok(Self::Compose),
            "SshReadonly" => Ok(Self::SshReadonly),
            "DockerReadonly" => Ok(Self::DockerReadonly),
            _ => Err(CliError::InvalidInput(format!(
                "unsupported checkpoint mode: {value}"
            ))),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            DeployMode::DryRun => "dry-run",
            DeployMode::Compose => "compose",
            DeployMode::SshReadonly => "ssh-readonly",
            DeployMode::DockerReadonly => "docker-readonly",
        }
    }

    fn requires_host(&self) -> bool {
        !matches!(self, DeployMode::DryRun)
    }
}

#[derive(Debug, Clone)]
struct ExecutionMeta {
    execution_id: String,
    host_id: String,
    host_address: String,
    environment: Environment,
    plan: DeploymentPlan,
}

#[derive(Debug, Deserialize)]
struct ExecutionCheckpointInfo {
    host_id: String,
    mode_type: String,
}

fn handle_deploy_run(cmd: DeployRunCommand) -> Result<(), CliError> {
    let plan_path = PathBuf::from(&cmd.plan);
    let plan = plan::load_plan(&plan_path)?;
    let mode = DeployMode::parse(&cmd.mode)?;
    let execution_id = new_execution_id();
    let started_at = current_timestamp_ms();

    let (host_ctx, host_meta) = resolve_host_context(mode, cmd.host.as_deref())?;

    let session_info = executions::ExecutionSessionInfo {
        execution_id: execution_id.clone(),
        mode: mode.label().to_string(),
        host_id: host_meta.as_ref().map(|host| host.id.clone()),
        plan_path: Some(plan_path.to_string_lossy().to_string()),
        started_at,
        finished_at: None,
    };
    executions::write_session_info(&session_info)?;

    let (session, stream_handle) =
        create_execution_session(mode, plan.clone(), host_ctx.clone(), cmd.stream)?;

    let meta = build_execution_meta(&execution_id, &host_meta, &plan);
    let checkpoint_path = executions::checkpoint_path(&execution_id)?;
    let mut session = attach_record_writer(session.with_checkpoint(checkpoint_path.clone()), &meta);

    run_session_with_approvals(&mut session, &meta, cmd.pause_on_approval)?;

    if let Some(handle) = stream_handle {
        let _ = handle.join();
    }

    executions::update_finished_at(&execution_id, current_timestamp_ms())?;
    println!("Execution completed: {}", execution_id);
    Ok(())
}

fn handle_deploy_status(cmd: DeployStatusCommand) -> Result<(), CliError> {
    let records = executions::load_records(&cmd.execution_id)?;
    if records.is_empty() {
        println!("No execution records found.");
        return Ok(());
    }
    for record in records {
        println!(
            "{}\t{:?}\t{}",
            record.step_id,
            record.status,
            record.error.clone().unwrap_or_default()
        );
    }
    Ok(())
}

fn handle_deploy_logs(cmd: DeployLogsCommand) -> Result<(), CliError> {
    let path = executions::record_file_path(&cmd.execution_id)?;
    if !path.exists() {
        return Err(CliError::InvalidInput(format!(
            "execution logs not found: {}",
            cmd.execution_id
        )));
    }
    tail_records(&path, cmd.follow, cmd.step.as_deref())?;
    Ok(())
}

fn handle_deploy_resume(cmd: DeployResumeCommand) -> Result<(), CliError> {
    if !executions::execution_exists(&cmd.execution_id)? {
        return Err(CliError::InvalidInput(format!(
            "execution not found: {}",
            cmd.execution_id
        )));
    }
    if !executions::checkpoint_exists(&cmd.execution_id)? {
        return Err(CliError::InvalidInput(format!(
            "checkpoint not found for {}",
            cmd.execution_id
        )));
    }
    let checkpoint_path = executions::checkpoint_path(&cmd.execution_id)?;
    let checkpoint_content = executions::read_checkpoint(&cmd.execution_id)?;
    let checkpoint_info: ExecutionCheckpointInfo = serde_json::from_str(&checkpoint_content)?;
    let mode = DeployMode::from_checkpoint(&checkpoint_info.mode_type)?;

    let host = if mode.requires_host() {
        Some(hosts::find_host(&checkpoint_info.host_id)?)
    } else {
        None
    };

    let session_info = executions::load_session_info(&cmd.execution_id)?;
    let plan_path = session_info
        .plan_path
        .ok_or_else(|| CliError::InvalidInput("plan path missing for execution".to_string()))?;
    let plan = plan::load_plan(&plan_path)?;
    let meta = build_execution_meta(&cmd.execution_id, &host, &plan);

    let (session, stream_handle) = resume_execution_session(
        mode,
        &checkpoint_path,
        host_ctx_from_host(host.clone()),
        cmd.stream,
    )?;
    let mut session = attach_record_writer(session, &meta);

    run_session_with_approvals(&mut session, &meta, cmd.pause_on_approval)?;

    if let Some(handle) = stream_handle {
        let _ = handle.join();
    }

    executions::update_finished_at(&cmd.execution_id, current_timestamp_ms())?;
    println!("Execution resumed: {}", cmd.execution_id);
    Ok(())
}

fn handle_deploy_list() -> Result<(), CliError> {
    let sessions = executions::list_sessions()?;
    if sessions.is_empty() {
        println!("No execution sessions found.");
        return Ok(());
    }
    for session in sessions {
        println!(
            "{}\t{}\t{}\t{}",
            session.execution_id,
            session.mode,
            session
                .host_id
                .clone()
                .unwrap_or_else(|| "local".to_string()),
            session.started_at
        );
    }
    Ok(())
}

fn handle_deploy_clean(cmd: DeployCleanCommand) -> Result<(), CliError> {
    executions::delete_execution(&cmd.execution_id)?;
    println!("Execution data removed: {}", cmd.execution_id);
    Ok(())
}

fn handle_logs(cmd: LogsCommand) -> Result<(), CliError> {
    match cmd {
        LogsCommand::System(cmd) => {
            let entries = get_system_logs(&cmd.host, cmd.lines)?;
            for entry in entries {
                println!(
                    "{}\t{}\t{}\t{}",
                    entry.timestamp, entry.level, entry.source, entry.message
                );
            }
        }
        LogsCommand::Container(cmd) => {
            let logs = get_container_logs(&cmd.host, &cmd.container, cmd.lines, cmd.since)?;
            for entry in logs {
                println!("{}\t{:?}\t{}", entry.timestamp, entry.level, entry.message);
            }
        }
        LogsCommand::Ops(cmd) => {
            let mut events = create_storage_backend().load_events()?;
            if let Some(host_id) = cmd.host.as_deref() {
                events.retain(|event| event.host_id == host_id);
            }
            if let Some(execution_id) = cmd.execution_id.as_deref() {
                events.retain(|event| event.execution_id == execution_id);
            }
            events.sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));
            if let Some(limit) = cmd.limit {
                events.truncate(limit);
            }
            for event in events {
                println!(
                    "{}\t{}\t{:?}\t{}",
                    event.execution_id, event.step_id, event.status, event.service_name
                );
            }
        }
    }
    Ok(())
}

fn handle_monitor(cmd: MonitorCommand) -> Result<(), CliError> {
    match cmd {
        MonitorCommand::Metrics(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            let metrics = collect_system_metrics(&client, &target, &host.id)
                .map_err(|e| CliError::InvalidInput(format!("metrics collection failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&metrics)?);
        }
    }
    Ok(())
}

fn handle_alert(cmd: AlertCommand) -> Result<(), CliError> {
    match cmd {
        AlertCommand::Rules(rule_cmd) => match rule_cmd {
            AlertRulesCommand::List => {
                let state = load_alert_store()?;
                for rule in state.rules {
                    println!(
                        "{}\t{}\t{:?}\t{}\t{:?}",
                        rule.id, rule.name, rule.metric_type, rule.threshold, rule.severity
                    );
                }
            }
            AlertRulesCommand::Add(cmd) => {
                let mut state = load_alert_store()?;
                let rule = AlertRule {
                    id: cmd.id,
                    name: cmd.name,
                    metric_type: parse_metric_type(&cmd.metric)?,
                    threshold: cmd.threshold,
                    comparison: parse_comparison(&cmd.comparison)?,
                    severity: parse_severity(&cmd.severity)?,
                    enabled: !cmd.disabled,
                };
                state.rules.retain(|item| item.id != rule.id);
                state.rules.push(rule);
                save_alert_store(&state)?;
                println!("Alert rule saved.");
            }
            AlertRulesCommand::Remove(cmd) => {
                let mut state = load_alert_store()?;
                let before = state.rules.len();
                state.rules.retain(|item| item.id != cmd.id);
                if state.rules.len() == before {
                    return Err(CliError::InvalidInput("alert rule not found".to_string()));
                }
                save_alert_store(&state)?;
                println!("Alert rule removed.");
            }
        },
        AlertCommand::Active => {
            let state = load_alert_store()?;
            if state.active.is_empty() {
                println!("No active alerts.");
                return Ok(());
            }
            for alert in state.active {
                println!(
                    "{}\t{}\t{:?}\t{}",
                    alert.id, alert.rule_id, alert.severity, alert.message
                );
            }
        }
        AlertCommand::Ack(cmd) => {
            let mut state = load_alert_store()?;
            if let Some(alert) = state.active.iter_mut().find(|alert| alert.id == cmd.id) {
                alert.acknowledged = true;
                save_alert_store(&state)?;
                println!("Alert acknowledged.");
            } else {
                return Err(CliError::InvalidInput("alert not found".to_string()));
            }
        }
        AlertCommand::Clear(cmd) => {
            let mut state = load_alert_store()?;
            let before = state.active.len();
            state.active.retain(|alert| alert.id != cmd.id);
            if state.active.len() == before {
                return Err(CliError::InvalidInput("alert not found".to_string()));
            }
            save_alert_store(&state)?;
            println!("Alert cleared.");
        }
        AlertCommand::Evaluate(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let mut state = load_alert_store()?;
            let new_alerts = evaluate_alerts_for_host(&host, &mut state)?;
            save_alert_store(&state)?;
            if new_alerts.is_empty() {
                println!("No new alerts.");
            } else {
                for alert in new_alerts {
                    println!(
                        "{}\t{}\t{:?}\t{}",
                        alert.id, alert.rule_id, alert.severity, alert.message
                    );
                }
            }
        }
    }
    Ok(())
}

fn handle_container(cmd: ContainerCommand) -> Result<(), CliError> {
    match cmd {
        ContainerCommand::Health(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            if let Some(container) = cmd.container.as_deref() {
                let result = container_health::check_container_health(&client, &target, container)
                    .map_err(|e| CliError::InvalidInput(e))?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let results = container_health::check_all_containers_health(&client, &target, None)
                    .map_err(|e| CliError::InvalidInput(e))?;
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
        }
        ContainerCommand::Logs(cmd) => handle_logs(LogsCommand::Container(cmd))?,
    }
    Ok(())
}

fn handle_security(cmd: SecurityCommand) -> Result<(), CliError> {
    match cmd {
        SecurityCommand::ScanJunk(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            let items = scan_junk_files(&client, &target)
                .map_err(|e| CliError::InvalidInput(format!("junk scan failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&items)?);
        }
        SecurityCommand::CleanJunk(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            agus_observer::clean_junk_files(&client, &target, cmd.targets)
                .map_err(|e| CliError::InvalidInput(format!("junk clean failed: {e}")))?;
            println!("Junk clean completed.");
        }
        SecurityCommand::Vulnerability(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            let report = scan_vulnerability_context(&client, &target)
                .map_err(|e| CliError::InvalidInput(format!("vulnerability scan failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        SecurityCommand::Nginx(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            let report = scan_nginx_status(&client, &target)
                .map_err(|e| CliError::InvalidInput(format!("nginx scan failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

fn handle_diagnose(cmd: DiagnoseCommand) -> Result<(), CliError> {
    let provider = load_llm_provider()?;
    match cmd {
        DiagnoseCommand::Error(cmd) => {
            let logs = collect_log_inputs(&cmd.logs)?;
            let result = provider
                .diagnose_error(&cmd.message, &logs, cmd.context.as_deref())
                .map_err(|e| CliError::Config(format!("diagnosis failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        DiagnoseCommand::Performance(cmd) => {
            let host = hosts::find_host(&cmd.host)?;
            let target = exec::ssh_target_from_host(&host);
            let client = ProcessSshClient::new();
            let metrics = collect_system_metrics(&client, &target, &host.id)
                .map_err(|e| CliError::InvalidInput(format!("metrics collection failed: {e}")))?;
            let perf = map_system_metrics_to_perf(&metrics);
            let result = provider
                .evaluate_performance(&cmd.service, &perf)
                .map_err(|e| CliError::Config(format!("performance analysis failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        DiagnoseCommand::Dependencies(cmd) => {
            let graph = scan_repo_basic(Path::new(&cmd.repo))
                .map_err(|e| CliError::InvalidInput(format!("scan repo failed: {e}")))?;
            let result = provider
                .analyze_dependencies(&cmd.service, &graph)
                .map_err(|e| CliError::Config(format!("dependency analysis failed: {e}")))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    Ok(())
}

fn resolve_host_context(
    mode: DeployMode,
    host_arg: Option<&str>,
) -> Result<(Option<HostContext>, Option<Host>), CliError> {
    if !mode.requires_host() {
        return Ok((None, None));
    }
    let host_id = match host_arg {
        Some(host) => host.to_string(),
        None => {
            let ctx = context::load_context()?;
            ctx.current_host.ok_or_else(|| {
                CliError::InvalidInput("host is required (use --host or context)".to_string())
            })?
        }
    };
    let host = hosts::find_host(&host_id)?;
    let host_ctx = HostContext {
        host: host.address.clone(),
        user: host.user.clone(),
        port: host.port,
        environment: host.environment,
    };
    Ok((Some(host_ctx), Some(host)))
}

fn host_ctx_from_host(host: Option<Host>) -> Option<HostContext> {
    host.map(|host| HostContext {
        host: host.address,
        user: host.user,
        port: host.port,
        environment: host.environment,
    })
}

fn create_execution_session(
    mode: DeployMode,
    plan: DeploymentPlan,
    host_ctx: Option<HostContext>,
    stream: bool,
) -> Result<(ExecutionSession, Option<thread::JoinHandle<()>>), CliError> {
    let executor = Executor::new();
    let mut handle = None;
    match mode {
        DeployMode::DryRun => executor
            .start_dry_run(plan)
            .map(|session| (session, None))
            .map_err(|e| CliError::InvalidInput(e.to_string())),
        DeployMode::Compose => {
            let host_ctx = host_ctx.ok_or_else(|| {
                CliError::InvalidInput("host context required for compose".to_string())
            })?;
            let client = ProcessSshClient::new();
            let sender = if stream {
                let (sender, receiver) = log_stream::create_log_stream();
                handle = Some(spawn_log_stream_thread(receiver));
                Some(sender)
            } else {
                None
            };
            executor
                .start_compose_with_log_stream(plan, host_ctx, client, sender)
                .map(|session| (session, handle))
                .map_err(|e| CliError::InvalidInput(e.to_string()))
        }
        DeployMode::SshReadonly => {
            let host_ctx = host_ctx.ok_or_else(|| {
                CliError::InvalidInput("host context required for ssh-readonly".to_string())
            })?;
            let client = ProcessSshClient::new();
            executor
                .start_ssh_readonly(plan, host_ctx, client)
                .map(|session| (session, None))
                .map_err(|e| CliError::InvalidInput(e.to_string()))
        }
        DeployMode::DockerReadonly => {
            let host_ctx = host_ctx.ok_or_else(|| {
                CliError::InvalidInput("host context required for docker-readonly".to_string())
            })?;
            let client = ProcessSshClient::new();
            executor
                .start_docker_readonly(plan, host_ctx, client)
                .map(|session| (session, None))
                .map_err(|e| CliError::InvalidInput(e.to_string()))
        }
    }
}

fn resume_execution_session(
    mode: DeployMode,
    checkpoint_path: &Path,
    host_ctx: Option<HostContext>,
    stream: bool,
) -> Result<(ExecutionSession, Option<thread::JoinHandle<()>>), CliError> {
    let executor = Executor::new();
    let mut handle = None;
    match mode {
        DeployMode::DryRun => executor
            .resume_dry_run(checkpoint_path)
            .map(|session| (session, None))
            .map_err(|e| CliError::InvalidInput(e.to_string())),
        DeployMode::Compose => {
            let host_ctx = host_ctx.ok_or_else(|| {
                CliError::InvalidInput("host context required for compose".to_string())
            })?;
            let client = ProcessSshClient::new();
            let sender = if stream {
                let (sender, receiver) = log_stream::create_log_stream();
                handle = Some(spawn_log_stream_thread(receiver));
                Some(sender)
            } else {
                None
            };
            executor
                .resume_compose(checkpoint_path, host_ctx, client, sender)
                .map(|session| (session, handle))
                .map_err(|e| CliError::InvalidInput(e.to_string()))
        }
        DeployMode::SshReadonly => {
            let host_ctx = host_ctx.ok_or_else(|| {
                CliError::InvalidInput("host context required for ssh-readonly".to_string())
            })?;
            let client = ProcessSshClient::new();
            executor
                .resume_ssh_readonly(checkpoint_path, host_ctx, client)
                .map(|session| (session, None))
                .map_err(|e| CliError::InvalidInput(e.to_string()))
        }
        DeployMode::DockerReadonly => {
            let host_ctx = host_ctx.ok_or_else(|| {
                CliError::InvalidInput("host context required for docker-readonly".to_string())
            })?;
            let client = ProcessSshClient::new();
            executor
                .resume_docker_readonly(checkpoint_path, host_ctx, client)
                .map(|session| (session, None))
                .map_err(|e| CliError::InvalidInput(e.to_string()))
        }
    }
}

fn attach_record_writer(session: ExecutionSession, meta: &ExecutionMeta) -> ExecutionSession {
    let exec_id = meta.execution_id.clone();
    let meta = meta.clone();
    let start_index = executions::load_records(&exec_id)
        .map(|records| records.len())
        .unwrap_or(0);
    let counter = Arc::new(AtomicUsize::new(start_index));
    session.with_progress_callback(move |record| {
        if let Err(err) = executions::append_record(&exec_id, record) {
            eprintln!("failed to persist record: {err}");
        }
        let index = counter.fetch_add(1, Ordering::SeqCst);
        if let Err(err) = append_ops_event(&meta, record, index) {
            eprintln!("failed to append ops event: {err}");
        }
    })
}

fn run_session_with_approvals(
    session: &mut ExecutionSession,
    meta: &ExecutionMeta,
    pause_on_approval: bool,
) -> Result<(), CliError> {
    loop {
        let records = session
            .run()
            .map_err(|e| CliError::InvalidInput(e.to_string()))?;
        session
            .save_checkpoint(&meta.execution_id, &meta.host_id, meta.environment)
            .map_err(|e| CliError::InvalidInput(e.to_string()))?;

        if let Some(step_id) = find_waiting_step(&records) {
            if pause_on_approval {
                println!("Execution paused on approval: {}", step_id);
                return Ok(());
            }
            if !prompt_yes_no(&format!("Approve step {step_id}? [y/N]: "))? {
                session
                    .reject_step(&step_id)
                    .map_err(|e| CliError::InvalidInput(e.to_string()))?;
                session
                    .save_checkpoint(&meta.execution_id, &meta.host_id, meta.environment)
                    .map_err(|e| CliError::InvalidInput(e.to_string()))?;
                continue;
            }
            prompt_admin_approval()?;
            session
                .approve_step(&step_id)
                .map_err(|e| CliError::InvalidInput(e.to_string()))?;
            session
                .save_checkpoint(&meta.execution_id, &meta.host_id, meta.environment)
                .map_err(|e| CliError::InvalidInput(e.to_string()))?;
            continue;
        }
        break;
    }
    Ok(())
}

fn build_execution_meta(
    execution_id: &str,
    host: &Option<Host>,
    plan: &DeploymentPlan,
) -> ExecutionMeta {
    let (host_id, host_address, environment) = match host {
        Some(host) => (host.id.clone(), host.address.clone(), host.environment),
        None => ("local".to_string(), "local".to_string(), Environment::Dev),
    };
    ExecutionMeta {
        execution_id: execution_id.to_string(),
        host_id,
        host_address,
        environment,
        plan: plan.clone(),
    }
}

fn project_for_action(action: &DeploymentAction) -> Option<String> {
    match action {
        DeploymentAction::ComposeUp { project_dir }
        | DeploymentAction::ComposeDown { project_dir } => Some(project_dir.clone()),
        DeploymentAction::NginxApply { project }
        | DeploymentAction::NginxRollback { project }
        | DeploymentAction::SslIssue { project }
        | DeploymentAction::SslRenew { project }
        | DeploymentAction::SslRollback { project } => Some(project.clone()),
        DeploymentAction::DbMigrate { plan_id } => Some(plan_id.clone()),
        _ => None,
    }
}

fn append_ops_event(
    meta: &ExecutionMeta,
    record: &ExecutionRecord,
    index: usize,
) -> Result<(), CliError> {
    let step = meta
        .plan
        .steps
        .iter()
        .find(|step| step.id == record.step_id);
    let (service_name, action, project) = match step {
        Some(step) => (
            step.service_name.clone(),
            Some(step.action.clone()),
            project_for_action(&step.action),
        ),
        None => ("unknown".to_string(), None, None),
    };
    let recorded_at = record
        .finished_at
        .or(record.started_at)
        .unwrap_or_else(current_timestamp_ms);
    let event = OpsEvent {
        id: format!("{}:{}:{}", meta.execution_id, index, record.step_id),
        execution_id: meta.execution_id.clone(),
        step_id: record.step_id.clone(),
        service_name,
        action,
        status: record.status.clone(),
        recorded_at,
        started_at: record.started_at,
        finished_at: record.finished_at,
        logs: record.logs.clone(),
        error: record.error.clone(),
        host_id: meta.host_id.clone(),
        host_address: meta.host_address.clone(),
        environment: meta.environment,
        project,
        trace_id: Some(meta.execution_id.clone()),
        project_id: None,
        scan_id: None,
    };

    let storage = create_storage_backend();
    storage.append_event(&event)?;
    let log_msg = format!(
        "Event: {:?} [Project: {:?}] [Host: {:?}] Status: {:?} Info: {:?}",
        event.step_id, event.project, event.host_id, event.status, event.logs
    );
    let _ = audit::write_audit_log("system", &log_msg);
    if event.project.is_some() && !event.service_name.is_empty() {
        let _ = audit::write_audit_log("behavior", &log_msg);
    }
    Ok(())
}

fn spawn_log_stream_thread(receiver: log_stream::LogStreamReceiver) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(msg) => {
                println!("[{}][{}] {}", msg.step_id, msg.level.as_str(), msg.message);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
    })
}

fn find_waiting_step(records: &[ExecutionRecord]) -> Option<String> {
    records
        .iter()
        .find(|record| record.status == ExecutionStatus::WaitingApproval)
        .map(|record| record.step_id.clone())
}

fn tail_records(path: &Path, follow: bool, step_filter: Option<&str>) -> Result<(), CliError> {
    let mut seen = 0usize;
    loop {
        let content = std::fs::read_to_string(path)?;
        let lines: Vec<&str> = content.lines().collect();
        for line in lines.iter().skip(seen) {
            let record: ExecutionRecord = match serde_json::from_str(line) {
                Ok(record) => record,
                Err(_) => continue,
            };
            if let Some(step) = step_filter {
                if record.step_id != step {
                    continue;
                }
            }
            render_record_logs(&record);
        }
        seen = lines.len();
        if !follow {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

fn render_record_logs(record: &ExecutionRecord) {
    for line in &record.logs {
        println!("[{}] {}", record.step_id, line);
    }
    if let Some(err) = &record.error {
        println!("[{}] error: {}", record.step_id, err);
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn new_execution_id() -> String {
    format!("exec-{}", current_timestamp_ms())
}

fn load_llm_provider() -> Result<Box<dyn llm::LlmProvider>, CliError> {
    let config = load_llm_config()?;
    llm::create_llm_provider(config)
        .map_err(|e| CliError::Config(format!("failed to create LLM provider: {e}")))
}

fn collect_log_inputs(inputs: &[String]) -> Result<Vec<String>, CliError> {
    let mut logs = Vec::new();
    for input in inputs {
        let path = PathBuf::from(input);
        if path.exists() && path.is_file() {
            let content = std::fs::read_to_string(&path)?;
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(200);
            for line in &lines[start..] {
                logs.push(line.to_string());
            }
        } else {
            logs.push(input.clone());
        }
    }
    Ok(logs)
}

fn map_system_metrics_to_perf(metrics: &SystemMetrics) -> PerformanceMetrics {
    let mut rx_total = 0u64;
    let mut tx_total = 0u64;
    for iface in &metrics.network.interfaces {
        rx_total = rx_total.saturating_add(iface.rx_bytes);
        tx_total = tx_total.saturating_add(iface.tx_bytes);
    }
    PerformanceMetrics {
        cpu_usage_percent: Some(metrics.cpu.usage_percent),
        memory_usage_mb: Some(metrics.memory.used_mb),
        memory_limit_mb: Some(metrics.memory.total_mb),
        network_rx_bytes: Some(rx_total),
        network_tx_bytes: Some(tx_total),
        request_count: None,
        error_rate: None,
        response_time_ms: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertStoreState {
    rules: Vec<AlertRule>,
    active: Vec<Alert>,
}

fn alert_store_path() -> Result<PathBuf, CliError> {
    Ok(agus_cli_core::config::ensure_home_dir()?.join("alert_store.json"))
}

fn load_alert_store() -> Result<AlertStoreState, CliError> {
    let path = alert_store_path()?;
    if !path.exists() {
        let state = AlertStoreState {
            rules: default_alert_rules(),
            active: Vec::new(),
        };
        save_alert_store(&state)?;
        return Ok(state);
    }
    let content = std::fs::read_to_string(path)?;
    let state = serde_json::from_str(&content)?;
    Ok(state)
}

fn save_alert_store(state: &AlertStoreState) -> Result<(), CliError> {
    let path = alert_store_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(path, content)?;
    Ok(())
}

fn default_alert_rules() -> Vec<AlertRule> {
    vec![
        AlertRule {
            id: "cpu_high".to_string(),
            name: "CPU usage high".to_string(),
            metric_type: MetricType::CpuUsage,
            threshold: 90.0,
            comparison: Comparison::GreaterThan,
            severity: AlertSeverity::Critical,
            enabled: true,
        },
        AlertRule {
            id: "memory_high".to_string(),
            name: "Memory usage high".to_string(),
            metric_type: MetricType::MemoryUsage,
            threshold: 85.0,
            comparison: Comparison::GreaterThan,
            severity: AlertSeverity::Warning,
            enabled: true,
        },
        AlertRule {
            id: "disk_full".to_string(),
            name: "Disk usage high".to_string(),
            metric_type: MetricType::DiskUsage,
            threshold: 95.0,
            comparison: Comparison::GreaterThan,
            severity: AlertSeverity::Critical,
            enabled: true,
        },
        AlertRule {
            id: "container_restart".to_string(),
            name: "Container restarts".to_string(),
            metric_type: MetricType::ContainerRestartCount,
            threshold: 5.0,
            comparison: Comparison::GreaterThan,
            severity: AlertSeverity::Error,
            enabled: true,
        },
    ]
}

fn parse_metric_type(value: &str) -> Result<MetricType, CliError> {
    match value.trim().to_lowercase().as_str() {
        "cpu" | "cpu_usage" => Ok(MetricType::CpuUsage),
        "memory" | "memory_usage" => Ok(MetricType::MemoryUsage),
        "disk" | "disk_usage" => Ok(MetricType::DiskUsage),
        "network_error" => Ok(MetricType::NetworkErrorRate),
        "container_restart" => Ok(MetricType::ContainerRestartCount),
        "container_uptime" => Ok(MetricType::ContainerUptime),
        other => Ok(MetricType::Custom(other.to_string())),
    }
}

fn parse_comparison(value: &str) -> Result<Comparison, CliError> {
    match value.trim().to_lowercase().as_str() {
        "gt" | "greater" | "greater_than" => Ok(Comparison::GreaterThan),
        "lt" | "less" | "less_than" => Ok(Comparison::LessThan),
        "eq" | "equal" => Ok(Comparison::Equal),
        "ne" | "not_equal" => Ok(Comparison::NotEqual),
        _ => Err(CliError::InvalidInput(
            "comparison must be gt|lt|eq|ne".to_string(),
        )),
    }
}

fn parse_severity(value: &str) -> Result<AlertSeverity, CliError> {
    match value.trim().to_lowercase().as_str() {
        "info" => Ok(AlertSeverity::Info),
        "warning" | "warn" => Ok(AlertSeverity::Warning),
        "error" => Ok(AlertSeverity::Error),
        "critical" => Ok(AlertSeverity::Critical),
        _ => Err(CliError::InvalidInput(
            "severity must be info|warning|error|critical".to_string(),
        )),
    }
}

fn evaluate_alerts_for_host(
    host: &Host,
    state: &mut AlertStoreState,
) -> Result<Vec<Alert>, CliError> {
    let target = exec::ssh_target_from_host(host);
    let client = ProcessSshClient::new();
    let metrics = collect_system_metrics(&client, &target, &host.id)
        .map_err(|e| CliError::InvalidInput(format!("metrics collection failed: {e}")))?;
    let mut new_alerts = evaluate_alerts(state, &build_host_alert_metrics(host, &metrics));
    if let Ok(containers) = container_health::check_all_containers_health(&client, &target, None) {
        for container in containers {
            let metrics = build_container_alert_metrics(host, &container);
            new_alerts.extend(evaluate_alerts(state, &metrics));
        }
    }
    Ok(new_alerts)
}

fn build_host_alert_metrics(host: &Host, metrics: &SystemMetrics) -> AlertMetrics {
    let disk_usage = metrics.disk.iter().map(|disk| disk.usage_percent).fold(
        None::<f64>,
        |acc, value| match acc {
            Some(prev) => Some(prev.max(value)),
            None => Some(value),
        },
    );
    let total_packets: u64 = metrics
        .network
        .interfaces
        .iter()
        .map(|iface| iface.rx_packets + iface.tx_packets)
        .sum();
    let total_errors: u64 = metrics
        .network
        .interfaces
        .iter()
        .map(|iface| iface.rx_errors + iface.tx_errors)
        .sum();
    let network_error_rate = if total_packets > 0 {
        Some((total_errors as f64 / total_packets as f64) * 100.0)
    } else {
        None
    };
    AlertMetrics {
        cpu_usage_percent: Some(metrics.cpu.usage_percent),
        memory_usage_percent: Some(metrics.memory.usage_percent),
        disk_usage_percent: disk_usage,
        network_error_rate,
        container_restart_count: None,
        container_uptime_seconds: None,
        custom_metrics: Default::default(),
        resource_id: Some(host.id.clone()),
        resource_type: Some("host".to_string()),
    }
}

fn build_container_alert_metrics(
    host: &Host,
    container: &container_health::ContainerHealthCheckResult,
) -> AlertMetrics {
    AlertMetrics {
        cpu_usage_percent: None,
        memory_usage_percent: None,
        disk_usage_percent: None,
        network_error_rate: None,
        container_restart_count: Some(container.health.restart_count),
        container_uptime_seconds: container.health.uptime_seconds,
        custom_metrics: Default::default(),
        resource_id: Some(format!("{}:{}", host.id, container.container_id)),
        resource_type: Some("container".to_string()),
    }
}

fn evaluate_alerts(state: &mut AlertStoreState, metrics: &AlertMetrics) -> Vec<Alert> {
    let mut new_alerts = Vec::new();
    for rule in &state.rules {
        if !rule.enabled {
            continue;
        }
        let value = match rule.metric_type {
            MetricType::CpuUsage => metrics.cpu_usage_percent,
            MetricType::MemoryUsage => metrics.memory_usage_percent,
            MetricType::DiskUsage => metrics.disk_usage_percent,
            MetricType::NetworkErrorRate => metrics.network_error_rate,
            MetricType::ContainerRestartCount => metrics.container_restart_count.map(|v| v as f64),
            MetricType::ContainerUptime => metrics.container_uptime_seconds.map(|v| v as f64),
            MetricType::Custom(ref key) => metrics.custom_metrics.get(key).cloned(),
        };
        let Some(value) = value else {
            continue;
        };
        let triggered = match rule.comparison {
            Comparison::GreaterThan => value > rule.threshold,
            Comparison::LessThan => value < rule.threshold,
            Comparison::Equal => (value - rule.threshold).abs() < 0.001,
            Comparison::NotEqual => (value - rule.threshold).abs() >= 0.001,
        };
        if !triggered {
            continue;
        }
        let resource_key = metrics.resource_id.as_deref().unwrap_or("global");
        let exists = state.active.iter().any(|alert| {
            let alert_resource = alert.resource_id.as_deref().unwrap_or("global");
            alert.rule_id == rule.id && alert_resource == resource_key
        });
        if exists {
            continue;
        }
        let alert = Alert {
            id: format!(
                "alert_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity,
            message: format!(
                "{} threshold {:.2} (value: {:.2})",
                rule.name, rule.threshold, value
            ),
            metric_value: value,
            threshold: rule.threshold,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            resource_id: metrics.resource_id.clone(),
            resource_type: metrics.resource_type.clone(),
            acknowledged: false,
        };
        state.active.push(alert.clone());
        new_alerts.push(alert);
    }
    new_alerts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemLogEntry {
    host_id: String,
    timestamp: u64,
    level: String,
    message: String,
    source: String,
}

fn get_system_logs(host_id: &str, lines: usize) -> Result<Vec<SystemLogEntry>, CliError> {
    let host = hosts::find_host(host_id)?;
    let target = exec::ssh_target_from_host(&host);
    let client = ProcessSshClient::new();
    let local_offset = local_timezone_offset();
    let remote_offset = fetch_remote_timezone_offset(&client, &target).unwrap_or(local_offset);

    let journalctl_available = client
        .execute(&target, "command -v journalctl")
        .map(|res| !res.stdout.trim().is_empty())
        .unwrap_or(false);

    if journalctl_available {
        let cmd_sudo = format!("sudo journalctl -n {} --no-pager --output=short-iso", lines);
        let output = client
            .execute(&target, &cmd_sudo)
            .map(|res| res.stdout)
            .or_else(|_| {
                let cmd = format!("journalctl -n {} --no-pager --output=short-iso", lines);
                client.execute(&target, &cmd).map(|res| res.stdout)
            });
        if let Ok(stdout) = output {
            let mut entries = Vec::new();
            for line in stdout.lines() {
                if let Some(entry) =
                    parse_system_log_line(line, host_id, local_offset, remote_offset)
                {
                    entries.push(entry);
                }
            }
            return Ok(entries);
        }
    }

    let syslog_output = fetch_syslog_output(&client, &target, lines)
        .map_err(|err| CliError::InvalidInput(format!("failed to read syslog: {err}")))?;
    let mut entries = Vec::new();
    for line in syslog_output.lines() {
        if let Some(entry) = parse_system_log_line(line, host_id, local_offset, remote_offset) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn local_timezone_offset() -> FixedOffset {
    FixedOffset::east_opt(Local::now().offset().local_minus_utc())
        .unwrap_or_else(|| FixedOffset::east_opt(0).expect("UTC offset should be valid"))
}

fn parse_timezone_offset(value: &str) -> Option<FixedOffset> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut sign = 1;
    let mut digits = trimmed;
    if let Some(rest) = trimmed.strip_prefix('+') {
        digits = rest;
    } else if let Some(rest) = trimmed.strip_prefix('-') {
        sign = -1;
        digits = rest;
    }
    let normalized = digits.replace(':', "");
    if normalized.len() != 4 {
        return None;
    }
    let hours: i32 = normalized.get(0..2)?.parse().ok()?;
    let minutes: i32 = normalized.get(2..4)?.parse().ok()?;
    let total_seconds = sign * (hours * 3600 + minutes * 60);
    FixedOffset::east_opt(total_seconds)
}

fn fetch_remote_timezone_offset(
    client: &ProcessSshClient,
    target: &agus_ssh::SshTarget,
) -> Option<FixedOffset> {
    let result = client.execute(target, "date +%z").ok()?;
    parse_timezone_offset(result.stdout.trim())
}

fn parse_journalctl_timestamp(
    value: &str,
    remote_offset: FixedOffset,
) -> Option<DateTime<FixedOffset>> {
    let trimmed = value.trim();
    let formats_with_offset = ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%z"];
    for format in formats_with_offset {
        if let Ok(dt) = DateTime::parse_from_str(trimmed, format) {
            return Some(dt);
        }
    }

    let formats_without_offset = ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"];
    for format in formats_without_offset {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, format) {
            return remote_offset.from_local_datetime(&naive).single();
        }
    }
    None
}

fn parse_syslog_timestamp(
    month: &str,
    day: &str,
    time: &str,
    remote_offset: FixedOffset,
) -> Option<DateTime<FixedOffset>> {
    let month = match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: u32 = day.parse().ok()?;
    let time = NaiveTime::parse_from_str(time, "%H:%M:%S").ok()?;
    let year = Utc::now().with_timezone(&remote_offset).year();
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let naive = NaiveDateTime::new(date, time);
    remote_offset.from_local_datetime(&naive).single()
}

fn split_log_source_and_message(content: &str) -> (String, String) {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return ("system".to_string(), String::new());
    }
    if let Some(colon_idx) = trimmed.find(':') {
        let prefix = trimmed[..colon_idx].trim();
        let message = trimmed[colon_idx + 1..].trim().to_string();
        let source = prefix
            .split_whitespace()
            .last()
            .unwrap_or(prefix)
            .to_string();
        (source, message)
    } else {
        ("system".to_string(), trimmed.to_string())
    }
}

fn parse_system_log_line(
    line: &str,
    host_id: &str,
    local_offset: FixedOffset,
    remote_offset: FixedOffset,
) -> Option<SystemLogEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (timestamp, content) = if trimmed.chars().take(4).all(|ch| ch.is_ascii_digit()) {
        let mut parts = trimmed.splitn(2, ' ');
        let timestamp_str = parts.next()?;
        let content = parts.next().unwrap_or("").trim_start();
        let dt = parse_journalctl_timestamp(timestamp_str, remote_offset)?;
        let timestamp = dt.with_timezone(&local_offset).timestamp();
        (timestamp as u64, content.to_string())
    } else {
        let mut parts = trimmed.split_whitespace();
        let month = parts.next()?;
        let day = parts.next()?;
        let time = parts.next()?;
        let content = parts.collect::<Vec<_>>().join(" ");
        let dt = parse_syslog_timestamp(month, day, time, remote_offset)?;
        let timestamp = dt.with_timezone(&local_offset).timestamp();
        (timestamp as u64, content)
    };

    let (source, message) = split_log_source_and_message(&content);
    let message_lower = message.to_lowercase();
    let level = if message_lower.contains("error") || message_lower.contains("fail") {
        "Error".to_string()
    } else if message_lower.contains("warn") {
        "Warning".to_string()
    } else {
        "Info".to_string()
    };

    Some(SystemLogEntry {
        host_id: host_id.to_string(),
        timestamp,
        level,
        message,
        source,
    })
}

fn fetch_syslog_output(
    client: &ProcessSshClient,
    target: &agus_ssh::SshTarget,
    lines: usize,
) -> Result<String, String> {
    let candidates = ["/var/log/syslog", "/var/log/messages"];
    for path in candidates {
        let cmd = format!("tail -n {} {}", lines, path);
        if let Ok(result) = client.execute(target, &cmd) {
            return Ok(result.stdout);
        }
        let cmd_sudo = format!("sudo {}", cmd);
        if let Ok(result) = client.execute(target, &cmd_sudo) {
            return Ok(result.stdout);
        }
    }
    Err("journalctl unavailable and syslog files not accessible".to_string())
}

fn get_container_logs(
    host_id: &str,
    container_id: &str,
    lines: Option<usize>,
    since: Option<u64>,
) -> Result<Vec<container_logs::ContainerLogEntry>, CliError> {
    let host = hosts::find_host(host_id)?;
    let target = exec::ssh_target_from_host(&host);
    let client = Arc::new(ProcessSshClient::new());
    let monitor = container_logs::SshContainerLogMonitor::new(client, target);
    monitor
        .get_logs(container_id, lines, since)
        .map_err(|e| CliError::InvalidInput(format!("container logs failed: {e}")))
}

fn run_repl() -> Result<(), CliError> {
    let mut input = String::new();
    let mut llm_provider: Option<Box<dyn llm::LlmProvider>> = None;
    loop {
        let ctx = context::load_context()?;
        let prompt = match &ctx.current_host {
            Some(host) => format!("agus@{host}> "),
            None => "agus> ".to_string(),
        };
        print!("{prompt}");
        io::stdout().flush()?;
        input.clear();
        if io::stdin().read_line(&mut input)? == 0 {
            break;
        }
        let line = input.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, "exit" | "quit") {
            break;
        }
        let (force_local, command_line) = if let Some(rest) = line.strip_prefix(":local ") {
            (true, rest.trim())
        } else if let Some(rest) = line.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, line)
        };
        if command_line.is_empty() {
            continue;
        }
        // 检测是否为中文自然语言输入
        if is_chinese_natural_language(command_line) {
            if let Err(err) = handle_llm_command(command_line, force_local, &mut llm_provider) {
                eprintln!("{}: {}", t("llm_error"), err);
            }
            continue;
        }

        let tokens = match shell_words::split(command_line) {
            Ok(tokens) => tokens,
            Err(err) => {
                eprintln!("{}: {}", t("invalid_input"), err);
                continue;
            }
        };
        if tokens.is_empty() {
            continue;
        }
        let first = tokens[0].as_str();
        if matches!(
            first,
            "exec"
                | "host"
                | "context"
                | "ssh"
                | "plan"
                | "deploy"
                | "logs"
                | "monitor"
                | "alert"
                | "container"
                | "security"
                | "diagnose"
        ) {
            let mut argv = vec!["agus".to_string()];
            argv.extend(tokens.clone());
            match AgusCli::try_parse_from(argv) {
                Ok(cli) => {
                    if let Some(command) = cli.command {
                        let _ = handle_command(command)?;
                    }
                }
                Err(err) => eprintln!("{err}"),
            }
            continue;
        }
        if risk::is_traditional_command(first) {
            if let Err(err) = handle_traditional_command(command_line, &tokens, force_local, false)
            {
                eprintln!("error: {err}");
            }
            continue;
        }
        if let Err(err) = handle_llm_command(command_line, force_local, &mut llm_provider) {
            eprintln!("error: {err}");
        }
    }
    Ok(())
}

fn handle_traditional_command(
    line: &str,
    tokens: &[String],
    force_local: bool,
    pre_approved: bool,
) -> Result<(), CliError> {
    let first = tokens[0].as_str();
    if first.eq_ignore_ascii_case("ssh") {
        let target = tokens.get(1).cloned().unwrap_or_default();
        if target.is_empty() {
            return Err(CliError::InvalidInput("ssh requires a target".to_string()));
        }
        let args = tokens.iter().skip(2).cloned().collect::<Vec<_>>();
        return handle_ssh(SshCommand { target, args });
    }

    if first.eq_ignore_ascii_case("scp")
        || first.eq_ignore_ascii_case("rsync")
        || first.eq_ignore_ascii_case("sftp")
    {
        let ctx = context::load_context()?;
        let args = rewrite_transfer_args(tokens, ctx.current_host.as_deref())?;
        run_command_inherit(first, &args)?;
        return Ok(());
    }

    if (first.eq_ignore_ascii_case("cp") || first.eq_ignore_ascii_case("mv"))
        && has_remote_path(tokens)
    {
        let ctx = context::load_context()?;
        let mut args = tokens.to_vec();
        args[0] = "scp".to_string();
        let rewritten = rewrite_transfer_args(&args, ctx.current_host.as_deref())?;
        run_command_inherit("scp", &rewritten)?;
        return Ok(());
    }

    let risk_level = risk::classify_command(line);
    enforce_approval(risk_level, pre_approved)?;

    let local_only = risk::is_local_only_command(first);
    let prefer_local = risk::is_default_local_command(first);
    let target_host = resolve_target(force_local, None, local_only || prefer_local)?;
    let is_interactive = risk::is_interactive_command(line);

    log_exec_event("repl", line, risk_level, true, &target_host);

    if is_dry_run() {
        print_dry_run(&target_host, line);
        return Ok(());
    }

    if let Some(host) = target_host {
        if is_interactive {
            run_remote_interactive(&host, line)?;
        } else {
            let output = exec::execute_remote(&host, line, true)?;
            print_output(&output.stdout, &output.stderr);
        }
        Ok(())
    } else {
        if is_interactive {
            let _ = exec::execute_local_interactive(line, &[], true)?;
            Ok(())
        } else {
            let output = exec::execute_local(line, &[], true)?;
            print_output(&output.stdout, &output.stderr);
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct StoredLlmConfig {
    provider: Option<String>,
    api_key: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LlmCliResponse {
    command: Option<String>,
    explanation: Option<String>,
    risk_level: Option<String>,
    answer: Option<String>,
    description_zh: Option<String>,  // 中文描述
    agus_command: Option<String>,   // 转换后的 agus 命令
}

// 检测输入是否为中文自然语言
fn is_chinese_natural_language(input: &str) -> bool {
    // 检测是否包含中文字符
    input.chars().any(|c| {
        matches!(c,
            '\u{4e00}'..='\u{9fff}' |  // CJK 统一汉字
            '\u{3400}'..='\u{4dbf}' |  // CJK 扩展 A
            '\u{20000}'..='\u{2a6df}'  // CJK 扩展 B
        )
    }) && !input.trim().starts_with("agus ") && !input.trim().starts_with("exec ") && 
         !risk::is_traditional_command(input.split_whitespace().next().unwrap_or(""))
}

// 获取用户语言偏好（从环境变量或系统语言）
fn get_user_language() -> Language {
    // 优先检查环境变量
    if let Ok(lang) = std::env::var("AGUS_LANG") {
        match lang.to_lowercase().as_str() {
            "zh" | "zh_cn" | "zh-cn" => return Language::Zh,
            "en" | "en_us" | "en-us" => return Language::En,
            _ => {}
        }
    }
    
    // 检查系统语言环境
    if let Ok(lang) = std::env::var("LANG") {
        if lang.to_lowercase().contains("zh") {
            return Language::Zh;
        }
    }
    
    // 默认英文
    Language::En
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Zh,
    En,
}

// 中文输出消息
fn t(key: &'static str) -> &'static str {
    let lang = get_user_language();
    match lang {
        Language::Zh => match key {
            "suggested_command" => "建议执行的命令",
            "explanation" => "说明",
            "risk_level" => "风险级别",
            "detected_risk" => "检测到的风险",
            "execute_confirm" => "是否执行建议的命令？(y/N)",
            "command_executed" => "命令已执行",
            "command_cancelled" => "命令已取消",
            "invalid_input" => "无效输入",
            "llm_error" => "LLM 请求失败",
            "no_command_generated" => "未能生成命令",
            "chinese_input_detected" => "检测到中文输入，正在转换为 agus 命令...",
            _ => key,
        },
        Language::En => match key {
            "suggested_command" => "Suggested command",
            "explanation" => "Explanation",
            "risk_level" => "Risk level",
            "detected_risk" => "Detected risk",
            "execute_confirm" => "Execute suggested command? [y/N]",
            "command_executed" => "Command executed",
            "command_cancelled" => "Command cancelled",
            "invalid_input" => "Invalid input",
            "llm_error" => "LLM request failed",
            "no_command_generated" => "No command generated",
            "chinese_input_detected" => "Detected Chinese input, converting to agus command...",
            _ => key,
        },
    }
}

fn handle_llm_command(
    line: &str,
    force_local: bool,
    llm_provider: &mut Option<Box<dyn llm::LlmProvider>>,
) -> Result<(), CliError> {
    if llm_provider.is_none() {
        let config = load_llm_config()?;
        let provider = llm::create_llm_provider(config)
            .map_err(|err| CliError::Config(format!("failed to create LLM provider: {err}")))?;
        *llm_provider = Some(provider);
    }

    let is_chinese = is_chinese_natural_language(line);
    if is_chinese {
        println!("{}", t("chinese_input_detected"));
    }

    let ctx = context::load_context()?;
    let prompt = build_llm_prompt(line, force_local, ctx.current_host.as_deref(), is_chinese);
    let response = llm_provider
        .as_ref()
        .expect("llm provider ready")
        .complete_prompt(&prompt)
        .map_err(|err| CliError::Config(format!("{}: {}", t("llm_error"), err)))?;

    if let Some(parsed) = parse_llm_response(&response) {
        // 优先显示 answer（如果不需要执行命令）
        if let Some(answer) = parsed
            .answer
            .as_ref()
            .filter(|text| !text.trim().is_empty())
        {
            println!("{answer}");
            return Ok(());
        }

        // 优先使用 agus_command，如果没有则使用 command
        let command_to_execute = parsed
            .agus_command
            .as_ref()
            .or(parsed.command.as_ref())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        // 显示说明
        if let Some(explanation) = parsed
            .description_zh
            .as_ref()
            .or(parsed.explanation.as_ref())
            .filter(|text| !text.trim().is_empty())
        {
            println!("{}: {}", t("explanation"), explanation);
        }

        if let Some(cmd) = command_to_execute {
            let risk_level = risk::classify_command(cmd);
            
            // 显示建议的命令
            println!("{}: {}", t("suggested_command"), cmd);
            
            // 显示风险级别
            if let Some(level) = parsed
                .risk_level
                .as_ref()
                .filter(|text| !text.trim().is_empty())
            {
                println!("{}: {}", t("risk_level"), level);
            }
            println!("{}: {}", t("detected_risk"), risk_level_label(risk_level));
            
            // 确认执行
            if prompt_yes_no(&format!("{} ", t("execute_confirm")))? {
                println!("{}", t("command_executed"));
                return execute_generated_command(cmd, force_local, true);
            } else {
                println!("{}", t("command_cancelled"));
                return Ok(());
            }
        } else {
            println!("{}", t("no_command_generated"));
        }
        return Ok(());
    }

    // 如果无法解析 JSON，直接输出原始响应
    println!("{}", response.trim());
    Ok(())
}

fn execute_generated_command(
    command_line: &str,
    force_local: bool,
    pre_approved: bool,
) -> Result<(), CliError> {
    let tokens = shell_words::split(command_line)
        .map_err(|err| CliError::InvalidInput(format!("invalid command: {err}")))?;
    if tokens.is_empty() {
        return Ok(());
    }
    let first = tokens[0].as_str();

    if matches!(
        first,
        "exec"
            | "host"
            | "context"
            | "ssh"
            | "plan"
            | "deploy"
            | "logs"
            | "monitor"
            | "alert"
            | "container"
            | "security"
            | "diagnose"
    ) {
        let mut argv = vec!["agus".to_string()];
        argv.extend(tokens);
        match AgusCli::try_parse_from(argv) {
            Ok(cli) => {
                if let Some(command) = cli.command {
                    let _ = handle_command(command)?;
                }
                return Ok(());
            }
            Err(err) => return Err(CliError::InvalidInput(err.to_string())),
        }
    }

    if risk::is_traditional_command(first) {
        return handle_traditional_command(command_line, &tokens, force_local, pre_approved);
    }

    let risk_level = risk::classify_command(command_line);
    enforce_approval(risk_level, pre_approved)?;

    let local_only = risk::is_local_only_command(first);
    let prefer_local = risk::is_default_local_command(first);
    let target_host = resolve_target(force_local, None, local_only || prefer_local)?;
    let is_interactive = risk::is_interactive_command(command_line);

    log_exec_event("llm", command_line, risk_level, true, &target_host);

    if is_dry_run() {
        print_dry_run(&target_host, command_line);
        return Ok(());
    }

    if let Some(host) = target_host {
        if is_interactive {
            run_remote_interactive(&host, command_line)?;
        } else {
            let output = exec::execute_remote(&host, command_line, true)?;
            print_output(&output.stdout, &output.stderr);
        }
        Ok(())
    } else if is_interactive {
        let _ = exec::execute_local_interactive(command_line, &[], true)?;
        Ok(())
    } else {
        let output = exec::execute_local(command_line, &[], true)?;
        print_output(&output.stdout, &output.stderr);
        Ok(())
    }
}

fn parse_llm_response(raw: &str) -> Option<LlmCliResponse> {
    if let Ok(parsed) = serde_json::from_str::<LlmCliResponse>(raw) {
        return Some(parsed);
    }
    let trimmed = raw.trim();
    let json_start = trimmed.find('{')?;
    let json_end = trimmed.rfind('}')?;
    if json_start >= json_end {
        return None;
    }
    serde_json::from_str::<LlmCliResponse>(&trimmed[json_start..=json_end]).ok()
}

fn build_llm_prompt(input: &str, force_local: bool, current_host: Option<&str>, is_chinese: bool) -> String {
    let host_hint = current_host.unwrap_or("local");
    let lang_instruction = if is_chinese {
        "用户使用中文输入，请用中文回复。"
    } else {
        "User is using English, please reply in English."
    };
    
    let agus_commands_help = r#"
Available agus commands:
- agus host list/add/remove/show: 主机管理
- agus context use/show/clear: 上下文管理
- agus exec --host <host> -- <command>: 执行命令
- agus deploy run --plan <plan> --host <host>: 部署执行
- agus logs system/container/ops: 日志查询
- agus monitor metrics --host <host>: 监控指标
- agus alert rules/active/evaluate: 告警管理
- agus container health/logs: 容器健康检查
- agus security scan-junk/vulnerability: 安全扫描
- agus diagnose error/performance: 诊断分析
"#;
    
    if is_chinese {
        format!(
            "你是一位 SRE 运维助手，帮助用户将自然语言转换为安全的 agus CLI 命令。\n\
{lang_instruction}\n\
当前上下文主机: {host_hint}\n\
强制本地执行: {force_local}\n\
用户请求: {input}\n\n\
{agus_commands_help}\n\n\
请返回 JSON 格式，包含以下字段：\n\
- command: 要执行的 shell 命令（如果没有则留空）\n\
- agus_command: 转换后的 agus CLI 命令（优先使用 agus 命令，如果用户意图可以用 agus 命令实现）\n\
- explanation: 简短说明或步骤（中文）\n\
- description_zh: 中文描述\n\
- risk_level: 风险级别 low|medium|high\n\
- answer: 如果不需要执行命令，提供回答（中文）\n\n\
如果 force_local 为 true，不要在命令中包含 ssh/scp/rsync。\n\
优先将用户意图转换为 agus 命令，而不是原始 shell 命令。"
        )
    } else {
        format!(
            "You are an SRE copilot helping craft safe shell commands.\n\
{lang_instruction}\n\
Current context host: {host_hint}\n\
Force local execution: {force_local}\n\
User request: {input}\n\n\
{agus_commands_help}\n\n\
Return JSON only with keys:\n\
- command: a single shell command to run (empty if none)\n\
- agus_command: converted agus CLI command (prefer agus commands if user intent can be achieved)\n\
- explanation: short reason or steps\n\
- description_zh: Chinese description\n\
- risk_level: low|medium|high\n\
- answer: if no command should be run\n\n\
If force local is true, do not include ssh/scp/rsync in the command.\n\
Prefer converting user intent to agus commands rather than raw shell commands."
        )
    }
}

fn load_llm_config() -> Result<llm::LlmConfig, CliError> {
    let base = agus_cli_core::config::agus_home()?;
    let path = base.join("llm_config.json");
    let stored = if path.exists() {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str::<StoredLlmConfig>(&content).unwrap_or_default()
    } else {
        StoredLlmConfig::default()
    };

    let provider_name = stored.provider.unwrap_or_else(|| "openai".to_string());
    let provider = parse_llm_provider(&provider_name)?;
    let model = stored
        .model
        .unwrap_or_else(|| default_llm_model(&provider_name).to_string());
    let base_url = stored.base_url.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    let mut api_key = std::env::var("AGUS_LLM_API_KEY").unwrap_or_default();
    if api_key.trim().is_empty() {
        api_key = stored.api_key.unwrap_or_default();
    }
    if api_key.trim().is_empty() {
        let store = create_secret_store();
        if let Ok(secret) = store.get_secret("llm.api_key") {
            api_key = secret;
        }
    }

    if api_key.trim().is_empty() && provider != LlmProviderType::Ollama {
        return Err(CliError::Config(
            "LLM API key not configured. Set AGUS_LLM_API_KEY or configure it in the GUI."
                .to_string(),
        ));
    }

    Ok(llm::LlmConfig {
        provider,
        api_key,
        model,
        base_url,
    })
}

fn parse_llm_provider(provider: &str) -> Result<LlmProviderType, CliError> {
    let normalized = provider.trim().to_lowercase();
    match normalized.as_str() {
        "openai" => Ok(LlmProviderType::OpenAI),
        "claude" => Ok(LlmProviderType::Claude),
        "gemini" => Ok(LlmProviderType::Gemini),
        "openrouter" => Ok(LlmProviderType::OpenRouter),
        "alibaba-qwen" => Ok(LlmProviderType::AlibabaQwen),
        "deepseek" => Ok(LlmProviderType::DeepSeek),
        "zhipu" => Ok(LlmProviderType::Zhipu),
        "ollama" => Ok(LlmProviderType::Ollama),
        _ => Err(CliError::Config(format!(
            "unknown LLM provider: {provider}"
        ))),
    }
}

fn default_llm_model(provider: &str) -> &'static str {
    match provider.trim().to_lowercase().as_str() {
        "ollama" => "llama3",
        "claude" => "claude-3-sonnet-20240229",
        "gemini" => "gemini-1.5-pro",
        _ => "gpt-4",
    }
}

fn risk_level_label(level: risk::RiskLevel) -> &'static str {
    let lang = get_user_language();
    match (lang, level) {
        (Language::Zh, risk::RiskLevel::Low) => "低",
        (Language::Zh, risk::RiskLevel::Medium) => "中",
        (Language::Zh, risk::RiskLevel::High) => "高",
        (Language::En, risk::RiskLevel::Low) => "low",
        (Language::En, risk::RiskLevel::Medium) => "medium",
        (Language::En, risk::RiskLevel::High) => "high",
    }
}

fn resolve_target(
    force_local: bool,
    explicit_host: Option<&str>,
    prefer_local: bool,
) -> Result<Option<Host>, CliError> {
    if force_local {
        return Ok(None);
    }
    if let Some(host) = explicit_host {
        return Ok(Some(hosts::find_host(host)?));
    }
    if prefer_local {
        return Ok(None);
    }
    let ctx = context::load_context()?;
    if let Some(host_id) = ctx.current_host {
        return Ok(Some(hosts::find_host(&host_id)?));
    }
    Ok(None)
}

fn enforce_approval(risk_level: risk::RiskLevel, yes: bool) -> Result<(), CliError> {
    match risk_level {
        risk::RiskLevel::High => prompt_admin_approval(),
        risk::RiskLevel::Medium => {
            if yes {
                Ok(())
            } else if prompt_yes_no("Command requires confirmation. Proceed? [y/N]: ")? {
                Ok(())
            } else {
                Err(CliError::InvalidInput("execution cancelled".to_string()))
            }
        }
        risk::RiskLevel::Low => Ok(()),
    }
}

fn prompt_admin_approval() -> Result<(), CliError> {
    if is_automation_mode() {
        let result = prompt_admin_approval_from_env();
        if result.is_ok() {
            log_cli_event("cli approval method=automation result=success");
        }
        return result;
    }
    if let Some(config) = admin::load_admin_config()? {
        for _ in 0..3 {
            let username = prompt_line("Admin username: ")?;
            let password = rpassword::prompt_password("Admin password: ")?;
            if username == config.username
                && admin::verify_password(&config.password_hash, &password)?
            {
                log_cli_event(&format!(
                    "cli approval method=admin user={} result=success",
                    username
                ));
                return Ok(());
            }
            eprintln!("Invalid credentials.");
        }
        return Err(CliError::AuthFailed);
    }
    let result = prompt_system_approval();
    if result.is_ok() {
        log_cli_event("cli approval method=system result=success");
    }
    result
}

fn prompt_admin_approval_from_env() -> Result<(), CliError> {
    let username = std::env::var("AGUS_CLI_APPROVAL_USERNAME")
        .map_err(|_| CliError::InvalidInput("missing AGUS_CLI_APPROVAL_USERNAME".to_string()))?;
    let password = std::env::var("AGUS_CLI_APPROVAL_PASSWORD")
        .map_err(|_| CliError::InvalidInput("missing AGUS_CLI_APPROVAL_PASSWORD".to_string()))?;
    let config = admin::load_admin_config()?.ok_or(CliError::AdminMissing)?;
    if username != config.username {
        return Err(CliError::AuthFailed);
    }
    if admin::verify_password(&config.password_hash, &password)? {
        Ok(())
    } else {
        Err(CliError::AuthFailed)
    }
}

fn prompt_system_approval() -> Result<(), CliError> {
    #[cfg(not(unix))]
    {
        return Err(CliError::AdminMissing);
    }
    #[cfg(unix)]
    {
        let current_user = current_username()?;
        let username = prompt_line(&format!(
            "Admin username (system, current: {}): ",
            current_user
        ))?;
        let effective_user = if username.trim().is_empty() {
            current_user
        } else {
            username
        };
        if effective_user != current_username()? {
            return Err(CliError::AuthFailed);
        }
        let password = rpassword::prompt_password("System password: ")?;
        verify_system_password(&password)?;
        Ok(())
    }
}

#[cfg(unix)]
fn verify_system_password(password: &str) -> Result<(), CliError> {
    if find_executable("sudo").is_none() {
        return Err(CliError::InvalidInput(
            "sudo is not available; run `asda admin set` or set AGUS_CLI_APPROVAL_USERNAME/AGUS_CLI_APPROVAL_PASSWORD"
                .to_string(),
        ));
    }
    let mut child = Command::new("sudo")
        .args(["-S", "-k", "-v", "-p", ""])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(format!("{password}\n").as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::AuthFailed)
    }
}

fn current_username() -> Result<String, CliError> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .map_err(|_| CliError::Config("current username not found".to_string()))
}

fn prompt_yes_no(label: &str) -> Result<bool, CliError> {
    let mut input = String::new();
    print!("{label}");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let value = input.trim().to_lowercase();
    // 支持中文确认：y/yes/是/确认
    Ok(matches!(value.as_str(), "y" | "yes" | "是" | "确认" | "ok" | "okay"))
}

fn prompt_line(label: &str) -> Result<String, CliError> {
    let mut input = String::new();
    print!("{label}");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn parse_environment(value: &str) -> Result<Environment, CliError> {
    match value.to_lowercase().as_str() {
        "dev" => Ok(Environment::Dev),
        "test" => Ok(Environment::Test),
        "staging" => Ok(Environment::Staging),
        "prod" => Ok(Environment::Prod),
        _ => Err(CliError::InvalidInput(format!(
            "unknown environment: {value}"
        ))),
    }
}

fn print_output(stdout: &str, stderr: &str) {
    if !stdout.trim().is_empty() {
        print!("{stdout}");
    }
    if !stderr.trim().is_empty() {
        eprint!("{stderr}");
    }
}

fn join_tokens(tokens: &[String]) -> String {
    tokens.join(" ")
}

fn exit_code(status: i32) -> i32 {
    if status < 0 {
        1
    } else {
        status
    }
}

fn build_passthrough_args(target: &str, args: &[String]) -> Vec<String> {
    let mut cmd_args = Vec::new();
    cmd_args.push(target.to_string());
    cmd_args.extend_from_slice(args);
    cmd_args
}

fn run_ssh_with_host(host: &Host, extra_args: &[String]) -> Result<(), CliError> {
    let mut args = Vec::new();
    if host.port != 22 {
        args.push("-p".to_string());
        args.push(host.port.to_string());
    }
    if let Some(identity) = &host.identity_file {
        args.push("-i".to_string());
        args.push(identity.to_string());
    }
    let host_spec = format!("{}@{}", host.user, host.address);
    args.push(host_spec);
    args.extend_from_slice(extra_args);

    if let Some(password) = &host.password {
        if let Some(sshpass) = find_executable("sshpass") {
            let mut sshpass_args = vec!["-p".to_string(), password.clone(), "ssh".to_string()];
            sshpass_args.extend(args);
            run_command_inherit(&sshpass, &sshpass_args)?;
            return Ok(());
        }
        eprintln!("sshpass not available; falling back to interactive ssh.");
        if !args.iter().any(|arg| arg == "-tt") {
            args.insert(0, "-tt".to_string());
        }
        run_command_inherit("ssh", &args)?;
        return Ok(());
    }

    run_command_inherit("ssh", &args)?;
    Ok(())
}

fn run_remote_interactive(host: &Host, command: &str) -> Result<(), CliError> {
    let mut args = Vec::new();
    args.push("-tt".to_string());
    if host.port != 22 {
        args.push("-p".to_string());
        args.push(host.port.to_string());
    }
    if let Some(identity) = &host.identity_file {
        args.push("-i".to_string());
        args.push(identity.to_string());
    }
    let host_spec = format!("{}@{}", host.user, host.address);
    args.push(host_spec);
    args.push(command.to_string());

    if let Some(password) = &host.password {
        if let Some(sshpass) = find_executable("sshpass") {
            let mut sshpass_args = vec!["-p".to_string(), password.clone(), "ssh".to_string()];
            sshpass_args.extend(args);
            run_command_inherit(&sshpass, &sshpass_args)?;
            return Ok(());
        }
        eprintln!("sshpass not available; falling back to interactive ssh.");
        run_command_inherit("ssh", &args)?;
        return Ok(());
    }

    run_command_inherit("ssh", &args)?;
    Ok(())
}

fn run_command_inherit(command: &str, args: &[String]) -> Result<(), CliError> {
    if is_dry_run() {
        print_dry_run_command(command, args);
        return Ok(());
    }
    ensure_command_available(command)?;
    let status = Command::new(command).args(args).status()?;
    if !status.success() {
        return Err(CliError::InvalidInput(format!(
            "command exited with status: {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

fn rewrite_transfer_args(
    tokens: &[String],
    preferred_host: Option<&str>,
) -> Result<Vec<String>, CliError> {
    let hosts_list = hosts::load_hosts()?;
    let mut args = Vec::new();
    for (idx, token) in tokens.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        if let Some((prefix, path)) = token.split_once(':') {
            if prefix.is_empty() {
                let host_id = preferred_host
                    .ok_or_else(|| CliError::InvalidInput("no host context set".to_string()))?;
                let host = hosts_list
                    .iter()
                    .find(|item| item.id == host_id)
                    .ok_or_else(|| CliError::InvalidInput(format!("host not found: {host_id}")))?;
                args.push(format!("{}@{}:{}", host.user, host.address, path));
                continue;
            }
            if !prefix.contains('@') {
                if let Some(host) = hosts_list.iter().find(|item| item.id == prefix) {
                    args.push(format!("{}@{}:{}", host.user, host.address, path));
                    continue;
                }
            }
        }
        args.push(token.clone());
    }
    Ok(args)
}

fn has_remote_path(tokens: &[String]) -> bool {
    tokens.iter().skip(1).any(|token| token.contains(":/"))
}

fn is_transfer_command(cmd: &str) -> bool {
    cmd.eq_ignore_ascii_case("scp")
        || cmd.eq_ignore_ascii_case("rsync")
        || cmd.eq_ignore_ascii_case("sftp")
}

fn is_copy_command(cmd: &str) -> bool {
    cmd.eq_ignore_ascii_case("cp") || cmd.eq_ignore_ascii_case("mv")
}

fn find_executable(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return candidate.to_str().map(|s| s.to_string());
        }
    }
    None
}

fn ensure_command_available(command: &str) -> Result<(), CliError> {
    let path = std::path::Path::new(command);
    if command.contains(std::path::MAIN_SEPARATOR) || path.is_absolute() {
        if path.exists() {
            return Ok(());
        }
        return Err(CliError::InvalidInput(format!(
            "command not found: {}",
            command
        )));
    }
    if find_executable(command).is_some() {
        return Ok(());
    }
    Err(CliError::InvalidInput(format!(
        "command not found: {} (ensure it is installed and on PATH)",
        command
    )))
}

fn is_dry_run() -> bool {
    matches!(
        std::env::var("AGUS_CLI_DRY_RUN")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn is_automation_mode() -> bool {
    matches!(
        std::env::var("AGUS_CLI_AUTOMATION")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn print_dry_run(target_host: &Option<Host>, command: &str) {
    match target_host {
        Some(host) => println!(
            "DRY-RUN: ssh {}@{} -p {} -- {}",
            host.user, host.address, host.port, command
        ),
        None => println!("DRY-RUN: {}", command),
    }
}

fn print_dry_run_command(command: &str, args: &[String]) {
    if args.is_empty() {
        println!("DRY-RUN: {}", command);
    } else {
        println!("DRY-RUN: {} {}", command, args.join(" "));
    }
}

fn log_exec_event(
    source: &str,
    command_line: &str,
    risk_level: risk::RiskLevel,
    shell: bool,
    target_host: &Option<Host>,
) {
    let target = match target_host {
        Some(host) => format!(
            "remote host_id={} host={} user={} port={}",
            host.id, host.address, host.user, host.port
        ),
        None => "local".to_string(),
    };
    let risk_label = match risk_level {
        risk::RiskLevel::Low => "low",
        risk::RiskLevel::Medium => "medium",
        risk::RiskLevel::High => "high",
    };
    let log_msg = format!(
        "cli {source} target={target} risk={risk_label} dry_run={} shell={} cmd=\"{}\"",
        is_dry_run(),
        shell,
        command_line
    );
    log_cli_event(&log_msg);
}

fn log_cli_event(message: &str) {
    let _ = audit::write_audit_log("system", message);
}

const SHELL_INIT_SCRIPT: &str = r#"# Agus shell integration (zsh/bash)
# Usage:
#   eval "$(agus shell init --shell zsh)"
#   agus-mode
#   asda-mode
#   agus-mode-off

_agus_exec_cmds=(
  ssh scp rsync sftp ls cp mv rm mkdir rmdir chmod chown chgrp ln stat find tar gzip zip unzip
  tmux screen nohup bg fg jobs crontab at
  ps top htop pgrep pkill kill nice ulimit uname uptime hostname date timedatectl df du free mount umount
  ping traceroute curl wget nc telnet ss netstat lsof ip ifconfig dig nslookup
  systemctl service journalctl dmesg
  apt apt-get yum dnf apk rpm dpkg
  docker docker-compose podman nerdctl
  kubectl helm
  ansible ansible-playbook terraform
  git
  brew port mas softwareupdate launchctl log scutil networksetup diskutil pmset system_profiler spctl csrutil
  defaults dscl dsconfigad sysctl nvram osascript open security xattr codesign pkgutil installer mdfind mdutil airport
)

_agus_tty_cmds=(
  cat less head tail grep awk sed cut sort uniq
)

_asda_cmds=(admin config secrets policy audit doctor daemon unlock)

agus-mode() {
  agus-mode-off
  export AGUS_MODE=agus
  __agus_exec_tty() {
    local cmd="$1"
    shift
    if [ -t 0 ]; then
      command agus exec -- "${cmd}" "$@"
    else
      command "${cmd}" "$@"
    fi
  }
  for cmd in "${_agus_exec_cmds[@]}"; do
    alias "${cmd}=agus exec -- ${cmd}"
  done
  for cmd in "${_agus_tty_cmds[@]}"; do
    eval "${cmd}() { __agus_exec_tty ${cmd} \"\$@\"; }"
  done
  alias "ssh=agus ssh"
  echo "agus mode enabled"
}

asda-mode() {
  agus-mode-off
  export AGUS_MODE=asda
  for cmd in "${_asda_cmds[@]}"; do
    alias "${cmd}=asda ${cmd}"
  done
  echo "asda mode enabled"
}

agus-mode-off() {
  unset AGUS_MODE
  for cmd in "${_agus_exec_cmds[@]}"; do
    unalias "${cmd}" 2>/dev/null
  done
  for cmd in "${_agus_tty_cmds[@]}"; do
    unset -f "${cmd}" 2>/dev/null
  done
  for cmd in "${_asda_cmds[@]}"; do
    unalias "${cmd}" 2>/dev/null
  done
  unalias ssh 2>/dev/null
  unset -f __agus_exec_tty 2>/dev/null
}
"#;
