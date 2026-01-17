use agus_core_domain::Host;
use agus_storage::{create_storage_backend, StorageBackend};

use crate::{config, CliError};

fn storage() -> Result<Box<dyn StorageBackend>, CliError> {
    let _ = config::ensure_home_dir()?;
    Ok(create_storage_backend())
}

pub fn load_hosts() -> Result<Vec<Host>, CliError> {
    let storage = storage()?;
    Ok(storage.load_hosts()?)
}

pub fn save_hosts(hosts: &[Host]) -> Result<(), CliError> {
    let storage = storage()?;
    storage.save_hosts(hosts)?;
    Ok(())
}

pub fn find_host(host_id: &str) -> Result<Host, CliError> {
    let hosts = load_hosts()?;
    hosts
        .into_iter()
        .find(|host| host.id == host_id || host.address == host_id)
        .ok_or_else(|| CliError::InvalidInput(format!("host not found: {host_id}")))
}

pub fn upsert_host(host: Host) -> Result<bool, CliError> {
    let mut hosts = load_hosts()?;
    if let Some(existing) = hosts.iter_mut().find(|item| item.id == host.id) {
        *existing = host;
        save_hosts(&hosts)?;
        return Ok(true);
    }
    hosts.push(host);
    save_hosts(&hosts)?;
    Ok(false)
}

pub fn remove_host(host_id: &str) -> Result<bool, CliError> {
    let mut hosts = load_hosts()?;
    let original_len = hosts.len();
    hosts.retain(|host| host.id != host_id);
    if hosts.len() == original_len {
        return Ok(false);
    }
    save_hosts(&hosts)?;
    Ok(true)
}
