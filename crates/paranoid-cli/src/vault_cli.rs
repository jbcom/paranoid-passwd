use paranoid_core::{CharsetSpec, FrameworkId, GenerationReport, ParanoidRequest, VERSION};
use paranoid_vault::{
    NewLoginRecord, UpdateLoginRecord, init_vault, read_vault_header, unlock_vault,
    unlock_vault_with_certificate, unlock_vault_with_device,
};
use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::PathBuf,
};

pub fn run(args: &[OsString]) -> anyhow::Result<i32> {
    let invocation = parse_vault_args(args)?;
    match &invocation.command {
        VaultCommand::Help => {
            print_usage(io::stdout())?;
            Ok(0)
        }
        VaultCommand::Init => {
            if !matches!(&invocation.auth, VaultAuth::PasswordEnv(_)) {
                return Err(anyhow::anyhow!(
                    "vault init requires a recovery secret via PARANOID_MASTER_PASSWORD or --password-env"
                ));
            }
            let master_password = read_master_password(invocation.password_env())?;
            let header = init_vault(&invocation.path, &master_password)?;
            println!(
                "initialized\t{}\tformat={}\tkeyslots={}",
                invocation.path.display(),
                header.format_version,
                header.keyslots.len()
            );
            Ok(0)
        }
        VaultCommand::Keyslots => {
            let header = read_vault_header(&invocation.path)?;
            for keyslot in header.keyslots {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    keyslot.id,
                    keyslot.kind.as_str(),
                    keyslot.label.unwrap_or_default(),
                    keyslot.wrap_algorithm,
                    keyslot.certificate_fingerprint_sha256.unwrap_or_default()
                );
            }
            Ok(0)
        }
        VaultCommand::List => {
            let vault = unlock_vault_for_invocation(&invocation)?;
            for item in vault.list_items()? {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    item.id,
                    item.kind.as_str(),
                    item.title,
                    item.username,
                    item.url.unwrap_or_default(),
                    item.updated_at_epoch
                );
            }
            Ok(0)
        }
        VaultCommand::Show { id } => {
            let vault = unlock_vault_for_invocation(&invocation)?;
            let item = vault.get_item(id)?;
            print_item(&item)?;
            Ok(0)
        }
        VaultCommand::Add { record } => {
            let vault = unlock_vault_for_invocation(&invocation)?;
            let item = vault.add_login(record.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::Update { id, update } => {
            let vault = unlock_vault_for_invocation(&invocation)?;
            let item = vault.update_login(id, update.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::Delete { id } => {
            let vault = unlock_vault_for_invocation(&invocation)?;
            vault.delete_item(id)?;
            println!("deleted\t{id}");
            Ok(0)
        }
        VaultCommand::AddCertSlot { cert_path, label } => {
            let cert_pem = fs::read(cert_path)?;
            let mut vault = unlock_vault_for_invocation(&invocation)?;
            let keyslot = vault.add_certificate_keyslot(cert_pem.as_slice(), label.clone())?;
            println!(
                "{}\t{}\t{}",
                keyslot.id,
                keyslot.wrap_algorithm,
                keyslot.certificate_fingerprint_sha256.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::AddDeviceSlot { label } => {
            let mut vault = unlock_vault_for_invocation(&invocation)?;
            let keyslot = vault.add_device_keyslot(label.clone())?;
            println!(
                "{}\t{}\t{}",
                keyslot.id,
                keyslot.wrap_algorithm,
                keyslot.label.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::GenerateStore {
            request,
            title,
            username,
            url,
            notes,
            quiet,
        } => {
            if request.count != 1 {
                return Err(anyhow::anyhow!(
                    "vault generate-store only supports --count 1 to avoid ambiguous storage"
                ));
            }
            let vault = unlock_vault_for_invocation(&invocation)?;
            let (report, item) = vault.generate_and_store(
                request,
                title.clone(),
                username.clone(),
                url.clone(),
                notes.clone(),
            )?;
            print_generated_passwords(&report)?;
            if !*quiet {
                eprintln!("stored: {}", item.id);
            }
            Ok(0)
        }
    }
}

struct VaultInvocation {
    path: PathBuf,
    auth: VaultAuth,
    device_slot: Option<String>,
    command: VaultCommand,
}

enum VaultAuth {
    PasswordEnv(String),
    Certificate {
        cert_path: PathBuf,
        key_path: PathBuf,
        key_passphrase_env: Option<String>,
    },
}

impl VaultInvocation {
    fn password_env(&self) -> &str {
        match &self.auth {
            VaultAuth::PasswordEnv(env_name) => env_name.as_str(),
            VaultAuth::Certificate { .. } => "PARANOID_MASTER_PASSWORD",
        }
    }
}

enum VaultCommand {
    Help,
    Init,
    Keyslots,
    List,
    Show {
        id: String,
    },
    Add {
        record: NewLoginRecord,
    },
    Update {
        id: String,
        update: UpdateLoginRecord,
    },
    Delete {
        id: String,
    },
    AddCertSlot {
        cert_path: PathBuf,
        label: Option<String>,
    },
    AddDeviceSlot {
        label: Option<String>,
    },
    GenerateStore {
        request: ParanoidRequest,
        title: String,
        username: String,
        url: Option<String>,
        notes: Option<String>,
        quiet: bool,
    },
}

fn parse_vault_args(args: &[OsString]) -> anyhow::Result<VaultInvocation> {
    let mut path = default_vault_path();
    let mut password_env = "PARANOID_MASTER_PASSWORD".to_string();
    let mut cert_path = None;
    let mut key_path = None;
    let mut key_passphrase_env = None;
    let mut device_slot = None;
    let mut command: Option<String> = None;
    let mut command_args = Vec::new();
    let mut iter = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" if command.is_none() => {
                command = Some("help".to_string());
                break;
            }
            "--path" if command.is_none() => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--path requires a value"))?;
                path = PathBuf::from(value);
            }
            "--password-env" if command.is_none() => {
                password_env = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--password-env requires a value"))?;
            }
            "--cert" if command.is_none() => {
                cert_path = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--cert requires a value"))?,
                ));
            }
            "--key" if command.is_none() => {
                key_path = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--key requires a value"))?,
                ));
            }
            "--key-passphrase-env" if command.is_none() => {
                key_passphrase_env = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--key-passphrase-env requires a value"))?,
                );
            }
            "--device-slot" if command.is_none() => {
                device_slot = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--device-slot requires a value"))?,
                );
            }
            value if command.is_none() => {
                command = Some(value.to_string());
            }
            value => command_args.push(value.to_string()),
        }
    }

    let command = match command.as_deref().unwrap_or("help") {
        "help" => VaultCommand::Help,
        "init" => VaultCommand::Init,
        "keyslots" => VaultCommand::Keyslots,
        "list" => VaultCommand::List,
        "show" => parse_show(command_args.as_slice())?,
        "add" => parse_add(command_args.as_slice())?,
        "update" => parse_update(command_args.as_slice())?,
        "delete" => parse_delete(command_args.as_slice())?,
        "add-cert-slot" => parse_add_cert_slot(command_args.as_slice())?,
        "add-device-slot" => parse_add_device_slot(command_args.as_slice())?,
        "generate-store" => parse_generate_store(command_args.as_slice())?,
        other => return Err(anyhow::anyhow!("unknown vault subcommand: {other}")),
    };

    if device_slot.is_some() && cert_path.is_some() {
        return Err(anyhow::anyhow!(
            "--device-slot cannot be combined with certificate-backed unlock"
        ));
    }

    let auth = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => VaultAuth::Certificate {
            cert_path,
            key_path,
            key_passphrase_env,
        },
        (None, None) => VaultAuth::PasswordEnv(password_env),
        _ => {
            return Err(anyhow::anyhow!(
                "--cert and --key must be provided together for certificate-backed unlock"
            ));
        }
    };

    Ok(VaultInvocation {
        path,
        auth,
        device_slot,
        command,
    })
}

fn parse_show(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--id" => {
                id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .to_string(),
                );
            }
            other => return Err(anyhow::anyhow!("unexpected vault show argument: {other}")),
        }
    }
    Ok(VaultCommand::Show {
        id: id.ok_or_else(|| anyhow::anyhow!("vault show requires --id"))?,
    })
}

fn parse_add(args: &[String]) -> anyhow::Result<VaultCommand> {
    let record = parse_login_record(args)?;
    Ok(VaultCommand::Add { record })
}

fn parse_update(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut update = UpdateLoginRecord::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--id" => {
                id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .to_string(),
                );
            }
            "--title" => {
                update.title = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--title requires a value"))?
                        .to_string(),
                );
            }
            "--username" => {
                update.username = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--username requires a value"))?
                        .to_string(),
                );
            }
            "--password" => {
                update.password = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--password requires a value"))?
                        .to_string(),
                );
            }
            "--url" => {
                update.url = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--url requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-url" => update.url = Some(None),
            "--notes" => {
                update.notes = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--notes requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-notes" => update.notes = Some(None),
            other => return Err(anyhow::anyhow!("unexpected vault update argument: {other}")),
        }
    }
    Ok(VaultCommand::Update {
        id: id.ok_or_else(|| anyhow::anyhow!("vault update requires --id"))?,
        update,
    })
}

fn parse_delete(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--id" => {
                id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .to_string(),
                );
            }
            other => return Err(anyhow::anyhow!("unexpected vault delete argument: {other}")),
        }
    }
    Ok(VaultCommand::Delete {
        id: id.ok_or_else(|| anyhow::anyhow!("vault delete requires --id"))?,
    })
}

fn parse_add_cert_slot(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut cert_path = None;
    let mut label = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--cert" => {
                cert_path = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--cert requires a value"))?,
                ));
            }
            "--label" => {
                label = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--label requires a value"))?
                        .to_string(),
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault add-cert-slot argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::AddCertSlot {
        cert_path: cert_path
            .ok_or_else(|| anyhow::anyhow!("vault add-cert-slot requires --cert"))?,
        label,
    })
}

fn parse_add_device_slot(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut label = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--label" => {
                label = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--label requires a value"))?
                        .to_string(),
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault add-device-slot argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::AddDeviceSlot { label })
}

fn parse_generate_store(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut request = ParanoidRequest::default();
    let mut quiet = false;
    let mut charset_spec: Option<String> = None;
    let mut title = None;
    let mut username = None;
    let mut url = None;
    let mut notes = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--length" | "-l" => {
                request.length = parse_usize_arg(iter.next(), "--length")?;
            }
            "--count" | "-c" => {
                request.count = parse_usize_arg(iter.next(), "--count")?;
            }
            "--charset" | "-s" => {
                charset_spec = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--charset requires a value"))?
                        .to_string(),
                );
            }
            "--batch-size" => request.batch_size = parse_usize_arg(iter.next(), "--batch-size")?,
            "--require-lower" => {
                request.requirements.min_lowercase =
                    parse_usize_arg(iter.next(), "--require-lower")?;
            }
            "--require-upper" => {
                request.requirements.min_uppercase =
                    parse_usize_arg(iter.next(), "--require-upper")?;
            }
            "--require-digit" => {
                request.requirements.min_digits = parse_usize_arg(iter.next(), "--require-digit")?;
            }
            "--require-symbol" => {
                request.requirements.min_symbols =
                    parse_usize_arg(iter.next(), "--require-symbol")?;
            }
            "--framework" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--framework requires a value"))?;
                for value in raw
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    let framework = FrameworkId::parse(value)
                        .ok_or_else(|| anyhow::anyhow!("unknown framework: {value}"))?;
                    if !request.selected_frameworks.contains(&framework) {
                        request.selected_frameworks.push(framework);
                    }
                }
            }
            "--quiet" => quiet = true,
            "--title" => {
                title = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--title requires a value"))?
                        .to_string(),
                );
            }
            "--username" => {
                username = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--username requires a value"))?
                        .to_string(),
                );
            }
            "--url" => {
                url = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--url requires a value"))?
                        .to_string(),
                );
            }
            "--notes" => {
                notes = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--notes requires a value"))?
                        .to_string(),
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault generate-store argument: {other}"
                ));
            }
        }
    }

    if let Some(charset) = charset_spec {
        request.charset = CharsetSpec::NamedOrLiteral(charset);
    }

    Ok(VaultCommand::GenerateStore {
        request,
        title: title.ok_or_else(|| anyhow::anyhow!("vault generate-store requires --title"))?,
        username: username
            .ok_or_else(|| anyhow::anyhow!("vault generate-store requires --username"))?,
        url,
        notes,
        quiet,
    })
}

fn parse_login_record(args: &[String]) -> anyhow::Result<NewLoginRecord> {
    let mut title = None;
    let mut username = None;
    let mut password = None;
    let mut url = None;
    let mut notes = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--title" => {
                title = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--title requires a value"))?
                        .to_string(),
                );
            }
            "--username" => {
                username = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--username requires a value"))?
                        .to_string(),
                );
            }
            "--password" => {
                password = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--password requires a value"))?
                        .to_string(),
                );
            }
            "--url" => {
                url = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--url requires a value"))?
                        .to_string(),
                );
            }
            "--notes" => {
                notes = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--notes requires a value"))?
                        .to_string(),
                );
            }
            other => return Err(anyhow::anyhow!("unexpected vault add argument: {other}")),
        }
    }

    Ok(NewLoginRecord {
        title: title.ok_or_else(|| anyhow::anyhow!("vault add requires --title"))?,
        username: username.ok_or_else(|| anyhow::anyhow!("vault add requires --username"))?,
        password: password.ok_or_else(|| anyhow::anyhow!("vault add requires --password"))?,
        url,
        notes,
    })
}

fn parse_usize_arg(next: Option<&String>, flag: &str) -> anyhow::Result<usize> {
    next.ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))?
        .parse()
        .map_err(anyhow::Error::from)
}

fn read_master_password(env_name: &str) -> anyhow::Result<String> {
    let value = env::var(env_name).map_err(|_| {
        anyhow::anyhow!("set {env_name} in the environment before running vault commands")
    })?;
    if value.is_empty() {
        return Err(anyhow::anyhow!("{env_name} must not be empty"));
    }
    Ok(value)
}

fn read_optional_env(env_name: &str) -> anyhow::Result<Option<String>> {
    match env::var(env_name) {
        Ok(value) => {
            if value.is_empty() {
                return Err(anyhow::anyhow!("{env_name} must not be empty"));
            }
            Ok(Some(value))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow::Error::from(error)),
    }
}

fn unlock_vault_for_invocation(
    invocation: &VaultInvocation,
) -> anyhow::Result<paranoid_vault::UnlockedVault> {
    if let Some(slot_id) = invocation.device_slot.as_deref() {
        return unlock_vault_with_device(&invocation.path, Some(slot_id))
            .map_err(anyhow::Error::from);
    }

    match &invocation.auth {
        VaultAuth::PasswordEnv(env_name) => match read_master_password(env_name.as_str()) {
            Ok(master_password) => {
                unlock_vault(&invocation.path, &master_password).map_err(anyhow::Error::from)
            }
            Err(password_error) => match unlock_vault_with_device(&invocation.path, None) {
                Ok(vault) => Ok(vault),
                Err(device_error) => Err(password_error
                    .context(format!("device-bound fallback unavailable: {device_error}"))),
            },
        },
        VaultAuth::Certificate {
            cert_path,
            key_path,
            key_passphrase_env,
        } => {
            let cert_pem = fs::read(cert_path)?;
            let key_pem = fs::read(key_path)?;
            let key_passphrase = match key_passphrase_env {
                Some(env_name) => read_optional_env(env_name.as_str())?,
                None => None,
            };
            unlock_vault_with_certificate(
                &invocation.path,
                cert_pem.as_slice(),
                key_pem.as_slice(),
                key_passphrase.as_deref(),
            )
            .map_err(anyhow::Error::from)
        }
    }
}

fn default_vault_path() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg)
            .join("paranoid-passwd")
            .join("vault.sqlite");
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("paranoid-passwd")
            .join("vault.sqlite");
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        return PathBuf::from(profile)
            .join("AppData")
            .join("Local")
            .join("paranoid-passwd")
            .join("vault.sqlite");
    }
    PathBuf::from("paranoid-passwd.vault.sqlite")
}

fn print_usage(mut out: impl Write) -> io::Result<()> {
    writeln!(
        out,
        "\
paranoid-passwd {VERSION}

Usage:
  paranoid-passwd vault [--path FILE] [--password-env VAR] [--device-slot ID] [--cert CERT.pem --key KEY.pem [--key-passphrase-env VAR]] <subcommand> [OPTIONS]

Subcommands:
  init
  keyslots
  list
  show --id ID
  add --title TITLE --username USER --password SECRET [--url URL] [--notes NOTES]
  update --id ID [--title TITLE] [--username USER] [--password SECRET] [--url URL|--clear-url] [--notes NOTES|--clear-notes]
  delete --id ID
  add-cert-slot --cert CERT.pem [--label LABEL]
  add-device-slot [--label LABEL]
  generate-store [generator flags...] --title TITLE --username USER [--url URL] [--notes NOTES]

Unlock sources:
  By default vault commands read the recovery secret from PARANOID_MASTER_PASSWORD.
  Override with --password-env VAR.
  If the recovery secret is absent and the vault has exactly one device-bound keyslot, commands fall back to passwordless device unlock.
  Use --device-slot ID to select a specific device-bound keyslot explicitly.
  Certificate-backed unlock requires --cert and --key together before the subcommand.
  If the private key PEM is encrypted, pass --key-passphrase-env VAR.
"
    )
}

fn print_item(item: &paranoid_vault::VaultItem) -> anyhow::Result<()> {
    println!("id: {}", item.id);
    println!("kind: {}", item.kind.as_str());
    println!("created_at_epoch: {}", item.created_at_epoch);
    println!("updated_at_epoch: {}", item.updated_at_epoch);
    match &item.payload {
        paranoid_vault::VaultItemPayload::Login(login) => {
            println!("title: {}", login.title);
            println!("username: {}", login.username);
            println!("password: {}", login.password);
            println!("url: {}", login.url.as_deref().unwrap_or(""));
            println!("notes: {}", login.notes.as_deref().unwrap_or(""));
        }
    }
    Ok(())
}

fn print_generated_passwords(report: &GenerationReport) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for password in &report.passwords {
        writeln!(handle, "{}", password.value)?;
    }
    handle.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vault_args_supports_certificate_auth() {
        let invocation = parse_vault_args(&[
            OsString::from("--cert"),
            OsString::from("unlock-cert.pem"),
            OsString::from("--key"),
            OsString::from("unlock-key.pem"),
            OsString::from("--key-passphrase-env"),
            OsString::from("PARANOID_KEY_PASSPHRASE"),
            OsString::from("list"),
        ])
        .expect("parse");

        match invocation.auth {
            VaultAuth::Certificate {
                cert_path,
                key_path,
                key_passphrase_env,
            } => {
                assert_eq!(cert_path, PathBuf::from("unlock-cert.pem"));
                assert_eq!(key_path, PathBuf::from("unlock-key.pem"));
                assert_eq!(
                    key_passphrase_env.as_deref(),
                    Some("PARANOID_KEY_PASSPHRASE")
                );
            }
            VaultAuth::PasswordEnv(_) => panic!("expected certificate auth"),
        }
        assert!(matches!(invocation.command, VaultCommand::List));
    }

    #[test]
    fn parse_add_cert_slot_requires_slot_certificate() {
        let command = parse_vault_args(&[
            OsString::from("add-cert-slot"),
            OsString::from("--cert"),
            OsString::from("recipient.pem"),
            OsString::from("--label"),
            OsString::from("laptop"),
        ])
        .expect("parse");

        match command.command {
            VaultCommand::AddCertSlot { cert_path, label } => {
                assert_eq!(cert_path, PathBuf::from("recipient.pem"));
                assert_eq!(label.as_deref(), Some("laptop"));
            }
            _ => panic!("expected add-cert-slot command"),
        }
    }

    #[test]
    fn parse_add_device_slot_supports_label() {
        let command = parse_vault_args(&[
            OsString::from("add-device-slot"),
            OsString::from("--label"),
            OsString::from("daily"),
        ])
        .expect("parse");

        match command.command {
            VaultCommand::AddDeviceSlot { label } => {
                assert_eq!(label.as_deref(), Some("daily"));
            }
            _ => panic!("expected add-device-slot command"),
        }
    }

    #[test]
    fn parse_vault_args_supports_explicit_device_slot_unlock() {
        let invocation = parse_vault_args(&[
            OsString::from("--device-slot"),
            OsString::from("device-abc123"),
            OsString::from("list"),
        ])
        .expect("parse");

        assert_eq!(invocation.device_slot.as_deref(), Some("device-abc123"));
        assert!(matches!(invocation.command, VaultCommand::List));
    }
}
