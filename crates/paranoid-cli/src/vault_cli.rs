use paranoid_core::{CharsetSpec, FrameworkId, GenerationReport, ParanoidRequest, VERSION};
use paranoid_vault::{NewLoginRecord, UpdateLoginRecord, init_vault, unlock_vault};
use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};

pub fn run(args: &[OsString]) -> anyhow::Result<i32> {
    let invocation = parse_vault_args(args)?;
    match invocation.command {
        VaultCommand::Help => {
            print_usage(io::stdout())?;
            Ok(0)
        }
        VaultCommand::Init => {
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let header = init_vault(&invocation.path, &master_password)?;
            println!(
                "initialized\t{}\tformat={}\tkeyslots={}",
                invocation.path.display(),
                header.format_version,
                header.keyslots.len()
            );
            Ok(0)
        }
        VaultCommand::List => {
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let vault = unlock_vault(&invocation.path, &master_password)?;
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
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let vault = unlock_vault(&invocation.path, &master_password)?;
            let item = vault.get_item(&id)?;
            print_item(&item)?;
            Ok(0)
        }
        VaultCommand::Add { record } => {
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let vault = unlock_vault(&invocation.path, &master_password)?;
            let item = vault.add_login(record)?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::Update { id, update } => {
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let vault = unlock_vault(&invocation.path, &master_password)?;
            let item = vault.update_login(&id, update)?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::Delete { id } => {
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let vault = unlock_vault(&invocation.path, &master_password)?;
            vault.delete_item(&id)?;
            println!("deleted\t{id}");
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
            let master_password = read_master_password(invocation.password_env.as_str())?;
            let vault = unlock_vault(&invocation.path, &master_password)?;
            let (report, item) = vault.generate_and_store(&request, title, username, url, notes)?;
            print_generated_passwords(&report)?;
            if !quiet {
                eprintln!("stored: {}", item.id);
            }
            Ok(0)
        }
    }
}

struct VaultInvocation {
    path: PathBuf,
    password_env: String,
    command: VaultCommand,
}

enum VaultCommand {
    Help,
    Init,
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
            value if command.is_none() => {
                command = Some(value.to_string());
            }
            value => command_args.push(value.to_string()),
        }
    }

    let command = match command.as_deref().unwrap_or("help") {
        "help" => VaultCommand::Help,
        "init" => VaultCommand::Init,
        "list" => VaultCommand::List,
        "show" => parse_show(command_args.as_slice())?,
        "add" => parse_add(command_args.as_slice())?,
        "update" => parse_update(command_args.as_slice())?,
        "delete" => parse_delete(command_args.as_slice())?,
        "generate-store" => parse_generate_store(command_args.as_slice())?,
        other => return Err(anyhow::anyhow!("unknown vault subcommand: {other}")),
    };

    Ok(VaultInvocation {
        path,
        password_env,
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
  paranoid-passwd vault [--path FILE] [--password-env VAR] <subcommand> [OPTIONS]

Subcommands:
  init
  list
  show --id ID
  add --title TITLE --username USER --password SECRET [--url URL] [--notes NOTES]
  update --id ID [--title TITLE] [--username USER] [--password SECRET] [--url URL|--clear-url] [--notes NOTES|--clear-notes]
  delete --id ID
  generate-store [generator flags...] --title TITLE --username USER [--url URL] [--notes NOTES]

Master password:
  Vault commands read the master password from PARANOID_MASTER_PASSWORD by default.
  Override with --password-env VAR.
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
