use paranoid_core::{CharsetSpec, FrameworkId, GenerationReport, ParanoidRequest, VERSION};
use paranoid_vault::{
    GenerateStoreLoginRecord, NewCardRecord, NewIdentityRecord, NewLoginRecord,
    NewSecureNoteRecord, UpdateCardRecord, UpdateIdentityRecord, UpdateLoginRecord,
    UpdateSecureNoteRecord, VaultAuth, VaultItemFilter, VaultItemKind, VaultOpenOptions,
    default_vault_path, init_vault, inspect_certificate_pem, inspect_vault_backup,
    inspect_vault_transfer, read_master_password, read_vault_header, restore_vault_backup,
    unlock_vault_for_options,
};
use std::{
    ffi::OsString,
    fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use crate::vault_tui;

pub fn run(args: &[OsString]) -> anyhow::Result<i32> {
    let invocation = parse_vault_args(args)?;
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    if should_launch_tui(&invocation, interactive) {
        return vault_tui::run(invocation.open_options.clone()).map(|_| 0);
    }

    let command = invocation.command.unwrap_or(VaultCommand::Help);
    match &command {
        VaultCommand::Help => {
            print_usage(io::stdout())?;
            Ok(0)
        }
        VaultCommand::Init => {
            if !matches!(&invocation.open_options.auth, VaultAuth::PasswordEnv(_)) {
                return Err(anyhow::anyhow!(
                    "vault init requires a recovery secret via PARANOID_MASTER_PASSWORD or --password-env"
                ));
            }
            let master_password = read_master_password(invocation.open_options.password_env())?;
            let header = init_vault(&invocation.open_options.path, &master_password)?;
            println!(
                "initialized\t{}\tformat={}\tkeyslots={}",
                invocation.open_options.path.display(),
                header.format_version,
                header.keyslots.len()
            );
            Ok(0)
        }
        VaultCommand::Keyslots => {
            let header = read_vault_header(&invocation.open_options.path)?;
            let posture = header.recovery_posture();
            let keyslot_health = header.keyslot_health_summaries();
            println!(
                "posture\trecovery={}\tcertificate={}\trecommended={}\tpassword={}\tmnemonic={}\tdevice={}\tcertificate_slots={}",
                posture.has_recovery_path,
                posture.has_certificate_path,
                posture.meets_recommended_posture,
                posture.password_recovery_slots,
                posture.mnemonic_recovery_slots,
                posture.device_bound_slots,
                posture.certificate_wrapped_slots
            );
            for recommendation in header.recovery_recommendations() {
                println!("recommendation\t{recommendation}");
            }
            for (keyslot, health) in header.keyslots.into_iter().zip(keyslot_health.into_iter()) {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    keyslot.id,
                    keyslot.kind.as_str(),
                    keyslot.label.unwrap_or_default(),
                    keyslot.wrap_algorithm,
                    keyslot.certificate_fingerprint_sha256.unwrap_or_default(),
                    keyslot.certificate_subject.unwrap_or_default(),
                    keyslot.certificate_not_before.unwrap_or_default(),
                    keyslot.certificate_not_after.unwrap_or_default(),
                    if health.healthy {
                        "healthy"
                    } else {
                        "attention"
                    }
                );
                for warning in health.warnings {
                    println!("health_warning\t{warning}");
                }
            }
            Ok(0)
        }
        VaultCommand::InspectKeyslot { id } => {
            let header = read_vault_header(&invocation.open_options.path)?;
            let posture = header.recovery_posture();
            let keyslot = header
                .keyslots
                .iter()
                .find(|keyslot| keyslot.id == *id)
                .ok_or_else(|| anyhow::anyhow!("unknown keyslot: {id}"))?;
            println!("id\t{}", keyslot.id);
            println!("kind\t{}", keyslot.kind.as_str());
            println!("label\t{}", keyslot.label.as_deref().unwrap_or(""));
            println!("wrapped_by_os_keystore\t{}", keyslot.wrapped_by_os_keystore);
            println!("wrap_algorithm\t{}", keyslot.wrap_algorithm);
            println!(
                "recovery_posture\trecovery={}\tcertificate={}\trecommended={}",
                posture.has_recovery_path,
                posture.has_certificate_path,
                posture.meets_recommended_posture
            );
            if let Some(fingerprint) = &keyslot.certificate_fingerprint_sha256 {
                println!("certificate_fingerprint_sha256\t{fingerprint}");
            }
            if let Some(subject) = &keyslot.certificate_subject {
                println!("certificate_subject\t{subject}");
            }
            if let Some(not_before) = &keyslot.certificate_not_before {
                println!("certificate_not_before\t{not_before}");
            }
            if let Some(not_after) = &keyslot.certificate_not_after {
                println!("certificate_not_after\t{not_after}");
            }
            if let Some(language) = &keyslot.mnemonic_language {
                println!("mnemonic_language\t{language}");
            }
            if let Some(words) = keyslot.mnemonic_words {
                println!("mnemonic_words\t{words}");
            }
            if let Some(service) = &keyslot.device_service {
                println!("device_service\t{service}");
            }
            if let Some(account) = &keyslot.device_account {
                println!("device_account\t{account}");
            }
            let health = header.assess_keyslot_health(id)?;
            println!("healthy\t{}", health.healthy);
            for warning in health.warnings {
                println!("health_warning\t{warning}");
            }
            let impact = header.assess_keyslot_removal(id)?;
            println!(
                "removal_requires_confirmation\t{}",
                impact.requires_explicit_confirmation
            );
            for warning in impact.warnings {
                println!("warning\t{warning}");
            }
            Ok(0)
        }
        VaultCommand::List { query } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let items = vault.list_items_filtered(query)?;
            for item in items {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    item.id,
                    item.kind.as_str(),
                    item.title,
                    item.subtitle,
                    item.location.unwrap_or_default(),
                    item.folder.unwrap_or_default(),
                    item.updated_at_epoch,
                    item.duplicate_password_count
                );
            }
            Ok(0)
        }
        VaultCommand::Show { id } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.get_item(id)?;
            let duplicate_password_count = vault.duplicate_password_count(id)?;
            print_item(&item, duplicate_password_count)?;
            Ok(0)
        }
        VaultCommand::Add { record } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.add_login(record.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::AddNote { record } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.add_secure_note(record.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::AddCard { record } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.add_card(record.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::AddIdentity { record } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.add_identity(record.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::Update { id, update } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.update_login(id, update.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::UpdateNote { id, update } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.update_secure_note(id, update.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::UpdateCard { id, update } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.update_card(id, update.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::UpdateIdentity { id, update } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let item = vault.update_identity(id, update.clone())?;
            println!("{}", item.id);
            Ok(0)
        }
        VaultCommand::ExportBackup { output } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let written = vault.export_backup(output)?;
            println!("{}", written.display());
            Ok(0)
        }
        VaultCommand::ExportTransfer {
            output,
            filter,
            package_password_env,
            package_cert_path,
        } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let package_password = package_password_env
                .as_deref()
                .map(read_master_password)
                .transpose()?;
            let package_certificate = package_cert_path.as_ref().map(fs::read).transpose()?;
            let written = vault.export_transfer_package(
                output,
                filter,
                package_password.as_deref(),
                package_certificate.as_deref(),
            )?;
            println!("{}", written.display());
            Ok(0)
        }
        VaultCommand::InspectBackup { input } => {
            let summary = inspect_vault_backup(input)?;
            println!("backup_format_version\t{}", summary.backup_format_version);
            println!("vault_format_version\t{}", summary.vault_format_version);
            println!("header_format_version\t{}", summary.header_format_version);
            println!("exported_at_epoch\t{}", summary.exported_at_epoch);
            println!(
                "restorable_by_current_build\t{}",
                summary.restorable_by_current_build
            );
            println!("item_count\t{}", summary.item_count);
            println!("login_count\t{}", summary.login_count);
            println!("secure_note_count\t{}", summary.secure_note_count);
            println!("card_count\t{}", summary.card_count);
            println!("identity_count\t{}", summary.identity_count);
            println!("keyslot_count\t{}", summary.keyslot_count);
            println!(
                "recovery_posture\trecovery={}\tcertificate={}\trecommended={}\tpassword={}\tmnemonic={}\tdevice={}\tcertificate_slots={}",
                summary.recovery_posture.has_recovery_path,
                summary.recovery_posture.has_certificate_path,
                summary.recovery_posture.meets_recommended_posture,
                summary.recovery_posture.password_recovery_slots,
                summary.recovery_posture.mnemonic_recovery_slots,
                summary.recovery_posture.device_bound_slots,
                summary.recovery_posture.certificate_wrapped_slots
            );
            for warning in summary.warnings {
                println!("warning\t{warning}");
            }
            for keyslot in summary.keyslots {
                println!(
                    "keyslot\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    keyslot.id,
                    keyslot.kind.as_str(),
                    keyslot.label.unwrap_or_default(),
                    keyslot.wrap_algorithm,
                    keyslot.certificate_fingerprint_sha256.unwrap_or_default(),
                    keyslot.certificate_subject.unwrap_or_default(),
                    keyslot.certificate_not_before.unwrap_or_default(),
                    keyslot.certificate_not_after.unwrap_or_default()
                );
            }
            Ok(0)
        }
        VaultCommand::InspectTransfer { input } => {
            let summary = inspect_vault_transfer(input)?;
            println!(
                "transfer_format_version\t{}",
                summary.transfer_format_version
            );
            println!(
                "source_vault_format_version\t{}",
                summary.source_vault_format_version
            );
            println!("exported_at_epoch\t{}", summary.exported_at_epoch);
            println!(
                "importable_by_current_build\t{}",
                summary.importable_by_current_build
            );
            println!("item_count\t{}", summary.item_count);
            println!("login_count\t{}", summary.login_count);
            println!("secure_note_count\t{}", summary.secure_note_count);
            println!("card_count\t{}", summary.card_count);
            println!("identity_count\t{}", summary.identity_count);
            println!("has_recovery_path\t{}", summary.has_recovery_path);
            println!("has_certificate_path\t{}", summary.has_certificate_path);
            println!(
                "filter\tquery={}\tkind={}\tfolder={}\ttag={}",
                summary.filter.query.unwrap_or_default(),
                summary
                    .filter
                    .kind
                    .as_ref()
                    .map(VaultItemKind::as_str)
                    .unwrap_or_default(),
                summary.filter.folder.unwrap_or_default(),
                summary.filter.tag.unwrap_or_default(),
            );
            if let Some(fingerprint) = summary.certificate_fingerprint_sha256 {
                println!("certificate_fingerprint_sha256\t{fingerprint}");
            }
            if let Some(subject) = summary.certificate_subject {
                println!("certificate_subject\t{subject}");
            }
            if let Some(not_after) = summary.certificate_not_after {
                println!("certificate_not_after\t{not_after}");
            }
            for warning in summary.warnings {
                println!("warning\t{warning}");
            }
            Ok(0)
        }
        VaultCommand::ImportBackup { input, force } => {
            restore_vault_backup(input, &invocation.open_options.path, *force)?;
            println!("{}", invocation.open_options.path.display());
            Ok(0)
        }
        VaultCommand::ImportTransfer {
            input,
            replace_existing,
            package_password_env,
            package_cert_path,
            package_key_path,
            package_key_passphrase_env,
        } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let summary = if let Some(password_env) = package_password_env {
                let password = read_master_password(password_env)?;
                vault.import_transfer_package_with_password(input, &password, *replace_existing)?
            } else {
                let cert_path = package_cert_path.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "vault import-transfer requires --package-password-env or --package-cert plus --package-key"
                    )
                })?;
                let key_path = package_key_path.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "vault import-transfer requires --package-password-env or --package-cert plus --package-key"
                    )
                })?;
                let cert_pem = fs::read(cert_path)?;
                let key_pem = fs::read(key_path)?;
                let key_passphrase = package_key_passphrase_env
                    .as_deref()
                    .map(read_master_password)
                    .transpose()?;
                vault.import_transfer_package_with_certificate(
                    input,
                    cert_pem.as_slice(),
                    key_pem.as_slice(),
                    key_passphrase.as_deref(),
                    *replace_existing,
                )?
            };
            println!("imported_count\t{}", summary.imported_count);
            println!("replaced_count\t{}", summary.replaced_count);
            println!("remapped_count\t{}", summary.remapped_count);
            Ok(0)
        }
        VaultCommand::Delete { id } => {
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            vault.delete_item(id)?;
            println!("deleted\t{id}");
            Ok(0)
        }
        VaultCommand::AddCertSlot { cert_path, label } => {
            let cert_pem = fs::read(cert_path)?;
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.add_certificate_keyslot(cert_pem.as_slice(), label.clone())?;
            println!(
                "{}\t{}\t{}\t{}\t{}",
                keyslot.id,
                keyslot.wrap_algorithm,
                keyslot.certificate_fingerprint_sha256.unwrap_or_default(),
                keyslot.certificate_subject.unwrap_or_default(),
                keyslot.certificate_not_after.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::InspectCertificate { cert_path } => {
            let cert_pem = fs::read(cert_path)?;
            let preview = inspect_certificate_pem(cert_pem.as_slice())?;
            println!("fingerprint_sha256\t{}", preview.fingerprint_sha256);
            println!("subject\t{}", preview.subject);
            println!("not_before\t{}", preview.not_before);
            println!("not_after\t{}", preview.not_after);
            Ok(0)
        }
        VaultCommand::AddMnemonicSlot { label } => {
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let enrollment = vault.add_mnemonic_keyslot(label.clone())?;
            println!("slot_id\t{}", enrollment.keyslot.id);
            println!("wrap_algorithm\t{}", enrollment.keyslot.wrap_algorithm);
            println!("mnemonic\t{}", enrollment.mnemonic);
            Ok(0)
        }
        VaultCommand::RotateMnemonicSlot { id } => {
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let enrollment = vault.rotate_mnemonic_keyslot(id)?;
            println!("slot_id\t{}", enrollment.keyslot.id);
            println!("wrap_algorithm\t{}", enrollment.keyslot.wrap_algorithm);
            println!(
                "label\t{}",
                enrollment.keyslot.label.as_deref().unwrap_or_default()
            );
            println!("mnemonic\t{}", enrollment.mnemonic);
            Ok(0)
        }
        VaultCommand::AddDeviceSlot { label } => {
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.add_device_keyslot(label.clone())?;
            println!(
                "{}\t{}\t{}",
                keyslot.id,
                keyslot.wrap_algorithm,
                keyslot.label.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::RewrapCertSlot { id, cert_path } => {
            let cert_pem = fs::read(cert_path)?;
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.rewrap_certificate_keyslot(id, cert_pem.as_slice())?;
            println!(
                "{}\t{}\t{}\t{}\t{}",
                keyslot.id,
                keyslot.kind.as_str(),
                keyslot.certificate_fingerprint_sha256.unwrap_or_default(),
                keyslot.certificate_subject.unwrap_or_default(),
                keyslot.certificate_not_after.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::RenameKeyslot { id, label } => {
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.relabel_keyslot(id, label.clone())?;
            println!(
                "{}\t{}\t{}",
                keyslot.id,
                keyslot.kind.as_str(),
                keyslot.label.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::RemoveKeyslot { id, force } => {
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.remove_keyslot(id, *force)?;
            println!("removed\t{}\t{}", keyslot.id, keyslot.kind.as_str());
            Ok(0)
        }
        VaultCommand::RebindDeviceSlot { id } => {
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.rebind_device_keyslot(id)?;
            println!(
                "rebound\t{}\t{}\t{}",
                keyslot.id,
                keyslot.kind.as_str(),
                keyslot.device_account.unwrap_or_default()
            );
            Ok(0)
        }
        VaultCommand::RotateRecoverySecret { new_password_env } => {
            let new_recovery_secret = read_master_password(new_password_env)?;
            let mut vault = unlock_vault_for_options(&invocation.open_options)?;
            let keyslot = vault.rotate_password_recovery_keyslot(&new_recovery_secret)?;
            println!("rotated\t{}\t{}", keyslot.id, keyslot.wrap_algorithm);
            Ok(0)
        }
        VaultCommand::GenerateStore {
            request,
            target_login_id,
            title,
            username,
            url,
            notes,
            folder,
            tags,
            quiet,
        } => {
            if request.count != 1 {
                return Err(anyhow::anyhow!(
                    "vault generate-store only supports --count 1 to avoid ambiguous storage"
                ));
            }
            if target_login_id.is_none() && (title.is_none() || username.is_none()) {
                return Err(anyhow::anyhow!(
                    "vault generate-store requires --title and --username unless --id targets an existing login"
                ));
            }
            let vault = unlock_vault_for_options(&invocation.open_options)?;
            let (report, item) = vault.generate_and_store(
                request,
                GenerateStoreLoginRecord {
                    target_login_id: target_login_id.clone(),
                    title: title.clone(),
                    username: username.clone(),
                    url: url.clone(),
                    notes: notes.clone(),
                    folder: folder.clone(),
                    tags: Some(tags.clone()),
                },
            )?;
            print_generated_passwords(&report)?;
            if !*quiet {
                eprintln!(
                    "{}: {}",
                    if target_login_id.is_some() {
                        "rotated"
                    } else {
                        "stored"
                    },
                    item.id
                );
            }
            Ok(0)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    Auto,
    Cli,
    Tui,
}

struct VaultInvocation {
    open_options: VaultOpenOptions,
    mode: LaunchMode,
    command: Option<VaultCommand>,
}

#[derive(Debug, Clone)]
enum VaultCommand {
    Help,
    Init,
    Keyslots,
    InspectKeyslot {
        id: String,
    },
    List {
        query: VaultItemFilter,
    },
    Show {
        id: String,
    },
    Add {
        record: NewLoginRecord,
    },
    AddNote {
        record: NewSecureNoteRecord,
    },
    AddCard {
        record: NewCardRecord,
    },
    AddIdentity {
        record: NewIdentityRecord,
    },
    Update {
        id: String,
        update: UpdateLoginRecord,
    },
    UpdateNote {
        id: String,
        update: UpdateSecureNoteRecord,
    },
    UpdateCard {
        id: String,
        update: UpdateCardRecord,
    },
    UpdateIdentity {
        id: String,
        update: UpdateIdentityRecord,
    },
    ExportBackup {
        output: PathBuf,
    },
    ExportTransfer {
        output: PathBuf,
        filter: VaultItemFilter,
        package_password_env: Option<String>,
        package_cert_path: Option<PathBuf>,
    },
    InspectBackup {
        input: PathBuf,
    },
    InspectTransfer {
        input: PathBuf,
    },
    ImportBackup {
        input: PathBuf,
        force: bool,
    },
    ImportTransfer {
        input: PathBuf,
        replace_existing: bool,
        package_password_env: Option<String>,
        package_cert_path: Option<PathBuf>,
        package_key_path: Option<PathBuf>,
        package_key_passphrase_env: Option<String>,
    },
    Delete {
        id: String,
    },
    AddCertSlot {
        cert_path: PathBuf,
        label: Option<String>,
    },
    InspectCertificate {
        cert_path: PathBuf,
    },
    AddMnemonicSlot {
        label: Option<String>,
    },
    RotateMnemonicSlot {
        id: String,
    },
    AddDeviceSlot {
        label: Option<String>,
    },
    RewrapCertSlot {
        id: String,
        cert_path: PathBuf,
    },
    RenameKeyslot {
        id: String,
        label: Option<String>,
    },
    RemoveKeyslot {
        id: String,
        force: bool,
    },
    RebindDeviceSlot {
        id: String,
    },
    RotateRecoverySecret {
        new_password_env: String,
    },
    GenerateStore {
        request: ParanoidRequest,
        target_login_id: Option<String>,
        title: Option<String>,
        username: Option<String>,
        url: Option<String>,
        notes: Option<String>,
        folder: Option<String>,
        tags: Vec<String>,
        quiet: bool,
    },
}

fn parse_vault_args(args: &[OsString]) -> anyhow::Result<VaultInvocation> {
    let mut path = default_vault_path();
    let mut password_env = "PARANOID_MASTER_PASSWORD".to_string();
    let mut cert_path = None;
    let mut key_path = None;
    let mut key_passphrase_env = None;
    let mut mnemonic_phrase_env = None;
    let mut mnemonic_slot = None;
    let mut device_slot = None;
    let mut mode = LaunchMode::Auto;
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
            "--tui" if command.is_none() => mode = LaunchMode::Tui,
            "--cli" if command.is_none() => mode = LaunchMode::Cli,
            "--recovery-phrase-env" if command.is_none() => {
                mnemonic_phrase_env =
                    Some(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--recovery-phrase-env requires a value")
                    })?);
            }
            "--mnemonic-slot" if command.is_none() => {
                mnemonic_slot = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--mnemonic-slot requires a value"))?,
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

    let command = match command.as_deref() {
        None => None,
        Some("help") => Some(VaultCommand::Help),
        Some("init") => Some(VaultCommand::Init),
        Some("keyslots") => Some(VaultCommand::Keyslots),
        Some("inspect-keyslot") => Some(parse_inspect_keyslot(command_args.as_slice())?),
        Some("list") => Some(parse_list(command_args.as_slice())?),
        Some("show") => Some(parse_show(command_args.as_slice())?),
        Some("add") => Some(parse_add(command_args.as_slice())?),
        Some("add-note") => Some(parse_add_note(command_args.as_slice())?),
        Some("add-card") => Some(parse_add_card(command_args.as_slice())?),
        Some("add-identity") => Some(parse_add_identity(command_args.as_slice())?),
        Some("update") => Some(parse_update(command_args.as_slice())?),
        Some("update-note") => Some(parse_update_note(command_args.as_slice())?),
        Some("update-card") => Some(parse_update_card(command_args.as_slice())?),
        Some("update-identity") => Some(parse_update_identity(command_args.as_slice())?),
        Some("export-backup") => Some(parse_export_backup(command_args.as_slice())?),
        Some("export-transfer") => Some(parse_export_transfer(command_args.as_slice())?),
        Some("inspect-backup") => Some(parse_inspect_backup(command_args.as_slice())?),
        Some("inspect-transfer") => Some(parse_inspect_transfer(command_args.as_slice())?),
        Some("import-backup") => Some(parse_import_backup(command_args.as_slice())?),
        Some("import-transfer") => Some(parse_import_transfer(command_args.as_slice())?),
        Some("delete") => Some(parse_delete(command_args.as_slice())?),
        Some("add-cert-slot") => Some(parse_add_cert_slot(command_args.as_slice())?),
        Some("inspect-certificate") => Some(parse_inspect_certificate(command_args.as_slice())?),
        Some("add-mnemonic-slot") => Some(parse_add_mnemonic_slot(command_args.as_slice())?),
        Some("rotate-mnemonic-slot") => Some(parse_rotate_mnemonic_slot(command_args.as_slice())?),
        Some("add-device-slot") => Some(parse_add_device_slot(command_args.as_slice())?),
        Some("rewrap-cert-slot") => Some(parse_rewrap_cert_slot(command_args.as_slice())?),
        Some("rename-keyslot") => Some(parse_rename_keyslot(command_args.as_slice())?),
        Some("remove-keyslot") => Some(parse_remove_keyslot(command_args.as_slice())?),
        Some("rebind-device-slot") => Some(parse_rebind_device_slot(command_args.as_slice())?),
        Some("rotate-recovery-secret") => {
            Some(parse_rotate_recovery_secret(command_args.as_slice())?)
        }
        Some("generate-store") => Some(parse_generate_store(command_args.as_slice())?),
        Some(other) => return Err(anyhow::anyhow!("unknown vault subcommand: {other}")),
    };

    if device_slot.is_some() && cert_path.is_some() {
        return Err(anyhow::anyhow!(
            "--device-slot cannot be combined with certificate-backed unlock"
        ));
    }
    if mnemonic_slot.is_some() && mnemonic_phrase_env.is_none() {
        return Err(anyhow::anyhow!(
            "--mnemonic-slot requires --recovery-phrase-env"
        ));
    }
    if mnemonic_phrase_env.is_some() && cert_path.is_some() {
        return Err(anyhow::anyhow!(
            "--recovery-phrase-env cannot be combined with certificate-backed unlock"
        ));
    }
    if matches!(mode, LaunchMode::Tui) && command.is_some() {
        return Err(anyhow::anyhow!(
            "--tui cannot be combined with an explicit vault subcommand"
        ));
    }

    let auth = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => VaultAuth::Certificate {
            cert_path,
            key_path,
            key_passphrase_env,
            key_passphrase: None,
        },
        (None, None) => VaultAuth::PasswordEnv(password_env),
        _ => {
            return Err(anyhow::anyhow!(
                "--cert and --key must be provided together for certificate-backed unlock"
            ));
        }
    };

    Ok(VaultInvocation {
        open_options: VaultOpenOptions {
            path,
            auth,
            mnemonic_phrase_env,
            mnemonic_phrase: None,
            mnemonic_slot,
            device_slot,
            use_device_auto: false,
        },
        mode,
        command,
    })
}

fn should_launch_tui(invocation: &VaultInvocation, interactive: bool) -> bool {
    matches!(invocation.mode, LaunchMode::Tui)
        || (matches!(invocation.mode, LaunchMode::Auto)
            && interactive
            && invocation.command.is_none())
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

fn parse_inspect_keyslot(args: &[String]) -> anyhow::Result<VaultCommand> {
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
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected inspect-keyslot argument: {other}"
                ));
            }
        }
    }
    Ok(VaultCommand::InspectKeyslot {
        id: id.ok_or_else(|| anyhow::anyhow!("inspect-keyslot requires --id"))?,
    })
}

fn parse_export_backup(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut output = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--output" => {
                output =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--output requires a value")
                    })?));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown argument for vault export-backup: {other}"
                ));
            }
        }
    }
    Ok(VaultCommand::ExportBackup {
        output: output.ok_or_else(|| anyhow::anyhow!("vault export-backup requires --output"))?,
    })
}

fn parse_export_transfer(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut output = None;
    let mut filter = VaultItemFilter::default();
    let mut package_password_env = None;
    let mut package_cert_path = None;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--output" => {
                output =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--output requires a value")
                    })?));
            }
            "--query" => {
                filter.query = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--query requires a value"))?
                        .to_string(),
                );
            }
            "--kind" => {
                filter.kind =
                    Some(VaultItemKind::parse(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--kind requires a value")
                    })?)?);
            }
            "--folder" => {
                filter.folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => {
                filter.tag = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?
                        .to_string(),
                );
            }
            "--package-password-env" => {
                package_password_env = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--package-password-env requires a value"))?
                        .to_string(),
                );
            }
            "--package-cert" => {
                package_cert_path =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--package-cert requires a value")
                    })?));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown argument for vault export-transfer: {other}"
                ));
            }
        }
    }
    if package_password_env.is_none() && package_cert_path.is_none() {
        return Err(anyhow::anyhow!(
            "vault export-transfer requires --package-password-env, --package-cert, or both"
        ));
    }
    Ok(VaultCommand::ExportTransfer {
        output: output.ok_or_else(|| anyhow::anyhow!("vault export-transfer requires --output"))?,
        filter,
        package_password_env,
        package_cert_path,
    })
}

fn parse_import_backup(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut input = None;
    let mut force = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--input" => {
                input =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--input requires a value")
                    })?));
            }
            "--force" => force = true,
            other => {
                return Err(anyhow::anyhow!(
                    "unknown argument for vault import-backup: {other}"
                ));
            }
        }
    }
    Ok(VaultCommand::ImportBackup {
        input: input.ok_or_else(|| anyhow::anyhow!("vault import-backup requires --input"))?,
        force,
    })
}

fn parse_inspect_backup(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut input = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--input" => {
                input =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--input requires a value")
                    })?));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown argument for vault inspect-backup: {other}"
                ));
            }
        }
    }
    Ok(VaultCommand::InspectBackup {
        input: input.ok_or_else(|| anyhow::anyhow!("vault inspect-backup requires --input"))?,
    })
}

fn parse_inspect_transfer(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut input = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--input" => {
                input =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--input requires a value")
                    })?));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown argument for vault inspect-transfer: {other}"
                ));
            }
        }
    }
    Ok(VaultCommand::InspectTransfer {
        input: input.ok_or_else(|| anyhow::anyhow!("vault inspect-transfer requires --input"))?,
    })
}

fn parse_import_transfer(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut input = None;
    let mut replace_existing = false;
    let mut package_password_env = None;
    let mut package_cert_path = None;
    let mut package_key_path = None;
    let mut package_key_passphrase_env = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--input" => {
                input =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--input requires a value")
                    })?));
            }
            "--replace-existing" => replace_existing = true,
            "--package-password-env" => {
                package_password_env = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--package-password-env requires a value"))?
                        .to_string(),
                );
            }
            "--package-cert" => {
                package_cert_path =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--package-cert requires a value")
                    })?));
            }
            "--package-key" => {
                package_key_path =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--package-key requires a value")
                    })?));
            }
            "--package-key-passphrase-env" => {
                package_key_passphrase_env = Some(
                    iter.next()
                        .ok_or_else(|| {
                            anyhow::anyhow!("--package-key-passphrase-env requires a value")
                        })?
                        .to_string(),
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown argument for vault import-transfer: {other}"
                ));
            }
        }
    }
    let using_password = package_password_env.is_some();
    let using_certificate = package_cert_path.is_some() || package_key_path.is_some();
    if using_password && using_certificate {
        return Err(anyhow::anyhow!(
            "vault import-transfer requires either --package-password-env or --package-cert plus --package-key"
        ));
    }
    if !using_password && !using_certificate {
        return Err(anyhow::anyhow!(
            "vault import-transfer requires --package-password-env or --package-cert plus --package-key"
        ));
    }
    if using_certificate && (package_cert_path.is_none() || package_key_path.is_none()) {
        return Err(anyhow::anyhow!(
            "vault import-transfer requires --package-cert and --package-key together"
        ));
    }
    Ok(VaultCommand::ImportTransfer {
        input: input.ok_or_else(|| anyhow::anyhow!("vault import-transfer requires --input"))?,
        replace_existing,
        package_password_env,
        package_cert_path,
        package_key_path,
        package_key_passphrase_env,
    })
}

fn parse_list(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut query = VaultItemFilter::default();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--query" => {
                query.query = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--query requires a value"))?
                        .to_string(),
                );
            }
            "--kind" => {
                query.kind =
                    Some(VaultItemKind::parse(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--kind requires a value")
                    })?)?);
            }
            "--folder" => {
                query.folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => {
                query.tag = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?
                        .to_string(),
                );
            }
            other => {
                return Err(anyhow::anyhow!("unknown argument for vault list: {other}"));
            }
        }
    }
    Ok(VaultCommand::List { query })
}

fn parse_add(args: &[String]) -> anyhow::Result<VaultCommand> {
    let record = parse_login_record(args)?;
    Ok(VaultCommand::Add { record })
}

fn parse_add_note(args: &[String]) -> anyhow::Result<VaultCommand> {
    let record = parse_secure_note_record(args)?;
    Ok(VaultCommand::AddNote { record })
}

fn parse_add_card(args: &[String]) -> anyhow::Result<VaultCommand> {
    let record = parse_card_record(args)?;
    Ok(VaultCommand::AddCard { record })
}

fn parse_add_identity(args: &[String]) -> anyhow::Result<VaultCommand> {
    let record = parse_identity_record(args)?;
    Ok(VaultCommand::AddIdentity { record })
}

fn parse_update(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut update = UpdateLoginRecord::default();
    let mut tags = Vec::new();
    let mut tags_specified = false;
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
            "--folder" => {
                update.folder = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-folder" => update.folder = Some(None),
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
                tags_specified = true;
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
                );
                tags_specified = true;
            }
            "--clear-tags" => {
                tags.clear();
                tags_specified = true;
            }
            other => return Err(anyhow::anyhow!("unexpected vault update argument: {other}")),
        }
    }
    if tags_specified {
        update.tags = Some(tags);
    }
    Ok(VaultCommand::Update {
        id: id.ok_or_else(|| anyhow::anyhow!("vault update requires --id"))?,
        update,
    })
}

fn parse_update_note(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut update = UpdateSecureNoteRecord::default();
    let mut tags = Vec::new();
    let mut tags_specified = false;
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
            "--content" => {
                update.content = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--content requires a value"))?
                        .to_string(),
                );
            }
            "--folder" => {
                update.folder = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-folder" => update.folder = Some(None),
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
                tags_specified = true;
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
                );
                tags_specified = true;
            }
            "--clear-tags" => {
                tags.clear();
                tags_specified = true;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault update-note argument: {other}"
                ));
            }
        }
    }
    if tags_specified {
        update.tags = Some(tags);
    }
    Ok(VaultCommand::UpdateNote {
        id: id.ok_or_else(|| anyhow::anyhow!("vault update-note requires --id"))?,
        update,
    })
}

fn parse_update_card(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut update = UpdateCardRecord::default();
    let mut tags = Vec::new();
    let mut tags_specified = false;
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
            "--cardholder" => {
                update.cardholder_name = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--cardholder requires a value"))?
                        .to_string(),
                );
            }
            "--number" => {
                update.number = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--number requires a value"))?
                        .to_string(),
                );
            }
            "--expiry-month" => {
                update.expiry_month = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--expiry-month requires a value"))?
                        .to_string(),
                );
            }
            "--expiry-year" => {
                update.expiry_year = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--expiry-year requires a value"))?
                        .to_string(),
                );
            }
            "--security-code" => {
                update.security_code = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--security-code requires a value"))?
                        .to_string(),
                );
            }
            "--billing-zip" => {
                update.billing_zip = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--billing-zip requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-billing-zip" => update.billing_zip = Some(None),
            "--notes" => {
                update.notes = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--notes requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-notes" => update.notes = Some(None),
            "--folder" => {
                update.folder = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-folder" => update.folder = Some(None),
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
                tags_specified = true;
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
                );
                tags_specified = true;
            }
            "--clear-tags" => {
                tags.clear();
                tags_specified = true;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault update-card argument: {other}"
                ));
            }
        }
    }
    if tags_specified {
        update.tags = Some(tags);
    }
    Ok(VaultCommand::UpdateCard {
        id: id.ok_or_else(|| anyhow::anyhow!("vault update-card requires --id"))?,
        update,
    })
}

fn parse_update_identity(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut update = UpdateIdentityRecord::default();
    let mut tags = Vec::new();
    let mut tags_specified = false;
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
            "--full-name" => {
                update.full_name = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--full-name requires a value"))?
                        .to_string(),
                );
            }
            "--email" => {
                update.email = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--email requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-email" => update.email = Some(None),
            "--phone" => {
                update.phone = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--phone requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-phone" => update.phone = Some(None),
            "--address" => {
                update.address = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--address requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-address" => update.address = Some(None),
            "--notes" => {
                update.notes = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--notes requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-notes" => update.notes = Some(None),
            "--folder" => {
                update.folder = Some(Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                ));
            }
            "--clear-folder" => update.folder = Some(None),
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
                tags_specified = true;
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
                );
                tags_specified = true;
            }
            "--clear-tags" => {
                tags.clear();
                tags_specified = true;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault update-identity argument: {other}"
                ));
            }
        }
    }
    if tags_specified {
        update.tags = Some(tags);
    }
    Ok(VaultCommand::UpdateIdentity {
        id: id.ok_or_else(|| anyhow::anyhow!("vault update-identity requires --id"))?,
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

fn parse_inspect_certificate(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut cert_path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--cert" => {
                cert_path = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--cert requires a value"))?,
                ));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected inspect-certificate argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::InspectCertificate {
        cert_path: cert_path
            .ok_or_else(|| anyhow::anyhow!("inspect-certificate requires --cert"))?,
    })
}

fn parse_add_mnemonic_slot(args: &[String]) -> anyhow::Result<VaultCommand> {
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
                    "unexpected vault add-mnemonic-slot argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::AddMnemonicSlot { label })
}

fn parse_rotate_mnemonic_slot(args: &[String]) -> anyhow::Result<VaultCommand> {
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
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault rotate-mnemonic-slot argument: {other}"
                ));
            }
        }
    }
    Ok(VaultCommand::RotateMnemonicSlot {
        id: id.ok_or_else(|| anyhow::anyhow!("vault rotate-mnemonic-slot requires --id"))?,
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

fn parse_rewrap_cert_slot(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut cert_path = None;
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
            "--cert" => {
                cert_path = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--cert requires a value"))?,
                ));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault rewrap-cert-slot argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::RewrapCertSlot {
        id: id.ok_or_else(|| anyhow::anyhow!("vault rewrap-cert-slot requires --id"))?,
        cert_path: cert_path
            .ok_or_else(|| anyhow::anyhow!("vault rewrap-cert-slot requires --cert"))?,
    })
}

fn parse_rename_keyslot(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut label = None;
    let mut label_specified = false;
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
            "--label" => {
                label = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--label requires a value"))?
                        .to_string(),
                );
                label_specified = true;
            }
            "--clear-label" => {
                label = None;
                label_specified = true;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault rename-keyslot argument: {other}"
                ));
            }
        }
    }

    if !label_specified {
        return Err(anyhow::anyhow!(
            "vault rename-keyslot requires --label or --clear-label"
        ));
    }

    Ok(VaultCommand::RenameKeyslot {
        id: id.ok_or_else(|| anyhow::anyhow!("vault rename-keyslot requires --id"))?,
        label,
    })
}

fn parse_remove_keyslot(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut id = None;
    let mut force = false;
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
            "--force" => force = true,
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault remove-keyslot argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::RemoveKeyslot {
        id: id.ok_or_else(|| anyhow::anyhow!("vault remove-keyslot requires --id"))?,
        force,
    })
}

fn parse_rebind_device_slot(args: &[String]) -> anyhow::Result<VaultCommand> {
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
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault rebind-device-slot argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::RebindDeviceSlot {
        id: id.ok_or_else(|| anyhow::anyhow!("vault rebind-device-slot requires --id"))?,
    })
}

fn parse_rotate_recovery_secret(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut new_password_env = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--new-password-env" => {
                new_password_env = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--new-password-env requires a value"))?
                        .to_string(),
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault rotate-recovery-secret argument: {other}"
                ));
            }
        }
    }

    Ok(VaultCommand::RotateRecoverySecret {
        new_password_env: new_password_env.ok_or_else(|| {
            anyhow::anyhow!("vault rotate-recovery-secret requires --new-password-env")
        })?,
    })
}

fn parse_generate_store(args: &[String]) -> anyhow::Result<VaultCommand> {
    let mut request = ParanoidRequest::default();
    let mut quiet = false;
    let mut charset_spec: Option<String> = None;
    let mut target_login_id = None;
    let mut title = None;
    let mut username = None;
    let mut url = None;
    let mut notes = None;
    let mut folder = None;
    let mut tags = Vec::new();
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
            "--id" => {
                target_login_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
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
            "--folder" => {
                folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
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
        target_login_id,
        title,
        username,
        url,
        notes,
        folder,
        tags,
        quiet,
    })
}

fn parse_login_record(args: &[String]) -> anyhow::Result<NewLoginRecord> {
    let mut title = None;
    let mut username = None;
    let mut password = None;
    let mut url = None;
    let mut notes = None;
    let mut folder = None;
    let mut tags = Vec::new();
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
            "--folder" => {
                folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
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
        folder,
        tags,
    })
}

fn parse_secure_note_record(args: &[String]) -> anyhow::Result<NewSecureNoteRecord> {
    let mut title = None;
    let mut content = None;
    let mut folder = None;
    let mut tags = Vec::new();
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
            "--content" => {
                content = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--content requires a value"))?
                        .to_string(),
                );
            }
            "--folder" => {
                folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
                );
            }
            "--tags" => {
                append_tag_argument(
                    &mut tags,
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault add-note argument: {other}"
                ));
            }
        }
    }

    Ok(NewSecureNoteRecord {
        title: title.ok_or_else(|| anyhow::anyhow!("vault add-note requires --title"))?,
        content: content.ok_or_else(|| anyhow::anyhow!("vault add-note requires --content"))?,
        folder,
        tags,
    })
}

fn parse_card_record(args: &[String]) -> anyhow::Result<NewCardRecord> {
    let mut title = None;
    let mut cardholder_name = None;
    let mut number = None;
    let mut expiry_month = None;
    let mut expiry_year = None;
    let mut security_code = None;
    let mut billing_zip = None;
    let mut notes = None;
    let mut folder = None;
    let mut tags = Vec::new();
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
            "--cardholder" => {
                cardholder_name = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--cardholder requires a value"))?
                        .to_string(),
                );
            }
            "--number" => {
                number = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--number requires a value"))?
                        .to_string(),
                );
            }
            "--expiry-month" => {
                expiry_month = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--expiry-month requires a value"))?
                        .to_string(),
                );
            }
            "--expiry-year" => {
                expiry_year = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--expiry-year requires a value"))?
                        .to_string(),
                );
            }
            "--security-code" => {
                security_code = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--security-code requires a value"))?
                        .to_string(),
                );
            }
            "--billing-zip" => {
                billing_zip = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--billing-zip requires a value"))?
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
            "--folder" => {
                folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => append_tag_argument(
                &mut tags,
                iter.next()
                    .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
            ),
            "--tags" => append_tag_argument(
                &mut tags,
                iter.next()
                    .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
            ),
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault add-card argument: {other}"
                ));
            }
        }
    }
    Ok(NewCardRecord {
        title: title.ok_or_else(|| anyhow::anyhow!("vault add-card requires --title"))?,
        cardholder_name: cardholder_name
            .ok_or_else(|| anyhow::anyhow!("vault add-card requires --cardholder"))?,
        number: number.ok_or_else(|| anyhow::anyhow!("vault add-card requires --number"))?,
        expiry_month: expiry_month
            .ok_or_else(|| anyhow::anyhow!("vault add-card requires --expiry-month"))?,
        expiry_year: expiry_year
            .ok_or_else(|| anyhow::anyhow!("vault add-card requires --expiry-year"))?,
        security_code: security_code
            .ok_or_else(|| anyhow::anyhow!("vault add-card requires --security-code"))?,
        billing_zip,
        notes,
        folder,
        tags,
    })
}

fn parse_identity_record(args: &[String]) -> anyhow::Result<NewIdentityRecord> {
    let mut title = None;
    let mut full_name = None;
    let mut email = None;
    let mut phone = None;
    let mut address = None;
    let mut notes = None;
    let mut folder = None;
    let mut tags = Vec::new();
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
            "--full-name" => {
                full_name = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--full-name requires a value"))?
                        .to_string(),
                );
            }
            "--email" => {
                email = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--email requires a value"))?
                        .to_string(),
                );
            }
            "--phone" => {
                phone = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--phone requires a value"))?
                        .to_string(),
                );
            }
            "--address" => {
                address = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--address requires a value"))?
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
            "--folder" => {
                folder = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--folder requires a value"))?
                        .to_string(),
                );
            }
            "--tag" => append_tag_argument(
                &mut tags,
                iter.next()
                    .ok_or_else(|| anyhow::anyhow!("--tag requires a value"))?,
            ),
            "--tags" => append_tag_argument(
                &mut tags,
                iter.next()
                    .ok_or_else(|| anyhow::anyhow!("--tags requires a value"))?,
            ),
            other => {
                return Err(anyhow::anyhow!(
                    "unexpected vault add-identity argument: {other}"
                ));
            }
        }
    }

    Ok(NewIdentityRecord {
        title: title.ok_or_else(|| anyhow::anyhow!("vault add-identity requires --title"))?,
        full_name: full_name
            .ok_or_else(|| anyhow::anyhow!("vault add-identity requires --full-name"))?,
        email,
        phone,
        address,
        notes,
        folder,
        tags,
    })
}

fn parse_usize_arg(next: Option<&String>, flag: &str) -> anyhow::Result<usize> {
    next.ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))?
        .parse()
        .map_err(anyhow::Error::from)
}

fn append_tag_argument(tags: &mut Vec<String>, raw: &str) {
    for tag in raw.split(',').map(str::trim).filter(|tag| !tag.is_empty()) {
        tags.push(tag.to_string());
    }
}

fn print_usage(mut out: impl Write) -> io::Result<()> {
    writeln!(
        out,
        "\
paranoid-passwd {VERSION}

Usage:
  paranoid-passwd vault [--tui|--cli] [--path FILE] [--password-env VAR] [--recovery-phrase-env VAR [--mnemonic-slot ID]] [--device-slot ID] [--cert CERT.pem --key KEY.pem [--key-passphrase-env VAR]] [subcommand] [OPTIONS]

Subcommands:
  init
  keyslots
  inspect-keyslot --id ID
  list [--query TEXT] [--kind login|secure_note|card|identity] [--folder NAME] [--tag TAG]
  show --id ID
  add --title TITLE --username USER --password SECRET [--url URL] [--notes NOTES] [--folder NAME] [--tag TAG|--tags TAG1,TAG2]
  add-note --title TITLE --content TEXT [--folder NAME] [--tag TAG|--tags TAG1,TAG2]
  add-card --title TITLE --cardholder NAME --number PAN --expiry-month MM --expiry-year YYYY --security-code CVC [--billing-zip ZIP] [--notes NOTES] [--folder NAME] [--tag TAG|--tags TAG1,TAG2]
  add-identity --title TITLE --full-name NAME [--email EMAIL] [--phone PHONE] [--address TEXT] [--notes NOTES] [--folder NAME] [--tag TAG|--tags TAG1,TAG2]
  update --id ID [--title TITLE] [--username USER] [--password SECRET] [--url URL|--clear-url] [--notes NOTES|--clear-notes] [--folder NAME|--clear-folder] [--tag TAG|--tags TAG1,TAG2|--clear-tags]
  update-note --id ID [--title TITLE] [--content TEXT] [--folder NAME|--clear-folder] [--tag TAG|--tags TAG1,TAG2|--clear-tags]
  update-card --id ID [--title TITLE] [--cardholder NAME] [--number PAN] [--expiry-month MM] [--expiry-year YYYY] [--security-code CVC] [--billing-zip ZIP|--clear-billing-zip] [--notes NOTES|--clear-notes] [--folder NAME|--clear-folder] [--tag TAG|--tags TAG1,TAG2|--clear-tags]
  update-identity --id ID [--title TITLE] [--full-name NAME] [--email EMAIL|--clear-email] [--phone PHONE|--clear-phone] [--address TEXT|--clear-address] [--notes NOTES|--clear-notes] [--folder NAME|--clear-folder] [--tag TAG|--tags TAG1,TAG2|--clear-tags]
  export-backup --output FILE
  export-transfer --output FILE [--query TEXT] [--kind login|secure_note|card|identity] [--folder NAME] [--tag TAG] [--package-password-env VAR] [--package-cert CERT.pem]
  inspect-backup --input FILE
  inspect-transfer --input FILE
  import-backup --input FILE [--force]
  import-transfer --input FILE [--replace-existing] [--package-password-env VAR | --package-cert CERT.pem --package-key KEY.pem [--package-key-passphrase-env VAR]]
  delete --id ID
  inspect-certificate --cert CERT.pem
  add-cert-slot --cert CERT.pem [--label LABEL]
  add-mnemonic-slot [--label LABEL]
  rotate-mnemonic-slot --id ID
  add-device-slot [--label LABEL]
  rewrap-cert-slot --id ID --cert CERT.pem
  rename-keyslot --id ID [--label LABEL|--clear-label]
  remove-keyslot --id ID [--force]
  rebind-device-slot --id ID
  rotate-recovery-secret --new-password-env VAR
  generate-store [generator flags...] [--id LOGIN_ID] [--title TITLE] [--username USER] [--url URL] [--notes NOTES] [--folder NAME] [--tag TAG|--tags TAG1,TAG2]

Unlock sources:
  By default vault commands read the recovery secret from PARANOID_MASTER_PASSWORD.
  Override with --password-env VAR.
  Wallet-style recovery uses --recovery-phrase-env VAR and optionally --mnemonic-slot ID.
  If the recovery secret is absent and the vault has exactly one device-bound keyslot, commands fall back to passwordless device unlock.
  Use --device-slot ID to select a specific device-bound keyslot explicitly.
  Certificate-backed unlock requires --cert and --key together before the subcommand.
  If the private key PEM is encrypted, pass --key-passphrase-env VAR.
  Encrypted transfer packages use their own unwrap material: --package-password-env for recovery-secret unwrap, or --package-cert/--package-key for certificate unwrap.
  Use rotate-recovery-secret to rewrap the password recovery slot without changing mnemonic, device, or certificate keyslots.
  For `generate-store`, pass --id LOGIN_ID to rotate an existing login in place instead of creating a new one.

Behavior:
  On an interactive TTY with no explicit subcommand, `paranoid-passwd vault` launches
  the native vault TUI. Pass --cli to force headless behavior or --tui to force the
  interactive view explicitly.
"
    )
}

fn print_item(
    item: &paranoid_vault::VaultItem,
    duplicate_password_count: usize,
) -> anyhow::Result<()> {
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
            println!("folder: {}", login.folder.as_deref().unwrap_or(""));
            println!("tags: {}", login.tags.join(","));
            println!("duplicate_password_count: {duplicate_password_count}");
            println!("password_history_count: {}", login.password_history.len());
            for (index, entry) in login.password_history.iter().enumerate() {
                println!(
                    "password_history[{index}]: {} @ {}",
                    entry.password, entry.changed_at_epoch
                );
            }
        }
        paranoid_vault::VaultItemPayload::SecureNote(note) => {
            println!("title: {}", note.title);
            println!("content: {}", note.content);
            println!("folder: {}", note.folder.as_deref().unwrap_or(""));
            println!("tags: {}", note.tags.join(","));
        }
        paranoid_vault::VaultItemPayload::Card(card) => {
            println!("title: {}", card.title);
            println!("cardholder_name: {}", card.cardholder_name);
            println!("number: {}", card.number);
            println!("expiry_month: {}", card.expiry_month);
            println!("expiry_year: {}", card.expiry_year);
            println!("security_code: {}", card.security_code);
            println!("billing_zip: {}", card.billing_zip.as_deref().unwrap_or(""));
            println!("notes: {}", card.notes.as_deref().unwrap_or(""));
            println!("folder: {}", card.folder.as_deref().unwrap_or(""));
            println!("tags: {}", card.tags.join(","));
        }
        paranoid_vault::VaultItemPayload::Identity(identity) => {
            println!("title: {}", identity.title);
            println!("full_name: {}", identity.full_name);
            println!("email: {}", identity.email.as_deref().unwrap_or(""));
            println!("phone: {}", identity.phone.as_deref().unwrap_or(""));
            println!("address: {}", identity.address.as_deref().unwrap_or(""));
            println!("notes: {}", identity.notes.as_deref().unwrap_or(""));
            println!("folder: {}", identity.folder.as_deref().unwrap_or(""));
            println!("tags: {}", identity.tags.join(","));
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

        match invocation.open_options.auth {
            VaultAuth::Certificate {
                cert_path,
                key_path,
                key_passphrase_env,
                key_passphrase,
            } => {
                assert_eq!(cert_path, PathBuf::from("unlock-cert.pem"));
                assert_eq!(key_path, PathBuf::from("unlock-key.pem"));
                assert_eq!(
                    key_passphrase_env.as_deref(),
                    Some("PARANOID_KEY_PASSPHRASE")
                );
                assert!(key_passphrase.is_none());
            }
            VaultAuth::PasswordEnv(_) | VaultAuth::Password(_) => {
                panic!("expected certificate auth")
            }
        }
        assert!(matches!(
            invocation.command,
            Some(VaultCommand::List { query }) if query == VaultItemFilter::default()
        ));
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
            Some(VaultCommand::AddCertSlot { cert_path, label }) => {
                assert_eq!(cert_path, PathBuf::from("recipient.pem"));
                assert_eq!(label.as_deref(), Some("laptop"));
            }
            _ => panic!("expected add-cert-slot command"),
        }
    }

    #[test]
    fn parse_inspect_certificate_requires_cert() {
        let command = parse_vault_args(&[
            OsString::from("inspect-certificate"),
            OsString::from("--cert"),
            OsString::from("recipient.pem"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::InspectCertificate { cert_path }) => {
                assert_eq!(cert_path, PathBuf::from("recipient.pem"));
            }
            _ => panic!("expected inspect-certificate command"),
        }
    }

    #[test]
    fn parse_inspect_keyslot_requires_id() {
        let command = parse_vault_args(&[
            OsString::from("inspect-keyslot"),
            OsString::from("--id"),
            OsString::from("device-test"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::InspectKeyslot { id }) => {
                assert_eq!(id, "device-test");
            }
            _ => panic!("expected inspect-keyslot command"),
        }
    }

    #[test]
    fn parse_add_mnemonic_slot_supports_label() {
        let command = parse_vault_args(&[
            OsString::from("add-mnemonic-slot"),
            OsString::from("--label"),
            OsString::from("paper"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::AddMnemonicSlot { label }) => {
                assert_eq!(label.as_deref(), Some("paper"));
            }
            _ => panic!("expected add-mnemonic-slot command"),
        }
    }

    #[test]
    fn parse_rotate_mnemonic_slot_requires_id() {
        let command = parse_vault_args(&[
            OsString::from("rotate-mnemonic-slot"),
            OsString::from("--id"),
            OsString::from("mnemonic-1234"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::RotateMnemonicSlot { id }) => {
                assert_eq!(id, "mnemonic-1234");
            }
            _ => panic!("expected rotate-mnemonic-slot command"),
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
            Some(VaultCommand::AddDeviceSlot { label }) => {
                assert_eq!(label.as_deref(), Some("daily"));
            }
            _ => panic!("expected add-device-slot command"),
        }
    }

    #[test]
    fn parse_rename_keyslot_supports_label_and_clear() {
        let command = parse_vault_args(&[
            OsString::from("rename-keyslot"),
            OsString::from("--id"),
            OsString::from("device-1234"),
            OsString::from("--label"),
            OsString::from("laptop"),
        ])
        .expect("parse rename label");

        match command.command {
            Some(VaultCommand::RenameKeyslot { id, label }) => {
                assert_eq!(id, "device-1234");
                assert_eq!(label.as_deref(), Some("laptop"));
            }
            _ => panic!("expected rename-keyslot command"),
        }

        let command = parse_vault_args(&[
            OsString::from("rename-keyslot"),
            OsString::from("--id"),
            OsString::from("device-1234"),
            OsString::from("--clear-label"),
        ])
        .expect("parse clear label");

        match command.command {
            Some(VaultCommand::RenameKeyslot { id, label }) => {
                assert_eq!(id, "device-1234");
                assert!(label.is_none());
            }
            _ => panic!("expected rename-keyslot clear command"),
        }
    }

    #[test]
    fn parse_rewrap_cert_slot_requires_id_and_cert() {
        let command = parse_vault_args(&[
            OsString::from("rewrap-cert-slot"),
            OsString::from("--id"),
            OsString::from("cert-1234"),
            OsString::from("--cert"),
            OsString::from("recipient-next.pem"),
        ])
        .expect("parse rewrap cert slot");

        match command.command {
            Some(VaultCommand::RewrapCertSlot { id, cert_path }) => {
                assert_eq!(id, "cert-1234");
                assert_eq!(cert_path, PathBuf::from("recipient-next.pem"));
            }
            _ => panic!("expected rewrap-cert-slot command"),
        }
    }

    #[test]
    fn parse_remove_keyslot_requires_id() {
        let command = parse_vault_args(&[
            OsString::from("remove-keyslot"),
            OsString::from("--id"),
            OsString::from("device-1234"),
            OsString::from("--force"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::RemoveKeyslot { id, force }) => {
                assert_eq!(id, "device-1234");
                assert!(force);
            }
            _ => panic!("expected remove-keyslot command"),
        }
    }

    #[test]
    fn parse_rebind_device_slot_requires_id() {
        let command = parse_vault_args(&[
            OsString::from("rebind-device-slot"),
            OsString::from("--id"),
            OsString::from("device-1234"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::RebindDeviceSlot { id }) => {
                assert_eq!(id, "device-1234");
            }
            _ => panic!("expected rebind-device-slot command"),
        }
    }

    #[test]
    fn parse_rotate_recovery_secret_requires_new_password_env() {
        let command = parse_vault_args(&[
            OsString::from("rotate-recovery-secret"),
            OsString::from("--new-password-env"),
            OsString::from("PARANOID_NEW_MASTER_PASSWORD"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::RotateRecoverySecret { new_password_env }) => {
                assert_eq!(new_password_env, "PARANOID_NEW_MASTER_PASSWORD");
            }
            _ => panic!("expected rotate-recovery-secret command"),
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

        assert_eq!(
            invocation.open_options.device_slot.as_deref(),
            Some("device-abc123")
        );
        assert!(matches!(
            invocation.command,
            Some(VaultCommand::List { query }) if query == VaultItemFilter::default()
        ));
    }

    #[test]
    fn parse_vault_args_supports_mnemonic_unlock() {
        let invocation = parse_vault_args(&[
            OsString::from("--recovery-phrase-env"),
            OsString::from("PARANOID_RECOVERY_PHRASE"),
            OsString::from("--mnemonic-slot"),
            OsString::from("mnemonic-abc123"),
            OsString::from("list"),
        ])
        .expect("parse");

        assert_eq!(
            invocation.open_options.mnemonic_phrase_env.as_deref(),
            Some("PARANOID_RECOVERY_PHRASE")
        );
        assert_eq!(
            invocation.open_options.mnemonic_slot.as_deref(),
            Some("mnemonic-abc123")
        );
        assert!(matches!(
            invocation.command,
            Some(VaultCommand::List { query }) if query == VaultItemFilter::default()
        ));
    }

    #[test]
    fn parse_vault_list_supports_query_filter() {
        let invocation = parse_vault_args(&[
            OsString::from("list"),
            OsString::from("--query"),
            OsString::from("octo"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::List { query }) => {
                assert_eq!(query.query.as_deref(), Some("octo"));
                assert_eq!(query.kind, None);
                assert_eq!(query.folder, None);
                assert_eq!(query.tag, None);
            }
            _ => panic!("expected filtered list command"),
        }
    }

    #[test]
    fn parse_vault_list_supports_structured_filters() {
        let invocation = parse_vault_args(&[
            OsString::from("list"),
            OsString::from("--kind"),
            OsString::from("login"),
            OsString::from("--folder"),
            OsString::from("Work"),
            OsString::from("--tag"),
            OsString::from("finance"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::List { query }) => {
                assert_eq!(query.kind, Some(VaultItemKind::Login));
                assert_eq!(query.folder.as_deref(), Some("Work"));
                assert_eq!(query.tag.as_deref(), Some("finance"));
            }
            _ => panic!("expected structured list command"),
        }
    }

    #[test]
    fn parse_export_backup_requires_output() {
        let invocation = parse_vault_args(&[
            OsString::from("export-backup"),
            OsString::from("--output"),
            OsString::from("vault-backup.json"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::ExportBackup { output }) => {
                assert_eq!(output, PathBuf::from("vault-backup.json"));
            }
            _ => panic!("expected export-backup command"),
        }
    }

    #[test]
    fn parse_export_transfer_supports_filter_and_multiple_access_paths() {
        let invocation = parse_vault_args(&[
            OsString::from("export-transfer"),
            OsString::from("--output"),
            OsString::from("vault-transfer.json"),
            OsString::from("--kind"),
            OsString::from("login"),
            OsString::from("--folder"),
            OsString::from("Work"),
            OsString::from("--tag"),
            OsString::from("prod"),
            OsString::from("--package-password-env"),
            OsString::from("PARANOID_TRANSFER_PASSWORD"),
            OsString::from("--package-cert"),
            OsString::from("recipient.pem"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::ExportTransfer {
                output,
                filter,
                package_password_env,
                package_cert_path,
            }) => {
                assert_eq!(output, PathBuf::from("vault-transfer.json"));
                assert_eq!(filter.kind, Some(VaultItemKind::Login));
                assert_eq!(filter.folder.as_deref(), Some("Work"));
                assert_eq!(filter.tag.as_deref(), Some("prod"));
                assert_eq!(
                    package_password_env.as_deref(),
                    Some("PARANOID_TRANSFER_PASSWORD")
                );
                assert_eq!(package_cert_path, Some(PathBuf::from("recipient.pem")));
            }
            _ => panic!("expected export-transfer command"),
        }
    }

    #[test]
    fn parse_inspect_backup_requires_input() {
        let invocation = parse_vault_args(&[
            OsString::from("inspect-backup"),
            OsString::from("--input"),
            OsString::from("vault-backup.json"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::InspectBackup { input }) => {
                assert_eq!(input, PathBuf::from("vault-backup.json"));
            }
            _ => panic!("expected inspect-backup command"),
        }
    }

    #[test]
    fn parse_inspect_transfer_requires_input() {
        let invocation = parse_vault_args(&[
            OsString::from("inspect-transfer"),
            OsString::from("--input"),
            OsString::from("vault-transfer.json"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::InspectTransfer { input }) => {
                assert_eq!(input, PathBuf::from("vault-transfer.json"));
            }
            _ => panic!("expected inspect-transfer command"),
        }
    }

    #[test]
    fn parse_import_backup_supports_force() {
        let invocation = parse_vault_args(&[
            OsString::from("import-backup"),
            OsString::from("--input"),
            OsString::from("vault-backup.json"),
            OsString::from("--force"),
        ])
        .expect("parse");

        match invocation.command {
            Some(VaultCommand::ImportBackup { input, force }) => {
                assert_eq!(input, PathBuf::from("vault-backup.json"));
                assert!(force);
            }
            _ => panic!("expected import-backup command"),
        }
    }

    #[test]
    fn parse_import_transfer_supports_password_or_certificate_modes() {
        let password_invocation = parse_vault_args(&[
            OsString::from("import-transfer"),
            OsString::from("--input"),
            OsString::from("vault-transfer.json"),
            OsString::from("--replace-existing"),
            OsString::from("--package-password-env"),
            OsString::from("PARANOID_TRANSFER_PASSWORD"),
        ])
        .expect("parse");

        match password_invocation.command {
            Some(VaultCommand::ImportTransfer {
                input,
                replace_existing,
                package_password_env,
                package_cert_path,
                package_key_path,
                package_key_passphrase_env,
            }) => {
                assert_eq!(input, PathBuf::from("vault-transfer.json"));
                assert!(replace_existing);
                assert_eq!(
                    package_password_env.as_deref(),
                    Some("PARANOID_TRANSFER_PASSWORD")
                );
                assert!(package_cert_path.is_none());
                assert!(package_key_path.is_none());
                assert!(package_key_passphrase_env.is_none());
            }
            _ => panic!("expected import-transfer password command"),
        }

        let certificate_invocation = parse_vault_args(&[
            OsString::from("import-transfer"),
            OsString::from("--input"),
            OsString::from("vault-transfer.json"),
            OsString::from("--package-cert"),
            OsString::from("recipient.pem"),
            OsString::from("--package-key"),
            OsString::from("recipient-key.pem"),
            OsString::from("--package-key-passphrase-env"),
            OsString::from("PARANOID_TRANSFER_KEY_PASSPHRASE"),
        ])
        .expect("parse");

        match certificate_invocation.command {
            Some(VaultCommand::ImportTransfer {
                input,
                replace_existing,
                package_password_env,
                package_cert_path,
                package_key_path,
                package_key_passphrase_env,
            }) => {
                assert_eq!(input, PathBuf::from("vault-transfer.json"));
                assert!(!replace_existing);
                assert!(package_password_env.is_none());
                assert_eq!(package_cert_path, Some(PathBuf::from("recipient.pem")));
                assert_eq!(package_key_path, Some(PathBuf::from("recipient-key.pem")));
                assert_eq!(
                    package_key_passphrase_env.as_deref(),
                    Some("PARANOID_TRANSFER_KEY_PASSPHRASE")
                );
            }
            _ => panic!("expected import-transfer certificate command"),
        }
    }

    #[test]
    fn parse_add_note_supports_title_and_content() {
        let command = parse_vault_args(&[
            OsString::from("add-note"),
            OsString::from("--title"),
            OsString::from("Recovery"),
            OsString::from("--content"),
            OsString::from("paper copy"),
            OsString::from("--folder"),
            OsString::from("Recovery"),
            OsString::from("--tags"),
            OsString::from("recovery,offline"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::AddNote { record }) => {
                assert_eq!(record.title, "Recovery");
                assert_eq!(record.content, "paper copy");
                assert_eq!(record.folder.as_deref(), Some("Recovery"));
                assert_eq!(record.tags, vec!["recovery", "offline"]);
            }
            _ => panic!("expected add-note command"),
        }
    }

    #[test]
    fn parse_add_identity_supports_full_name_and_contact_fields() {
        let command = parse_vault_args(&[
            OsString::from("add-identity"),
            OsString::from("--title"),
            OsString::from("Personal Identity"),
            OsString::from("--full-name"),
            OsString::from("Jon Bogaty"),
            OsString::from("--email"),
            OsString::from("jon@example.com"),
            OsString::from("--phone"),
            OsString::from("+1-555-0100"),
            OsString::from("--tags"),
            OsString::from("identity,travel"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::AddIdentity { record }) => {
                assert_eq!(record.title, "Personal Identity");
                assert_eq!(record.full_name, "Jon Bogaty");
                assert_eq!(record.email.as_deref(), Some("jon@example.com"));
                assert_eq!(record.phone.as_deref(), Some("+1-555-0100"));
                assert_eq!(record.tags, vec!["identity", "travel"]);
            }
            _ => panic!("expected add-identity command"),
        }
    }

    #[test]
    fn parse_add_supports_folder_metadata() {
        let command = parse_vault_args(&[
            OsString::from("add"),
            OsString::from("--title"),
            OsString::from("GitHub"),
            OsString::from("--username"),
            OsString::from("octocat"),
            OsString::from("--password"),
            OsString::from("hunter2"),
            OsString::from("--folder"),
            OsString::from("Work"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::Add { record }) => {
                assert_eq!(record.folder.as_deref(), Some("Work"));
            }
            _ => panic!("expected add command"),
        }
    }

    #[test]
    fn parse_update_supports_clearing_folder() {
        let command = parse_vault_args(&[
            OsString::from("update"),
            OsString::from("--id"),
            OsString::from("abc123"),
            OsString::from("--clear-folder"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::Update { id, update }) => {
                assert_eq!(id, "abc123");
                assert_eq!(update.folder, Some(None));
            }
            _ => panic!("expected update command"),
        }
    }

    #[test]
    fn parse_generate_store_supports_rotating_existing_login() {
        let command = parse_vault_args(&[
            OsString::from("generate-store"),
            OsString::from("--id"),
            OsString::from("login-123"),
            OsString::from("--length"),
            OsString::from("24"),
        ])
        .expect("parse");

        match command.command {
            Some(VaultCommand::GenerateStore {
                target_login_id,
                title,
                username,
                request,
                ..
            }) => {
                assert_eq!(target_login_id.as_deref(), Some("login-123"));
                assert!(title.is_none());
                assert!(username.is_none());
                assert_eq!(request.length, 24);
            }
            _ => panic!("expected generate-store command"),
        }
    }

    #[test]
    fn vault_defaults_to_tui_without_a_subcommand() {
        let invocation = parse_vault_args(&[]).expect("parse");
        assert!(matches!(invocation.mode, LaunchMode::Auto));
        assert!(invocation.command.is_none());
        assert!(should_launch_tui(&invocation, true));
    }

    #[test]
    fn vault_cli_flag_disables_implicit_tui_launch() {
        let invocation = parse_vault_args(&[OsString::from("--cli")]).expect("parse");
        assert!(matches!(invocation.mode, LaunchMode::Cli));
        assert!(invocation.command.is_none());
        assert!(!should_launch_tui(&invocation, true));
    }
}
