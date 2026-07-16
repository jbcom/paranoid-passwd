use crate::vault_tui::*;
use arboard::Clipboard;
use paranoid_vault::{NewCardRecord, NewIdentityRecord, NewLoginRecord, NewSecureNoteRecord};
use std::fs;

impl App {
    pub(crate) fn submit_login_form(&mut self) {
        let record = NewLoginRecord {
            title: self.add_login_form.title.trim().to_string(),
            username: self.add_login_form.username.trim().to_string(),
            password: self.add_login_form.password.clone(),
            url: normalize_optional_field(&self.add_login_form.url),
            notes: normalize_optional_field(&self.add_login_form.notes),
            folder: normalize_optional_field(&self.add_login_form.folder),
            tags: parse_tags_csv(&self.add_login_form.tags),
        };

        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_login_update(item_id, record),
            None => self.submit_login_create(record),
        }
    }

    pub(crate) fn submit_note_form(&mut self) {
        let record = NewSecureNoteRecord {
            title: self.note_form.title.trim().to_string(),
            content: self.note_form.content.trim().to_string(),
            folder: normalize_optional_field(&self.note_form.folder),
            tags: parse_tags_csv(&self.note_form.tags),
        };

        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_note_update(item_id, record),
            None => self.submit_note_create(record),
        }
    }

    pub(crate) fn submit_card_form(&mut self) {
        let record = NewCardRecord {
            title: self.card_form.title.trim().to_string(),
            cardholder_name: self.card_form.cardholder_name.trim().to_string(),
            number: self.card_form.number.trim().to_string(),
            expiry_month: self.card_form.expiry_month.trim().to_string(),
            expiry_year: self.card_form.expiry_year.trim().to_string(),
            security_code: self.card_form.security_code.trim().to_string(),
            billing_zip: normalize_optional_field(&self.card_form.billing_zip),
            notes: normalize_optional_field(&self.card_form.notes),
            folder: normalize_optional_field(&self.card_form.folder),
            tags: parse_tags_csv(&self.card_form.tags),
        };
        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_card_update(item_id, record),
            None => self.submit_card_create(record),
        }
    }

    pub(crate) fn submit_identity_form(&mut self) {
        let record = NewIdentityRecord {
            title: self.identity_form.title.trim().to_string(),
            full_name: self.identity_form.full_name.trim().to_string(),
            email: normalize_optional_field(&self.identity_form.email),
            phone: normalize_optional_field(&self.identity_form.phone),
            address: normalize_optional_field(&self.identity_form.address),
            notes: normalize_optional_field(&self.identity_form.notes),
            folder: normalize_optional_field(&self.identity_form.folder),
            tags: parse_tags_csv(&self.identity_form.tags),
        };
        match self.editing_item_id.clone() {
            Some(item_id) => self.submit_identity_update(item_id, record),
            None => self.submit_identity_create(record),
        }
    }

    pub(crate) fn submit_login_create(&mut self, record: NewLoginRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault.add_login(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Stored login item {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored login item {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Store failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Store failed: {error}");
            }
        }
    }

    pub(crate) fn submit_login_update(&mut self, item_id: String, record: NewLoginRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault
                .update_login(
                    &item_id,
                    paranoid_vault::UpdateLoginRecord {
                        title: Some(record.title),
                        username: Some(record.username),
                        password: Some(record.password),
                        url: Some(record.url),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated login item {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated login item {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Update failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Update failed: {error}");
            }
        }
    }

    pub(crate) fn submit_note_create(&mut self, record: NewSecureNoteRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault.add_secure_note(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Stored secure note {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored secure note {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Store failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Store failed: {error}");
            }
        }
    }

    pub(crate) fn submit_note_update(&mut self, item_id: String, record: NewSecureNoteRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault
                .update_secure_note(
                    &item_id,
                    UpdateSecureNoteRecord {
                        title: Some(record.title),
                        content: Some(record.content),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated secure note {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated secure note {item_id} in the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Update failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Update failed: {error}");
            }
        }
    }

    pub(crate) fn submit_card_create(&mut self, record: NewCardRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault.add_card(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status = format!("Stored card {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored card {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Store failed: {error}"),
            },
            Err(error) => self.status = format!("Store failed: {error}"),
        }
    }

    pub(crate) fn submit_card_update(&mut self, item_id: String, record: NewCardRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault
                .update_card(
                    &item_id,
                    UpdateCardRecord {
                        title: Some(record.title),
                        cardholder_name: Some(record.cardholder_name),
                        number: Some(record.number),
                        expiry_month: Some(record.expiry_month),
                        expiry_year: Some(record.expiry_year),
                        security_code: Some(record.security_code),
                        billing_zip: Some(record.billing_zip),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated card {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated card {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Update failed: {error}"),
            },
            Err(error) => self.status = format!("Update failed: {error}"),
        }
    }

    pub(crate) fn submit_identity_create(&mut self, record: NewIdentityRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault.add_identity(record).map_err(anyhow::Error::from) {
                Ok(item) => {
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Stored identity {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Stored identity {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Store failed: {error}"),
            },
            Err(error) => self.status = format!("Store failed: {error}"),
        }
    }

    pub(crate) fn submit_identity_update(&mut self, item_id: String, record: NewIdentityRecord) {
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault
                .update_identity(
                    &item_id,
                    UpdateIdentityRecord {
                        title: Some(record.title),
                        full_name: Some(record.full_name),
                        email: Some(record.email),
                        phone: Some(record.phone),
                        address: Some(record.address),
                        notes: Some(record.notes),
                        folder: Some(record.folder),
                        tags: Some(record.tags),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok(item) => {
                    let item_id = item.id.clone();
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status =
                            format!("Updated identity {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!("Updated identity {item_id} in the encrypted vault.");
                }
                Err(error) => self.status = format!("Update failed: {error}"),
            },
            Err(error) => self.status = format!("Update failed: {error}"),
        }
    }

    pub(crate) fn submit_generate_store(&mut self) {
        let request = match build_generate_request(&self.generate_store_form) {
            Ok(request) => request,
            Err(error) => {
                self.status = format!("Generation request blocked: {error}");
                return;
            }
        };
        let title = self.generate_store_form.title.trim().to_string();
        let username = self.generate_store_form.username.trim().to_string();
        if self.generate_store_form.target_login_id.is_none()
            && (title.is_empty() || username.is_empty())
        {
            self.status = "Generation store requires both a title and username.".to_string();
            return;
        }

        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault
                .generate_and_store(
                    &request,
                    GenerateStoreLoginRecord {
                        target_login_id: self.generate_store_form.target_login_id.clone(),
                        title: (!title.is_empty()).then(|| title.clone()),
                        username: (!username.is_empty()).then(|| username.clone()),
                        url: normalize_optional_field(&self.generate_store_form.url),
                        notes: normalize_optional_field(&self.generate_store_form.notes),
                        folder: normalize_optional_field(&self.generate_store_form.folder),
                        tags: Some(parse_tags_csv(&self.generate_store_form.tags)),
                    },
                )
                .map_err(anyhow::Error::from)
            {
                Ok((report, item)) => {
                    let verdict = report
                        .audit
                        .as_ref()
                        .map(|audit| if audit.overall_pass { "PASS" } else { "REVIEW" })
                        .unwrap_or("PASS");
                    let item_id = item.id.clone();
                    if let Err(error) = self.reload_vault_state(Some(item_id.as_str())) {
                        self.screen = Screen::Vault;
                        self.status = format!(
                            "Generated and stored {item_id} ({verdict}), but refresh failed: {error}"
                        );
                        return;
                    }
                    self.screen = Screen::Vault;
                    self.status = format!(
                        "Generated one password and {} item {item_id}. Generator verdict: {verdict}.",
                        if self.generate_store_form.target_login_id.is_some() {
                            "rotated"
                        } else {
                            "stored"
                        }
                    );
                }
                Err(error) => {
                    self.status = format!("Generate-and-store failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Generate-and-store failed: {error}");
            }
        }
    }

    pub(crate) fn submit_export_backup(&mut self) {
        let output = self.export_backup_form.path.trim().to_string();
        if output.is_empty() {
            self.status = "Backup export requires an output path.".to_string();
            return;
        }
        match self.unlock_for_operation("export", VaultOperationAccess::Export) {
            Ok(vault) => match vault
                .export_backup(output.as_str())
                .map_err(anyhow::Error::from)
            {
                Ok(path) => {
                    self.screen = Screen::Vault;
                    self.status = format!("Exported encrypted vault backup to {}.", path.display());
                }
                Err(error) => {
                    self.status = format!("Backup export failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Backup export failed: {error}");
            }
        }
    }

    pub(crate) fn submit_import_backup(&mut self) {
        let input = self.import_backup_form.path.trim().to_string();
        if input.is_empty() {
            self.status = "Backup import requires an input path.".to_string();
            return;
        }
        if let Err(error) =
            self.record_vault_operation_policy("mutate_item", VaultOperationAccess::Mutate)
        {
            self.status = format!("Backup import failed: {error}");
            return;
        }
        match restore_vault_backup(
            input.as_str(),
            &self.options.path,
            self.import_backup_form.overwrite,
        )
        .map_err(anyhow::Error::from)
        {
            Ok(_) => {
                let source = input.to_string();
                self.refresh();
                self.status = format!(
                    "Imported encrypted vault backup from {} into {}.",
                    source,
                    self.options.path.display()
                );
            }
            Err(error) => {
                self.status = format!("Backup import failed: {error}");
            }
        }
    }

    pub(crate) fn submit_export_transfer(&mut self) {
        let output = self.export_transfer_form.path.trim().to_string();
        if output.is_empty() {
            self.status = "Transfer export requires an output path.".to_string();
            return;
        }

        let package_password =
            normalize_optional_secret(&self.export_transfer_form.package_password);
        let cert_path = normalize_optional_field(&self.export_transfer_form.cert_path);
        if package_password.is_none() && cert_path.is_none() {
            self.status =
                "Transfer export requires a package recovery secret, recipient certificate, or both."
                    .to_string();
            return;
        }

        match self.unlock_for_operation("export", VaultOperationAccess::Export) {
            Ok(vault) => {
                let cert_pem = match cert_path {
                    Some(ref path) => match fs::read(path) {
                        Ok(pem) => Some(pem),
                        Err(error) => {
                            self.status = format!("Transfer export failed: {error}");
                            return;
                        }
                    },
                    None => None,
                };
                match vault
                    .export_transfer_package(
                        output.as_str(),
                        &self.filters.as_filter(),
                        package_password.as_ref().map(SecretString::as_str),
                        cert_pem.as_deref(),
                    )
                    .map_err(anyhow::Error::from)
                {
                    Ok(path) => {
                        self.screen = Screen::Vault;
                        self.status = format!(
                            "Exported encrypted transfer package for {} current item(s) to {}.",
                            self.items.len(),
                            path.display()
                        );
                    }
                    Err(error) => {
                        self.status = format!("Transfer export failed: {error}");
                    }
                }
            }
            Err(error) => {
                self.status = format!("Transfer export failed: {error}");
            }
        }
    }

    pub(crate) fn submit_import_transfer(&mut self) {
        let input = self.import_transfer_form.path.trim().to_string();
        if input.is_empty() {
            self.status = "Transfer import requires an input path.".to_string();
            return;
        }

        let package_password =
            normalize_optional_secret(&self.import_transfer_form.package_password);
        let cert_path = normalize_optional_field(&self.import_transfer_form.cert_path);
        let key_path = normalize_optional_field(&self.import_transfer_form.key_path);
        let key_passphrase = normalize_optional_secret(&self.import_transfer_form.key_passphrase);
        let use_password = package_password.is_some();
        let use_certificate = cert_path.is_some() || key_path.is_some();
        if use_password && use_certificate {
            self.status =
                "Transfer import requires either a package recovery secret or a certificate keypair, not both."
                    .to_string();
            return;
        }
        if !use_password && !use_certificate {
            self.status =
                "Transfer import requires a package recovery secret or a certificate keypair."
                    .to_string();
            return;
        }
        if use_certificate && (cert_path.is_none() || key_path.is_none()) {
            self.status =
                "Transfer import requires both a recipient certificate path and private key path."
                    .to_string();
            return;
        }

        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => {
                let result = if let Some(password) = package_password {
                    vault.import_transfer_package_with_password(
                        input.as_str(),
                        password.as_str(),
                        self.import_transfer_form.replace_existing,
                    )
                } else {
                    let cert_pem = match fs::read(cert_path.as_deref().unwrap_or_default()) {
                        Ok(pem) => pem,
                        Err(error) => {
                            self.status = format!("Transfer import failed: {error}");
                            return;
                        }
                    };
                    let key_pem = match fs::read(key_path.as_deref().unwrap_or_default()) {
                        Ok(pem) => pem,
                        Err(error) => {
                            self.status = format!("Transfer import failed: {error}");
                            return;
                        }
                    };
                    vault.import_transfer_package_with_certificate(
                        input.as_str(),
                        cert_pem.as_slice(),
                        key_pem.as_slice(),
                        key_passphrase.as_ref().map(SecretString::as_str),
                        self.import_transfer_form.replace_existing,
                    )
                };
                match result.map_err(anyhow::Error::from) {
                    Ok(summary) => {
                        self.refresh();
                        self.status = format!(
                            "Imported transfer package from {}. imported={} replaced={} remapped={}.",
                            input,
                            summary.imported_count,
                            summary.replaced_count,
                            summary.remapped_count
                        );
                    }
                    Err(error) => {
                        self.status = format!("Transfer import failed: {error}");
                    }
                }
            }
            Err(error) => {
                self.status = format!("Transfer import failed: {error}");
            }
        }
    }

    pub(crate) fn submit_mnemonic_slot(&mut self) {
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .add_mnemonic_keyslot(normalize_optional_field(&self.mnemonic_slot_form.label))
                .map_err(anyhow::Error::from)
            {
                Ok(enrollment) => {
                    self.header = Some(vault.header().clone());
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .map(|h| h.keyslots.len().saturating_sub(1))
                        .unwrap_or(0);
                    self.latest_mnemonic_enrollment = Some(enrollment);
                    self.screen = Screen::MnemonicReveal;
                    self.status = "Mnemonic recovery slot enrolled. Capture the phrase offline before leaving this screen."
                        .to_string();
                }
                Err(error) => {
                    self.status = format!("Mnemonic enrollment failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Mnemonic enrollment failed: {error}");
            }
        }
    }

    pub(crate) fn submit_rotate_mnemonic_slot(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to rotate.".to_string();
            return;
        };
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .rotate_mnemonic_keyslot(&slot.id)
                .map_err(anyhow::Error::from)
            {
                Ok(enrollment) => {
                    self.header = Some(vault.header().clone());
                    self.sync_rotated_mnemonic_unlock(&enrollment);
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == enrollment.keyslot.id)
                        })
                        .unwrap_or(0);
                    self.latest_mnemonic_enrollment = Some(enrollment);
                    self.screen = Screen::MnemonicReveal;
                    self.status = "Mnemonic recovery slot rotated. Capture the replacement phrase offline before leaving this screen.".to_string();
                }
                Err(error) => {
                    self.status = format!("Mnemonic rotation failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Mnemonic rotation failed: {error}");
            }
        }
    }

    pub(crate) fn submit_device_slot(&mut self) {
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .add_device_keyslot(normalize_optional_field(&self.device_slot_form.label))
                .map_err(anyhow::Error::from)
            {
                Ok(slot) => {
                    self.header = Some(vault.header().clone());
                    self.sync_device_fallback_target(Some(slot.id.as_str()));
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == slot.id)
                        })
                        .unwrap_or(0);
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Enrolled device-bound keyslot {} in secure storage.",
                        slot.id
                    );
                }
                Err(error) => {
                    self.status = format!("Device keyslot enrollment failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Device keyslot enrollment failed: {error}");
            }
        }
    }

    pub(crate) fn submit_certificate_slot(&mut self) {
        let cert_path = self.certificate_slot_form.cert_path.trim();
        if cert_path.is_empty() {
            self.status = "Certificate enrollment requires a PEM path.".to_string();
            return;
        }
        match fs::read(cert_path) {
            Ok(cert_pem) => {
                match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot)
                {
                    Ok(mut vault) => match vault
                        .add_certificate_keyslot(
                            cert_pem.as_slice(),
                            normalize_optional_field(&self.certificate_slot_form.label),
                        )
                        .map_err(anyhow::Error::from)
                    {
                        Ok(slot) => {
                            self.header = Some(vault.header().clone());
                            self.selected_keyslot_index = self
                                .header
                                .as_ref()
                                .and_then(|header| {
                                    header
                                        .keyslots
                                        .iter()
                                        .position(|candidate| candidate.id == slot.id)
                                })
                                .unwrap_or(0);
                            self.screen = Screen::Keyslots;
                            self.status = format!(
                                "Enrolled certificate keyslot {} for fingerprint {} (valid until {}).",
                                slot.id,
                                slot.certificate_fingerprint_sha256.unwrap_or_default(),
                                slot.certificate_not_after.unwrap_or_default()
                            );
                        }
                        Err(error) => {
                            self.status = format!("Certificate keyslot enrollment failed: {error}");
                        }
                    },
                    Err(error) => {
                        self.status = format!("Certificate keyslot enrollment failed: {error}");
                    }
                }
            }
            Err(error) => {
                self.status = format!("Certificate read failed: {error}");
            }
        }
    }

    pub(crate) fn submit_certificate_slot_rewrap(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to rewrap.".to_string();
            return;
        };
        let cert_path = self.certificate_rewrap_form.cert_path.trim().to_string();
        if cert_path.is_empty() {
            self.status = "Certificate rewrap requires a PEM path.".to_string();
            return;
        }
        let replacement_key_path = normalize_optional_field(&self.certificate_rewrap_form.key_path);
        let replacement_key_passphrase =
            normalize_optional_secret(&self.certificate_rewrap_form.key_passphrase);
        match fs::read(&cert_path) {
            Ok(cert_pem) => {
                match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot)
                {
                    Ok(mut vault) => match vault
                        .rewrap_certificate_keyslot(&slot.id, cert_pem.as_slice())
                        .map_err(anyhow::Error::from)
                    {
                        Ok(updated) => {
                            self.sync_rewrapped_certificate_unlock(
                                &slot,
                                cert_path.as_str(),
                                replacement_key_path.as_deref(),
                                replacement_key_passphrase.as_ref(),
                            );
                            self.header = Some(vault.header().clone());
                            self.selected_keyslot_index = self
                                .header
                                .as_ref()
                                .and_then(|header| {
                                    header
                                        .keyslots
                                        .iter()
                                        .position(|candidate| candidate.id == updated.id)
                                })
                                .unwrap_or(0);
                            self.screen = Screen::Keyslots;
                            self.status = format!(
                                "Rewrapped certificate keyslot {} to fingerprint {} (valid until {}). Active certificate session settings were preserved or updated if this was the active cert slot.",
                                updated.id,
                                updated.certificate_fingerprint_sha256.unwrap_or_default(),
                                updated.certificate_not_after.unwrap_or_default()
                            );
                        }
                        Err(error) => {
                            self.status = format!("Certificate keyslot rewrap failed: {error}");
                        }
                    },
                    Err(error) => {
                        self.status = format!("Certificate keyslot rewrap failed: {error}");
                    }
                }
            }
            Err(error) => {
                self.status = format!("Certificate read failed: {error}");
            }
        }
    }

    pub(crate) fn submit_keyslot_label_edit(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to relabel.".to_string();
            return;
        };
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .relabel_keyslot(
                    &slot.id,
                    normalize_optional_field(&self.keyslot_label_form.label),
                )
                .map_err(anyhow::Error::from)
            {
                Ok(updated) => {
                    self.header = Some(vault.header().clone());
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == updated.id)
                        })
                        .unwrap_or(0);
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Updated {} keyslot {} label to {}.",
                        updated.kind.as_str(),
                        updated.id,
                        updated.label.unwrap_or_else(|| "(cleared)".to_string())
                    );
                }
                Err(error) => {
                    self.status = format!("Keyslot relabel failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Keyslot relabel failed: {error}");
            }
        }
    }

    pub(crate) fn submit_rotate_recovery_secret(&mut self) {
        if self.recovery_secret_form.new_secret.is_empty() {
            self.status = "Recovery secret rotation requires a non-empty new secret.".to_string();
            return;
        }
        if self.recovery_secret_form.new_secret != self.recovery_secret_form.confirm_secret {
            self.status = "Recovery secret rotation requires matching confirmation.".to_string();
            return;
        }

        let new_secret = self.recovery_secret_form.new_secret.clone();
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .rotate_password_recovery_keyslot(new_secret.as_str())
                .map_err(anyhow::Error::from)
            {
                Ok(keyslot) => {
                    self.header = Some(vault.header().clone());
                    if matches!(
                        self.options.auth,
                        VaultAuth::PasswordEnv(_) | VaultAuth::Password(_)
                    ) {
                        self.options.auth = VaultAuth::Password(new_secret);
                    }
                    self.recovery_secret_form = RecoverySecretForm::default();
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Rotated password recovery keyslot {} with {}.",
                        keyslot.id, keyslot.wrap_algorithm
                    );
                }
                Err(error) => {
                    self.status = format!("Recovery secret rotation failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Recovery secret rotation failed: {error}");
            }
        }
    }

    pub(crate) fn remove_selected_keyslot(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to remove.".to_string();
            return;
        };
        let Some(header) = self.header.as_ref() else {
            self.status = "No vault header loaded for keyslot analysis.".to_string();
            return;
        };
        let impact = match header.assess_keyslot_removal(&slot.id) {
            Ok(impact) => impact,
            Err(error) => {
                self.status = format!("Keyslot removal failed: {error}");
                return;
            }
        };
        let force = self.pending_keyslot_removal_confirmation.as_deref() == Some(slot.id.as_str());
        if impact.requires_explicit_confirmation && !force {
            self.pending_keyslot_removal_confirmation = Some(slot.id.clone());
            self.status = format!(
                "Removal of {} requires confirmation: {} Press d again to confirm.",
                slot.id,
                impact.warnings.join(" ")
            );
            return;
        }
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .remove_keyslot(&slot.id, force)
                .map_err(anyhow::Error::from)
            {
                Ok(removed) => {
                    self.header = Some(vault.header().clone());
                    self.sync_device_fallback_target(None);
                    let remaining = self
                        .header
                        .as_ref()
                        .map(|header| header.keyslots.len())
                        .unwrap_or_default();
                    self.selected_keyslot_index =
                        self.selected_keyslot_index.min(remaining.saturating_sub(1));
                    self.pending_keyslot_removal_confirmation = None;
                    self.screen = Screen::Keyslots;
                    self.status =
                        format!("Removed {} keyslot {}.", removed.kind.as_str(), removed.id);
                }
                Err(error) => {
                    self.pending_keyslot_removal_confirmation = None;
                    self.status = format!("Keyslot removal failed: {error}");
                }
            },
            Err(error) => {
                self.pending_keyslot_removal_confirmation = None;
                self.status = format!("Keyslot removal failed: {error}");
            }
        }
    }

    pub(crate) fn rebind_selected_device_keyslot(&mut self) {
        let Some(slot) = selected_keyslot(self).cloned() else {
            self.status = "No keyslot selected to rebind.".to_string();
            return;
        };
        self.pending_keyslot_removal_confirmation = None;
        match self.unlock_for_operation("keyslot_lifecycle", VaultOperationAccess::Keyslot) {
            Ok(mut vault) => match vault
                .rebind_device_keyslot(&slot.id)
                .map_err(anyhow::Error::from)
            {
                Ok(updated) => {
                    self.header = Some(vault.header().clone());
                    self.sync_device_fallback_target(Some(updated.id.as_str()));
                    self.selected_keyslot_index = self
                        .header
                        .as_ref()
                        .and_then(|header| {
                            header
                                .keyslots
                                .iter()
                                .position(|candidate| candidate.id == updated.id)
                        })
                        .unwrap_or(0);
                    self.screen = Screen::Keyslots;
                    self.status = format!(
                        "Rebound device-bound keyslot {} to secure-storage account {}.",
                        updated.id,
                        updated.device_account.unwrap_or_default()
                    );
                }
                Err(error) => {
                    self.status = format!("Device keyslot rebind failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Device keyslot rebind failed: {error}");
            }
        }
    }

    pub(crate) fn delete_selected_item(&mut self) {
        let Some(detail) = &self.detail else {
            self.screen = Screen::Vault;
            self.status = "No vault item selected to delete.".to_string();
            return;
        };
        let item_id = detail.id.clone();
        match self.unlock_for_operation("mutate_item", VaultOperationAccess::Mutate) {
            Ok(vault) => match vault.delete_item(&item_id).map_err(anyhow::Error::from) {
                Ok(()) => {
                    self.screen = Screen::Vault;
                    self.editing_item_id = None;
                    if let Err(error) = self.reload_vault_state(None) {
                        self.status =
                            format!("Deleted item {item_id}, but refresh failed: {error}");
                        return;
                    }
                    self.status = format!("Deleted vault item {item_id} from the encrypted vault.");
                }
                Err(error) => {
                    self.status = format!("Delete failed: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Delete failed: {error}");
            }
        }
    }

    pub(crate) fn reload_detail(&mut self) {
        let Some(item_id) = self
            .items
            .get(self.selected_index)
            .map(|item| item.id.clone())
        else {
            self.detail = None;
            return;
        };

        match self.unlock_for_operation("read_item", VaultOperationAccess::Decrypt) {
            Ok(vault) => match vault
                .get_item(&item_id)
                .map_err(anyhow::Error::from)
                .context("failed to reload selected vault item")
            {
                Ok(detail) => {
                    self.detail = Some(detail);
                }
                Err(error) => {
                    self.detail = None;
                    self.status = format!("Detail reload failed: {error}");
                }
            },
            Err(error) => {
                self.detail = None;
                self.status = format!("Detail reload failed: {error}");
            }
        }
    }

    pub(crate) fn copy_selected_secret(&mut self) {
        let Some(payload) = self.detail.as_ref().map(|item| &item.payload) else {
            self.status = "No vault item selected to copy.".to_string();
            return;
        };
        let content = match payload {
            VaultItemPayload::Login(login) => login.password.clone(),
            VaultItemPayload::SecureNote(note) => note.content.clone(),
            VaultItemPayload::Card(card) => card.number.clone(),
            VaultItemPayload::Identity(identity) => identity
                .email
                .clone()
                .or_else(|| identity.phone.clone())
                .unwrap_or_else(|| identity.full_name.clone()),
        };
        if let Err(error) =
            self.record_vault_operation_policy("read_item", VaultOperationAccess::Decrypt)
        {
            self.status = format!("Copy blocked: {error}");
            return;
        }
        match Clipboard::new().and_then(|mut clipboard| clipboard.set_text(content.clone())) {
            Ok(()) => {
                self.session.arm_clipboard_clear(content);
                self.status = format!(
                    "Copied the selected vault secret to the clipboard. It will be cleared in {} seconds if unchanged.",
                    self.session.clipboard_clear_after().as_secs()
                );
            }
            Err(error) => {
                self.status = format!("Clipboard unavailable: {error}");
            }
        }
    }

    pub(crate) fn copy_latest_mnemonic(&mut self) {
        let Some(enrollment) = &self.latest_mnemonic_enrollment else {
            self.status = "No mnemonic phrase is available to copy.".to_string();
            return;
        };
        match Clipboard::new()
            .and_then(|mut clipboard| clipboard.set_text(enrollment.mnemonic.clone()))
        {
            Ok(()) => {
                self.session
                    .arm_clipboard_clear(enrollment.mnemonic.clone());
                self.status = format!(
                    "Copied the current mnemonic recovery phrase to the clipboard. It will be cleared in {} seconds if unchanged.",
                    self.session.clipboard_clear_after().as_secs()
                );
            }
            Err(error) => {
                self.status = format!("Clipboard unavailable: {error}");
            }
        }
    }
}
