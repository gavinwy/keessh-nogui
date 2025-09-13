// SPDX-FileCopyrightText: Copyright 2025 Gavin Weifert-Yeh
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause OR ISC OR MIT

use crate::FileEncoding::{
    Binary, UTF_16_BE, UTF_16_LE, UTF_32_BE, UTF_32_LE, UTF_7, UTF_8,
};
use anyhow::{anyhow, Context, Result};
use clap::{crate_version, Parser};
use keepass::db::Entry;
use keepass::{db::NodeRef, error::DatabaseOpenError, Database, DatabaseKey};
use num_bigint_dig::BigUint;
use num_traits::cast::FromPrimitive;
use serde_derive::Deserialize;
use serde_xml_rs::from_reader;
use ssh_agent_client_rs::Client;
use ssh_key::{Mpint, PrivateKey, PublicKey};
use std::collections::HashMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, u32};

const AUTO_OPEN_MAX_DEPTH: u32 = 8;
const AUTO_OPEN_MAX_WIDTH: u32 = 10;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
enum FileEncoding {
    Binary,
    UTF_7,
    UTF_8,
    UTF_16_LE,
    UTF_16_BE,
    UTF_32_LE,
    UTF_32_BE,
}

#[derive(Parser, Debug)]
#[command(name = "keessh")]
#[command(version = crate_version!())]
#[command(
    about = "CLI only ssh-agent client using KeePass files. Compatible with KeeAgent and KeepassXC keys."
)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[arg(group = "auto-open", long, default_value = "false")]
    no_auto_open: bool,

    #[arg(
        group = "strict-crypto",
        long = "use-strict-crypto",
        alias = "strict",
        help = "refuse to use insecure keys, rather than just warn."
    )]
    strict_crypto: bool,

    #[arg(
        group = "strict-crypto",
        long = "suppress-crypto-warnings",
        default_value = "false"
    )]
    suppress_crypto_warnings: bool,

    vault_path: Option<PathBuf>,
}

// TODO Consider not using Strings here
#[derive(Deserialize, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
struct KASetLocation {
    SelectedType: String,
    AttachmentName: String,
    SaveAttachmentToTempFile: bool,
    FileName: String,
}

#[derive(Deserialize, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
struct KeeagentSettings {
    AllowUseOfSshKey: bool,
    AddAtDatabaseOpen: bool,
    RemoveAtDatabaseClose: bool,
    UseConfirmConstraintWhenAdding: bool,
    UseLifetimeConstraintWhenAdding: bool,
    LifetimeConstraintDuration: i64,
    UseDestinationConstraintWhenAdding: Option<bool>, // Optional or missing on KXC
    DestinationConstraints: Option<String>,           // Optional or missing on KXC
    Location: KASetLocation,
}

#[derive(Debug, Eq, PartialEq)]
struct KeesshSettings {
    auto_open_recursion_enable: bool,
    strict_crypto_enabled: bool,
    suppress_crypto_warnings: bool,
    vault_location_preset: Option<String>,
}

impl Default for KeesshSettings {
    fn default() -> Self {
        KeesshSettings {
            auto_open_recursion_enable: true,
            strict_crypto_enabled: false,
            suppress_crypto_warnings: false,
            vault_location_preset: None,
        }
    }
}

impl KeesshSettings {
    fn new() -> Self {
        let mut s = KeesshSettings::default();
        if env::var("KEESSH_AUTO_OPEN").is_ok() {
            if is_falsey(env::var("KEESSH_AUTO_OPEN").unwrap()) {
                s.auto_open_recursion_enable = false;
            }
        }
        if env::var("KEESSH_STRICT_CRYPTO").is_ok() {
            if !is_falsey(env::var("KEESSH_STRICT_CRYPTO").unwrap()) {
                s.strict_crypto_enabled = true;
            }
        }
        if env::var("KEESSH_NO_CRYPTO_WARNINGS").is_ok() {
            s.suppress_crypto_warnings = true;
        }
        if env::var("KEESSH_VAULT").is_ok() {
            if Path::exists(env::var("KEESSH_VAULT").unwrap().as_ref()) {
                s.vault_location_preset = Some(env::var("KEESSH_VAULT").unwrap());
            }
        }
        s
    }
}

#[derive(Debug)]
struct SshKey {
    private_key: PrivateKey,
    public_key: PublicKey,
    settings: KeeagentSettings,
}

impl SshKey {
    // TODO could this be more idiomatic with TryFrom?
    fn from_entry(e: &Entry, db: &Database) -> Result<Self> {
        let settings_location = &e.attachment_refs["KeeAgent.settings"];
        let attachment = get_attachment_content(
            db,
            usize::from_u8((*settings_location).parse().unwrap()).unwrap(),
        ); // TODO Has to be a better way to do this
        let settings: KeeagentSettings =
            parse_keeagent_settings(attachment).context("failed to parse KeeAgent settings")?;

        let private_key_location = &e.attachment_refs[&settings.Location.AttachmentName];
        let private_key_file = get_attachment_content(
            db,
            usize::from_u8((*private_key_location).parse().unwrap()).unwrap(),
        );
        let private_key = PrivateKey::from_openssh(&private_key_file)
            .context("failed to load private key from attachment.")?;
        let public_key = private_key.public_key();

        Ok(Self {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            settings,
        })
    }
}

fn is_falsey(s: String) -> bool {
    // For reading env vars, can't get truthy/falsey from clap, so do this.
    // TODO probably a better way to do this, maybe with a library
    if i32::from_str(&s).is_ok() {
        if i32::from_str(&s).unwrap() == 0 {
            return true;
        }
    }
    if s.to_ascii_lowercase() == "false" {
        return true;
    }
    if s.to_ascii_lowercase() == "no" {
        return true;
    }
    false
}

fn get_auto_open_dbs(db: &Database) -> Result<HashMap<PathBuf, DatabaseKey>> {
    // Warning: Here be Dragons (recursion). TODO This can probably be done much better.
    //
    // The KeePass Extension KeeAutoExec, and KeePassXC support automatically opening databases
    // after a main database is opened. These sub databases must be directly under a group named
    // "AutoOpen" that is directly under the root of the vault. Those databases are specified as
    // entries, with the URL referring to the database file location, and the password referring
    // to the password for the database. keessh also supports this, and it's implemented here.
    //
    // There's a maximum depth and a maximum breadth for the recursion so it shouldn't be possible
    // to hose yourself with this too badly, and if you do, you'll probably notice you're hosed
    // sooner with KeeAutoExec or KeePassXC. Hopefully this will also prevent any bugs from causing
    // problems, but it's possible.
    //
    // I doubt any actual problems will come of this, AutoOpen is rare and anyone using it
    // recursively should already know what can happen.

    let mut new_dbs: HashMap<PathBuf, DatabaseKey> = HashMap::new();
    let mut duplicate_dbs: Vec<PathBuf> = Vec::new();
    if db.root.get(&["AutoOpen"]).is_none() {
        return Ok(new_dbs);
    }
    let auto_open_group_children = match db.root.get(&["AutoOpen"]).unwrap() {
        NodeRef::Entry(_) => return Ok(new_dbs), // If AutoOpen isn't a group, return.
        NodeRef::Group(g) => &g.children,
    };

    // This section should prevent the same database opening multiple times.
    for child in auto_open_group_children {
        let child_node = get_sub_db(NodeRef::from(child));
        if child_node.is_ok() {
            let child_entry = child_node?;

            // Check if child_entry is already considered a duplicate.
            for db_pathbuf in &duplicate_dbs {
                if child_entry.contains_key(db_pathbuf) {
                    anyhow!("Same database can't be auto-opened more than once.");
                }
            }

            // If child_entry is a duplicate, put it in list of duplicates.
            for db_pathbuf in &new_dbs {
                if child_entry.contains_key(db_pathbuf.0.deref()) {
                    duplicate_dbs.push(PathBuf::from(db_pathbuf.0.deref()));
                }
            }

            // Finally, if child_entry is in list of duplicates and is in new_dbs, remove from new_dbs.
            for db_pathbuf in &duplicate_dbs {
                if new_dbs.contains_key(db_pathbuf) {
                    new_dbs.remove(db_pathbuf);
                }
            }
        }
    }

    Ok(new_dbs)
}

fn get_keys_from_db(db: &Database) -> Vec<SshKey> {
    // For input database, iterates over all entries, finds those that have SSH keys attached
    // and returns them.

    let mut ssh_keys = Vec::<SshKey>::new();
    for node in &db.root {
        match node {
            NodeRef::Group(_g) => {}
            NodeRef::Entry(e) => {
                if e.attachment_refs.contains_key("KeeAgent.settings") {
                    let key: Result<SshKey> = SshKey::from_entry(e, db);
                    if key.is_err() {
                        eprintln!("key couldn't be loaded. {:?}", key);
                        continue;
                    } else {
                        ssh_keys.push(key.unwrap()); // if statement means shouldn't panic.
                    }
                }
            }
        }
    }
    ssh_keys
}

fn get_attachment_content(db: &Database, index: usize) -> &Vec<u8> {
    // When given a database and index to a header attachment, returns the content thereof.
    &db.header_attachments[index].content
}

fn get_encoding(bytes: &Vec<u8>) -> FileEncoding {
    /*
    Tries to detect text encoding of KeeAgent.settings or PEM encoded private key.

    Mainline KeePass offers to convert text attachments into the following formats:
    * Binary (no conversion)
    * Windows-1252                  NOT SUPPORTED
    * ASCII
    * UTF-7                         NOT SUPPORTED
    * UTF-8
    * UTF-16 Little Endian
    * UTF-16 Big Endian
    * UTF-32 Little Endian
    * UTF-32 Big Endian

    Right now, all except Windows-1252 and UTF-7 *should be* detected.

    One of the consequences of mainline keepass doing this is that if a user manually edits and
    re-attaches a file, it might cause errors related to an unexpected text encoding, e.g. If the
    attached file contains XML, this could cause the XML text declaration
    e.g. <?xml version="1.0" encoding="UTF-8"?> to be wrong.
    If the XML text declaration doesn't match the actual encoding of the text, XML parsers
    MUST report a fatal error and MUST NOT continue normal processing.
    (See https://www.w3.org/TR/xml/)

    Consequently, the text encoding of attachments needs to be checked.

    For now this starts with checking BOMs.
    If a BOM isn't found, then we cheat, since this is only meant to parse XML or PEM files,
    and match for either "<?xml" or "----- BEGIN" in the respective encoding.

    Windows-1252 and UTF-7 are ignored, because non ASCII characters appearing in these files
    is incredibly unlikely, since they are machine generated files designed to be compatible,
    and because detecting them is more complication than I want right now.
    TODO Windows-1252 and UTF-7 detection and handling.
    */

    // IMPORTANT GUARD ++++++++++++++++++++
    if bytes.len() < 4 {
        return Binary; // Prevents BOM check from panicking
    }
    // IMPORTANT GUARD ++++++++++++++++++++

    // The above guard should make this unwrap() never panic.
    let first_four = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    match first_four {
        0x2B2F7600..=0x2B2F76FF => return UTF_7,
        0xEFBBFF00..=0xEFBBFFFF => return UTF_8,
        0xFFFE0001..=0xFFFEFFFF => return UTF_16_LE,
        0xFEFF0000..=0xFEFFFFFF => return UTF_16_BE,
        0xFFFE0000 => return UTF_32_LE,
        0x0000FEFF => return UTF_32_BE,
        _ => {}
    }

    // TODO check for UTF-7 without BOM even though no one in their right mind would use it here.

    let patterns: Vec<(FileEncoding, Vec<u8>)> = vec![
        (UTF_8, vec![0x3C, 0x3F, 0x78, 0x6D, 0x6C]),
        (
            UTF_8,
            vec![
                0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x20, 0x42, 0x45, 0x47, 0x49, 0x4E,
            ],
        ),
        (
            UTF_16_LE,
            vec![0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C, 0x00],
        ),
        (
            UTF_16_LE,
            vec![
                0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x20, 0x00, 0x42, 0x00,
                0x45, 0x00, 0x47, 0x00, 0x49, 0x00, 0x4E, 0x00,
            ],
        ),
        (
            UTF_16_BE,
            vec![0x00, 0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C],
        ),
        (
            UTF_16_BE,
            vec![
                0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x20, 0x00, 0x42, 0x00, 0x45,
                0x00, 0x47, 0x00, 0x49, 0x00, 0x4E,
            ],
        ),
        (
            UTF_32_LE,
            vec![
                0x3C, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x6D, 0x00,
                0x00, 0x00, 0x6C, 0x00, 0x00, 0x00,
            ],
        ),
        (
            UTF_32_LE,
            vec![
                0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00,
                0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00,
                0x45, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00, 0x4E, 0x00,
                0x00, 0x00,
            ],
        ),
        (
            UTF_32_BE,
            vec![
                0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00,
                0x00, 0x6D, 0x00, 0x00, 0x00, 0x6C,
            ],
        ),
        (
            UTF_32_BE,
            vec![
                0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00,
                0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x42,
                0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00,
                0x00, 0x4E,
            ],
        ),
    ];
    'pattern: for pattern in patterns {
        if bytes.len() < pattern.1.len() {
            continue 'pattern; // Prevent trying to compare past end of bytes if pattern is longer.
        }
        for i in 0..pattern.1.len() {
            if bytes[i] != pattern.1[i] {
                continue 'pattern;
            }
        }
        return pattern.0;
    }
    Binary
}

fn get_sub_db(child: NodeRef) -> Result<HashMap<PathBuf, DatabaseKey>> {
    match child {
        NodeRef::Group(_) => Err(anyhow!("child is group.")),
        NodeRef::Entry(e) => {
            let pb = PathBuf::from(e.get_url().unwrap()).canonicalize()?;
            let dbk = DatabaseKey::new().with_password(e.get_password().unwrap());

            Ok(HashMap::from([(pb, dbk)]))
        }
    }
}

fn key_check_old_crypto(ssh_key: &SshKey) -> Result<()> {
    // Returns unit if key is using crypto considered acceptable. Otherwise, returns an Error.

    // Checks SSH key for crypto considered deprecated/insecure so user can be warned.
    // This is an Open SSF Best Practice: see https://bestpractices.dev
    let min_rsa_key_length: usize = 2048;
    if ssh_key.public_key.algorithm().is_dsa() {
        return Err(anyhow!(
            "DSA keys are deprecated and considered insecure. Please consider upgrading."
        ));
    }
    if ssh_key.public_key.algorithm().is_rsa() {
        // TODO when ssh_keygen crate goes 0.7.0, do this in less hacky way.
        // Gets Modulus of public key. The length of the modulus is the same as the key itself.
        // This should never panic because the match statement ensures key is RSA.
        let key_mod: &Mpint = &ssh_key.public_key.key_data().rsa().unwrap().n;

        // This shouldn't conceivably fail because TryFrom<Mpint> for BigUint
        // is implemented for ssh_key::Mpint
        let key_mod_len: usize = BigUint::try_from(key_mod)?.bits();
        if key_mod_len < min_rsa_key_length {
            return Err(anyhow!(
                "RSA keys smaller than 2048 bits are deprecated ".to_owned()
                    + "and considered insecure. Please consider upgrading."
            ));
        };
    }
    Ok(())
}

fn open_kpdb(key: DatabaseKey, db_file_location: PathBuf) -> Result<Database> {
    let mut db_file = std::fs::File::open(db_file_location)?;
    let db = Database::open(&mut db_file, key)?;
    Ok(db)
}

fn parse_keeagent_settings(settings_file: &Vec<u8>) -> Result<KeeagentSettings> {
    // Takes a Vec<u8> containing a raw attachment and attempt to parse it as a KeeAgent.settings
    // file, which is a non-compliant XML file, declared as UTF-16 but lacking a BOM.
    // The XML parser in serde_xml_rs won't accept that, so manually add a BOM here.
    //
    // It's possible that KeeAgent.settings can be encoded differently, but I haven't seen it.

    if get_encoding(&settings_file) != UTF_16_LE {
        return Err(anyhow!("Unknown or unsupported encoding"));
    }

    let mut new_settings = settings_file.clone();
    let utf_16le_bom = [0xFF, 0xFE];
    new_settings.splice(0..0, utf_16le_bom);
    let settings: KeeagentSettings = from_reader(&new_settings[..])?;
    Ok(settings)
}

fn main() {
    // Parse CLI arguments.
    let cli = Cli::parse();

    // Load hard-coded default settings and change them if set by user.
    // CLI argument overrides environment variable, which in turn overrides defaults.
    let mut keesh_settings = KeesshSettings::new();
    if cli.no_auto_open == true {
        keesh_settings.auto_open_recursion_enable = false;
    }
    if cli.strict_crypto == true {
        keesh_settings.strict_crypto_enabled = true;
    }
    if cli.suppress_crypto_warnings == true {
        keesh_settings.suppress_crypto_warnings = true;
    }

    let db_path = if cli.vault_path.is_some() {
        cli.vault_path.unwrap()
    } else {
        PathBuf::from(keesh_settings.vault_location_preset.unwrap())
    };
    let db_password =
        rpassword::prompt_password(format!("password for {:?}: ", db_path).as_str()).unwrap();
    let key = DatabaseKey::new().with_password(&db_password);
    let db = open_kpdb(key, db_path).unwrap();
    let ssh_keys = get_keys_from_db(&db);
    let socket = env::var("SSH_AUTH_SOCK").unwrap();
    let mut client = Client::connect(Path::new(socket.as_str())).unwrap();
    for i in ssh_keys {
        let crypto_check = key_check_old_crypto(&i);
        if crypto_check.is_err() {
            println!("{}", crypto_check.unwrap_err());
            if keesh_settings.strict_crypto_enabled {
                println!(
                    "not loading the following key due to strict-crypto being set.\n{}",
                    i.public_key.to_openssh().unwrap()
                );
                continue;
            }
        }
        client
            .add_identity(&i.private_key)
            .expect("TODO: panic message");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::Node;

    fn get_settings_encoding_test_files() -> HashMap<String, Vec<u8>> {
        let key = DatabaseKey::new().with_password("password");
        let path = PathBuf::from("tests/wrong_settings_encoding.kdbx");
        let db = open_kpdb(key, path).unwrap();
        let entry: Entry = match db.root.children.first().unwrap().clone() {
            Node::Group(_) => unimplemented!("Test db, we know its contents and can assume"),
            Node::Entry(e) => e,
        };
        let mut encoding_test_files: HashMap<String, Vec<u8>> = HashMap::new();
        for i in entry.attachment_refs {
            encoding_test_files.insert(
                i.0,
                get_attachment_content(&db, i.1.parse::<usize>().unwrap()).clone(),
            );
        }
        encoding_test_files
    }

    fn get_privkey_encoding_test_files() -> HashMap<String, Vec<u8>> {
        let key = DatabaseKey::new().with_password("password");
        let path = PathBuf::from("tests/wrong_privkey_encoding.kdbx");
        let db = open_kpdb(key, path).unwrap();
        let entry: Entry = match db.root.children.first().unwrap().clone() {
            Node::Group(_) => unimplemented!("Test db, we know its contents and can assume"),
            Node::Entry(e) => e,
        };
        let mut privkey_test_files: HashMap<String, Vec<u8>> = HashMap::new();
        for i in entry.attachment_refs {
            privkey_test_files.insert(
                i.0,
                get_attachment_content(&db, i.1.parse::<usize>().unwrap()).clone(),
            );
        }
        privkey_test_files
    }

    #[test]
    fn open_blank_kdbx() {
        let key = DatabaseKey::new().with_password("password");
        let path = PathBuf::from("tests/test0.kdbx");
        open_kpdb(key, path).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incorrect key")]
    fn open_kdbx_wrong_password() {
        let key = DatabaseKey::new().with_password("WRONG");
        let path = PathBuf::from("tests/test0.kdbx");
        open_kpdb(key, path).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid KDBX identifier")]
    fn open_kdbx_not_a_kdbx() {
        let key = DatabaseKey::new().with_password("password");
        let path = PathBuf::from("README.md");
        open_kpdb(key, path).unwrap();
    }

    #[test]
    fn get_encoding_test() {
        let files = get_settings_encoding_test_files();
        // files should contain: // TODO FIX THESE FILES TO BE CONSISTENTLY NAMED
        // TODO ADD FILES IN OTHER ENCODINGS
        // KeeAgent.settings (UTF-16 LE NO BOM)
        // * iso-8859-1.settings NOT TESTED
        // * utf-16.settings
        // * utf16-be-bom.settings
        // * utf16-le-bom.settings
        // * utf-32.settings
        // * utf-32-be-bom.settings
        // * utf-32-le-bom.settings
        // * utf8.settings
        // * windows-1252.settings NOT TESTED

        // Short file
        assert_eq!(get_encoding(&vec![0x2D, 0x2D, 0x2D]), Binary);

        // Normal settings files in weird encodings.
        assert_eq!(get_encoding(&files["utf-16.settings"]), UTF_16_LE);
        assert_eq!(get_encoding(&files["utf16-be-bom.settings"]), UTF_16_BE);
        assert_eq!(get_encoding(&files["utf16-le-bom.settings"]), UTF_16_LE);
        assert_eq!(get_encoding(&files["utf-32.settings"]), UTF_32_LE);
        assert_eq!(get_encoding(&files["utf-32-be.settings"]), UTF_32_BE);
        assert_eq!(get_encoding(&files["utf-32-le.settings"]), UTF_32_LE);
        assert_eq!(get_encoding(&files["utf8.settings"]), UTF_8);

        assert_eq!(get_encoding(&vec![0x4a; 20]), Binary);
    }

    #[test]
    fn parse_keeagent_settings_test() {
        let files = get_settings_encoding_test_files();
        assert_eq!(
                parse_keeagent_settings(&files["KeeAgent.settings"]).unwrap(),
                KeeagentSettings {
                    AllowUseOfSshKey: false,
                    AddAtDatabaseOpen: false,
                    RemoveAtDatabaseClose: false,
                    UseConfirmConstraintWhenAdding: false,
                    UseLifetimeConstraintWhenAdding: false,
                    LifetimeConstraintDuration: 0,
                    UseDestinationConstraintWhenAdding: None,
                    DestinationConstraints: None,
                    Location: KASetLocation {
                        SelectedType: "attachment".parse().unwrap(),
                        AttachmentName: "".parse().unwrap(),
                        SaveAttachmentToTempFile: false,
                        FileName: "".parse().unwrap()
                    }
                }
            );
    }

    #[test]
    #[should_panic(expected = "Unknown or unsupported encoding")]
    fn parse_settings_wrong_encoding2() {
        let files = get_settings_encoding_test_files();
        parse_keeagent_settings(&files["utf-32.settings"]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DSA keys are deprecated and considered insecure. Please consider upgrading.")]
    fn test_crypto_check_dsa()  {
        let key_str = std::fs::read_to_string("tests/test_dsa").unwrap();

        let private_key = PrivateKey::from_openssh(key_str).unwrap();
        let public_key = private_key.public_key().clone();

        let settings = KeeagentSettings {
            AllowUseOfSshKey: false,
            AddAtDatabaseOpen: false,
            RemoveAtDatabaseClose: false,
            UseConfirmConstraintWhenAdding: false,
            UseLifetimeConstraintWhenAdding: false,
            LifetimeConstraintDuration: 0,
            UseDestinationConstraintWhenAdding: None,
            DestinationConstraints: None,
            Location: KASetLocation {
                SelectedType: "attachment".parse().unwrap(),
                AttachmentName: "".parse().unwrap(),
                SaveAttachmentToTempFile: false,
                FileName: "".parse().unwrap(),
            }
        };

        let key_struct = SshKey {
            private_key,
            public_key,
            settings,
        };

        key_check_old_crypto(&key_struct).unwrap();
    }

    #[test]
    #[should_panic(expected = "RSA keys smaller than 2048 bits are deprecated and considered insecure. Please consider upgrading.")]
    fn test_crypto_check_rsa_2047() {
        let key_str = std::fs::read_to_string("tests/test_2047_rsa").unwrap();

        let private_key = PrivateKey::from_openssh(key_str).unwrap();
        let public_key = private_key.public_key().clone();

        let settings = KeeagentSettings {
            AllowUseOfSshKey: false,
            AddAtDatabaseOpen: false,
            RemoveAtDatabaseClose: false,
            UseConfirmConstraintWhenAdding: false,
            UseLifetimeConstraintWhenAdding: false,
            LifetimeConstraintDuration: 0,
            UseDestinationConstraintWhenAdding: None,
            DestinationConstraints: None,
            Location: KASetLocation {
                SelectedType: "attachment".parse().unwrap(),
                AttachmentName: "".parse().unwrap(),
                SaveAttachmentToTempFile: false,
                FileName: "".parse().unwrap(),
            }
        };

        let key_struct = SshKey {
            private_key,
            public_key,
            settings,
        };

        key_check_old_crypto(&key_struct).unwrap();
    }

    #[test]
    fn test_crypto_check_rsa_2048() {
        let key_str = std::fs::read_to_string("tests/test_2048_rsa").unwrap();

        let private_key = PrivateKey::from_openssh(key_str).unwrap();
        let public_key = private_key.public_key().clone();

        let settings = KeeagentSettings {
            AllowUseOfSshKey: false,
            AddAtDatabaseOpen: false,
            RemoveAtDatabaseClose: false,
            UseConfirmConstraintWhenAdding: false,
            UseLifetimeConstraintWhenAdding: false,
            LifetimeConstraintDuration: 0,
            UseDestinationConstraintWhenAdding: None,
            DestinationConstraints: None,
            Location: KASetLocation {
                SelectedType: "attachment".parse().unwrap(),
                AttachmentName: "".parse().unwrap(),
                SaveAttachmentToTempFile: false,
                FileName: "".parse().unwrap(),
            }
        };

        let key_struct = SshKey {
            private_key,
            public_key,
            settings,
        };

        key_check_old_crypto(&key_struct).unwrap();
    }

    #[test]
    fn test_crypto_check_rsa_2049() {
        let key_str = std::fs::read_to_string("tests/test_2049_rsa").unwrap();

        let private_key = PrivateKey::from_openssh(key_str).unwrap();
        let public_key = private_key.public_key().clone();

        let settings = KeeagentSettings {
            AllowUseOfSshKey: false,
            AddAtDatabaseOpen: false,
            RemoveAtDatabaseClose: false,
            UseConfirmConstraintWhenAdding: false,
            UseLifetimeConstraintWhenAdding: false,
            LifetimeConstraintDuration: 0,
            UseDestinationConstraintWhenAdding: None,
            DestinationConstraints: None,
            Location: KASetLocation {
                SelectedType: "attachment".parse().unwrap(),
                AttachmentName: "".parse().unwrap(),
                SaveAttachmentToTempFile: false,
                FileName: "".parse().unwrap(),
            }
        };

        let key_struct = SshKey {
            private_key,
            public_key,
            settings,
        };

        key_check_old_crypto(&key_struct).unwrap();
    }
}
