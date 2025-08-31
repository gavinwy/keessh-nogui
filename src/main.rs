// Copyright 2025 Gavin Weifert-Yeh
// License TBD, for now all rights reserved.

use anyhow::{anyhow, Context, Result};
use num_traits::cast::FromPrimitive;
use keepass::{
    db::NodeRef,
    Database,
    DatabaseKey,
    error::DatabaseOpenError
};
use ssh_key::{PrivateKey, PublicKey};
use ssh_agent_client_rs::Client;
use serde_derive::Deserialize;
use serde_xml_rs::from_reader;
use keepass::db::Entry;
use crate::FileEncoding::{Binary, ASCII, UTF_7, UTF_8, UTF_16_BE, UTF_16_LE, UTF_32_BE, UTF_32_LE};
use std::env;
use std::path::Path;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
enum FileEncoding {
    Binary,
    ASCII,
    UTF_7,
    UTF_8,
    UTF_16_LE,
    UTF_16_BE,
    UTF_32_LE,
    UTF_32_BE,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct KASetLocation {
    SelectedType: String,
    AttachmentName: String,
    SaveAttachmentToTempFile: bool,
    FileName: String
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct KeeagentSettings {
    AllowUseOfSshKey: bool,
    AddAtDatabaseOpen: bool,
    RemoveAtDatabaseClose: bool,
    UseConfirmConstraintWhenAdding: bool,
    UseLifetimeConstraintWhenAdding: bool,
    LifetimeConstraintDuration: i64,
    UseDestinationConstraintWhenAdding: Option<bool>,  // Optional or missing on KXC
    DestinationConstraints: Option<String>,           // Optional or missing on KXC
    Location: KASetLocation
}

#[derive(Debug)]
struct SshKey {
    private_key: PrivateKey,
    public_key: PublicKey,
    settings: KeeagentSettings,
}

impl SshKey {
    fn from_entry(e: &Entry, db: &Database) -> Result<Self> {
        let settings_location = & e.attachment_refs["KeeAgent.settings"];
        let attachment = get_attachment_content(db, usize::from_u8((*settings_location).parse().unwrap()).unwrap()); // TODO Has to be a better way to do this
        let settings: KeeagentSettings = parse_settings(attachment).context("failed to parse KeeAgent settings")?;

        let private_key_location = &e.attachment_refs[&settings.Location.AttachmentName];
        let private_key_file = get_attachment_content(db, usize::from_u8((*private_key_location).parse().unwrap()).unwrap());
        let private_key = PrivateKey::from_openssh(&private_key_file).context("failed to load private key from attachment.")?;
        let public_key = private_key.public_key();

        Ok(
            Self {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            settings,
        })
    }
}

fn open_kpdb(key: DatabaseKey, db_file_location: String) -> Result<Database> {
    let mut db_file = std::fs::File::open(db_file_location)?;
    let db =Database::open(&mut db_file, key)?;
    Ok(db)
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
    if bytes.len() < 4 { return Binary } // Prevents BOM check from panicking
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
        (UTF_8, vec![0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x20, 0x42, 0x45, 0x47, 0x49, 0x4E]),
        (UTF_16_LE, vec![0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C, 0x00]),
        (UTF_16_LE, vec![
            0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00,
            0x20, 0x00, 0x42, 0x00, 0x45, 0x00, 0x47, 0x00, 0x49, 0x00,
            0x4E, 0x00,
        ]),
        (UTF_16_BE, vec![0x00, 0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C]),
        (UTF_16_BE, vec![
            0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00,
            0x20, 0x00, 0x42, 0x00, 0x45, 0x00, 0x47, 0x00, 0x49, 0x00,
            0x4E,
        ]),
        (UTF_32_LE, vec![
            0x3C, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00,
            0x78, 0x00, 0x00, 0x00, 0x6D, 0x00, 0x00, 0x00,
            0x6C, 0x00, 0x00, 0x00,
        ]),
        (UTF_32_LE, vec![
            0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00,
            0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00,
            0x2D, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00,
            0x47, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
            0x4E, 0x00, 0x00, 0x00,
        ]),
        (UTF_32_BE, vec![
            0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x3F,
            0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x6D,
            0x00, 0x00, 0x00, 0x6C,
        ]),
        (UTF_32_BE, vec![
            0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D,
            0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x2D,
            0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x20,
            0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x45,
            0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x49,
            0x00, 0x00, 0x00, 0x4E,
        ]),
    ];
    'pattern: for pattern in patterns {
        if bytes.len() < pattern.1.len() {
            continue 'pattern;  // Prevent trying to compare past the end of bytes if the pattern is longer.
        }
        for i in 0..pattern.1.len() {
            if bytes[i] != pattern.1[i] {continue 'pattern;}
        }
        return pattern.0;
    }
    Binary
}

fn parse_settings(settings_file: &Vec<u8>) -> Result<KeeagentSettings> {
    // Takes a Vec<u8> containing a raw attachment and attempt to parse it as a KeeAgent.settings
    // file, which is a non-compliant XML file, declared as UTF-16 but lacking a BOM.
    // The XML parser in serde_xml_rs won't accept that, so manually add a BOM here.
    //
    // It's possible that KeeAgent.settings can be encoded differently, but I haven't seen it.

    if get_encoding(&settings_file) != UTF_16_LE {
        return Err(anyhow!("unknown or unsupported encoding."));
    }

    let mut new_settings = settings_file.clone();
    let utf_16le_bom = [0xFF, 0xFE];
    new_settings.splice(0..0, utf_16le_bom);
    let settings: KeeagentSettings = from_reader(&new_settings[..])?;
    Ok(settings)
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
                        continue
                    }
                    else {
                        ssh_keys.push(key.unwrap());  // if key was Err, we never get here, because conditional.
                    }
                }
            }
        }
    }
    ssh_keys
}

fn main() {
    let cli_args: Vec<String> = env::args().collect();
    let db_path = &cli_args[1];
    let db_password = rpassword::prompt_password(format!("password for {}: ",db_path).as_str()).unwrap();
    let key = DatabaseKey::new().with_password(&*db_password);
    let db = open_kpdb(key,String::from(db_path)).unwrap();
    let ssh_keys = get_keys_from_db(&db);
    let socket = env::var("SSH_AUTH_SOCK").unwrap();
    let mut client = Client::connect(Path::new(socket.as_str())).unwrap();
    for i in ssh_keys {
        client.add_identity(&i.private_key).expect("TODO: panic message");
    }

}
