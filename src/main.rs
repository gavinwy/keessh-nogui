use service_binding::Binding;
use ssh_agent_lib::client::connect;
use keepass::{
    db::NodeRef,
    Database,
    DatabaseKey,
    error::DatabaseOpenError
};
use std::fs::File;

let mut file = File::open("tests/test0.kdbx")?;
let key = DatabaseKey::new().with_password("password");
fn open_kpdb(key: DatabaseKey, db_file: File) {
    let db = Database::open(&mut file, key)?;

}


fn main() {

}
