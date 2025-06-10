use ssh_agent_lib::client::connect;
use keepass::{
    db::NodeRef,
    Database,
    DatabaseKey,
    error::DatabaseOpenError
};

fn open_kpdb(key: DatabaseKey, db_file_location: String) -> Database {
    let mut db_file = std::fs::File::open(db_file_location).unwrap();
    Database::open(&mut db_file, key).unwrap()
}


fn main() {
    let key = DatabaseKey::new().with_password("password");
    let db = open_kpdb(key,String::from("tests/test_agent.kdbx"));

    for node in &db.root {
        match node {
            NodeRef::Group(g) => {
                //println!("Saw group '{0}'", g.name);
            },
            NodeRef::Entry(e) => {
                println!("{:?}",e);
                let title = e.get_title().unwrap_or("(no title)");
                println!("Entry Title: '{0}'", title);
            //     for field in &e.fields {
            //         let val = e.get(field.0).unwrap();
            //         println!("Field String: '{0}'\nField Value: '{1}'", field.0, val)
            //     }
            }
        }
    }

    let attachments = db.header_attachments;
    let mut attachment_count = -1;
    // for i in attachments {
    //     let content = i.content;
    //     attachment_count += 1;
    //     println!("attachment number '{}'", attachment_count);
    //     println!("Content:\n'{}'", String::from_utf8(content).unwrap());
    // }
}
