mod server;
mod client;

use inquire::{Text, Select};
use anyhow::Result;
struct Database;

fn register(db: &mut Database) -> Result<()> {

    Ok(())

}
fn authenticate(db: &mut Database) -> Result<()> {
    Ok(())

}

fn main() -> Result<()>{
    let mut db: Database = Database;

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["register", "authenticate", "exit"])
            .prompt()?;

        let result = match select {
            "register" => register(&mut db),
            "authenticate" => authenticate(&mut db),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        if let Err(e) = result {
            eprintln!("{e}");
        }

    }
}
