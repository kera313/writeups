extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let shell_cmd = Command::new("/tmp/xa/atlas_rshell.sh")
    .output()
    .expect("Failed to run command.");
    let shell_cmd_output = String::from_utf8(shell_cmd.stdout).unwrap();

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}, Cmd Output for scriptX {}\n", timestamp, user, query, justification, shell_cmd_output);

    let mut file = match OpenOptions::new().append(true).create(true).open("/tmp/xa/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
