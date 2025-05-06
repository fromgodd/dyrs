use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::error::Error;

use reqwest;

const IP_FILE: &str = "last_ip.txt";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let current_ip = fetch_public_ip().await?;

    println!("Current IP: {}", current_ip);

    // Check last saved IP
    if let Some(last_ip) = read_last_ip()? {
        if last_ip == current_ip {
            println!("IP hasn't changed.");
            return Ok(());
        } else {
            println!("IP changed: {} -> {}", last_ip, current_ip);
        }
    } else {
        println!("No previous IP found.");
    }


    save_ip(&current_ip)?;
    println!("Saved new IP.");


    Ok(())
}


async fn fetch_public_ip() -> Result<String, Box<dyn Error>> {
    let ip = reqwest::get("https://api.ipify.org")
        .await?
        .text()
        .await?;
    Ok(ip)
}


fn read_last_ip() -> Result<Option<String>, io::Error> {
    if !Path::new(IP_FILE).exists() {
        return Ok(None); // File not there yet
    }

    let contents = fs::read_to_string(IP_FILE)?;
    Ok(Some(contents.trim().to_string()))
}


fn save_ip(ip: &str) -> Result<(), io::Error> {
    let mut file = fs::File::create(IP_FILE)?;
    file.write_all(ip.as_bytes())?;
    Ok(())
}
