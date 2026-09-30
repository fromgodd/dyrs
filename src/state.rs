//! Remembering the last address between runs.
//!
//! Two lines of text. The file is written to a temporary name and renamed so
//! that a machine losing power mid-write cannot leave a half-file that makes
//! the next run think the address changed.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct State {
    pub v4: Option<IpAddr>,
    pub v6: Option<IpAddr>,
}

impl State {
    pub fn load(path: &Path) -> State {
        let mut state = State::default();
        let Ok(text) = std::fs::read_to_string(path) else {
            return state; // no file yet: first run
        };
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let Ok(ip) = value.trim().parse::<IpAddr>() else {
                continue;
            };
            match key.trim() {
                "v4" => state.v4 = Some(ip),
                "v6" => state.v6 = Some(ip),
                _ => {}
            }
        }
        state
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut body = String::new();
        if let Some(ip) = self.v4 {
            body.push_str(&format!("v4={ip}\n"));
        }
        if let Some(ip) = self.v6 {
            body.push_str(&format!("v6={ip}\n"));
        }
        let tmp: PathBuf = path.with_extension("tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)
    }
}
