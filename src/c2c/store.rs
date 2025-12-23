//src/c2c/store.rs

use std::{fs, path::PathBuf};

use crate::c2c::types::C2CEvent;
use crate::error::{AppError, AppResult};

fn events_dir() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".tidbit");
    dir.push("c2c_events");
    dir
}

fn event_path(id: &str) -> PathBuf {
    let mut p = events_dir();
    p.push(format!("{id}.json"));
    p
}

pub fn store_local_event(ev: &C2CEvent) -> AppResult<()> {
    let dir = events_dir();
    fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(ev)?;
    fs::write(event_path(&ev.id), json)?;
    Ok(())
}

pub fn load_all_events() -> AppResult<Vec<C2CEvent>> {
    let dir = events_dir();
    let mut out = Vec::new();

    if !dir.exists() {
        return Ok(out);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let data = fs::read_to_string(&path)?;
        if let Ok(ev) = serde_json::from_str::<C2CEvent>(&data) {
            out.push(ev);
        }
    }

    // Most recent first
    out.sort_by_key(|e| e.timestamp);
    out.reverse();

    Ok(out)
}

pub fn load_event_by_id(id: &str) -> AppResult<Option<C2CEvent>> {
    let path = event_path(id);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    let ev = serde_json::from_str(&data)?;
    Ok(Some(ev))
}
