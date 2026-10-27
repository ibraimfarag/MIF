//! Noise learner: repeated dismissal of one event category earns an offer to
//! mute it (5 dismissals, per section 7.4 of the brief).

use anyhow::Result;
use serde::Serialize;

use crate::storage::sqlite::Storage;

const MUTE_THRESHOLD: i64 = 5;

#[derive(Debug, Serialize)]
pub struct NoiseStat {
    pub category: String,
    pub dismissals: i64,
    pub mute_suggested: bool,
    pub muted: bool,
}

pub fn record_dismissal(category: &str) -> Result<NoiseStat> {
    let storage = Storage::open()?;
    storage.bump_dismissal(category)?;
    let dismissals = storage.get_dismissal(category)?;
    let muted = storage.is_muted(category)?;
    Ok(NoiseStat {
        category: category.to_string(),
        dismissals,
        mute_suggested: !muted && dismissals >= MUTE_THRESHOLD,
        muted,
    })
}

pub fn mute_category(category: &str) -> Result<()> {
    Storage::open()?.set_muted(category, true)
}

pub fn unmute_category(category: &str) -> Result<()> {
    Storage::open()?.set_muted(category, false)
}

/// True when the UI should suppress a toast for this category.
#[allow(dead_code)]
pub fn is_muted(category: &str) -> Result<bool> {
    Storage::open()?.is_muted(category)
}

pub fn stats() -> Result<Vec<NoiseStat>> {
    let storage = Storage::open()?;
    let mut out = Vec::new();
    for (category, dismissals) in storage.all_dismissals()? {
        let muted = storage.is_muted(&category)?;
        out.push(NoiseStat {
            category,
            dismissals,
            mute_suggested: !muted && dismissals >= MUTE_THRESHOLD,
            muted,
        });
    }
    Ok(out)
}
