//! Engine-side alert cue.
//!
//! The service engine runs with the UI closed, so a critical event must still
//! be audible. Windows' `PlaySound` can play straight from memory, so the WAV
//! bytes are embedded in the binary — no asset path to resolve, nothing to
//! install, and the sound survives a moved/renamed installation.
//!
//! Volume note: `PlaySound` has no per-application volume; the engine cue uses
//! the system volume. The UI (when it is open) plays the same pack through the
//! audio plugin, where the Settings volume slider applies.

use windows::core::PCWSTR;
use windows::Win32::Media::Audio::{PlaySoundW, SND_ASYNC, SND_MEMORY, SND_NODEFAULT};

static CRITICAL: &[u8] = include_bytes!("../../../assets/sounds/critical.wav");
static WARNING: &[u8] = include_bytes!("../../../assets/sounds/warning.wav");

/// The cue for a severity, or `None` when the engine should stay silent
/// (unknown severity, sounds off, or do-not-disturb).
pub fn cue(severity: &str) -> Option<&'static [u8]> {
    let settings = crate::settings::current();
    if !settings.sound_enabled || settings.quiet() {
        return None;
    }
    match severity {
        "critical" => Some(CRITICAL),
        "high" => Some(WARNING),
        _ => None,
    }
}

/// Plays the cue for a severity, if one applies. Never fails loudly: a machine
/// with no audio device must not log an error on every event.
pub fn play_for_severity(severity: &str) {
    let Some(wav) = cue(severity) else { return };
    unsafe {
        let _ = PlaySoundW(
            PCWSTR(wav.as_ptr() as *const u16),
            None,
            SND_MEMORY | SND_ASYNC | SND_NODEFAULT,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cues_exist_for_high_severities_only() {
        // Settings default to sounds on and DND off, so these resolve.
        assert!(cue("critical").is_some());
        assert!(cue("high").is_some());
        assert!(cue("medium").is_none());
        assert!(cue("low").is_none());
        assert!(cue("").is_none());
    }

    #[test]
    fn embedded_wavs_are_valid_riff() {
        for wav in [CRITICAL, WARNING] {
            assert!(wav.len() > 44, "wav too small");
            assert_eq!(&wav[0..4], b"RIFF");
            assert_eq!(&wav[8..12], b"WAVE");
        }
    }
}
