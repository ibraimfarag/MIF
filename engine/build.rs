//! Embeds the Windows version resource and the application icon for
//! `mics-engine.exe`.
//!
//! Task Manager's Processes tab does not show a file name: it shows the
//! `FileDescription` string from the executable's version resource, then falls
//! back to the file name when there is none. The engine had no resource at all,
//! so it appeared as `mics-engine.exe` next to the app.
//!
//! The icon is the *same file* the Flutter runner embeds in `mics_app.exe`, so the
//! engine wears the application's icon in Task Manager, in the shortcut and in
//! Explorer instead of the generic one Windows substitutes for an icon-less exe.
//!
//! The file name stays `mics-engine.exe` on purpose: the app's lookup, the helper
//! service registration, the probes and `MICS_ENGINE_PATH` all depend on it, and a
//! path with a space would leak into every one of them. Only the name a person
//! reads changes.
//!
//! `MICS_REQUIRE_VERSION_RESOURCE=1` turns a toolchain without `rc.exe` into a
//! build error instead of a warning — release packaging sets it, so a package can
//! never ship an engine that shows up under the wrong name or with the wrong icon.

/// The icon the Flutter runner embeds in `mics_app.exe`; the engine reuses it so
/// both halves of the product are one icon to the user.
#[cfg(windows)]
const APP_ICON: &str = "../windows/runner/resources/app_icon.ico";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MICS_REQUIRE_VERSION_RESOURCE");
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed={APP_ICON}");
        embed_windows_version_resource();
    }
}

#[cfg(windows)]
fn embed_windows_version_resource() {
    let require = std::env::var("MICS_REQUIRE_VERSION_RESOURCE").as_deref() == Ok("1");
    let mut resource = winresource::WindowsResource::new();
    // What Task Manager, the Services console and the file's Properties dialog show.
    resource.set("FileDescription", "MiShild Background");
    resource.set("ProductName", "MI CS");
    resource.set("CompanyName", "Mourad Ibrahim Cyber Security");
    resource.set("LegalCopyright", "GPL-3.0-or-later");
    resource.set("InternalName", "mics-engine");
    resource.set("OriginalFilename", "mics-engine.exe");
    // From the crate, so the resource cannot drift from what `status` reports.
    let version = env!("CARGO_PKG_VERSION");
    resource.set("FileVersion", version);
    resource.set("ProductVersion", version);

    let icon = std::path::Path::new(APP_ICON);
    if icon.is_file() {
        resource.set_icon(APP_ICON);
    } else if require {
        panic!("application icon not found at {APP_ICON}; the engine would wear the generic one");
    } else {
        println!(
            "cargo:warning=application icon not found at {APP_ICON}; \
             Task Manager will show the generic icon for mics-engine.exe"
        );
    }

    if let Err(error) = resource.compile() {
        if require {
            panic!("failed to embed the Windows version resource: {error}");
        }
        println!(
            "cargo:warning=no Windows version resource ({error}); Task Manager will \
             show mics-engine.exe instead of \"MiShild Background\""
        );
    }
}