//! Embedded image assets. PNGs are baked into the executable so no asset
//! directory is needed next to the binary. windui decodes PNG through tiny-skia
//! (`ImageContent::from_bytes`), so the old `image` crate dependency is gone.

use std::cell::RefCell;
use std::collections::HashMap;

use windui::prelude::*;

// Decoded images are Rc-shared and cheap to clone. Cache them by key so a
// refresh tick that rebuilds a site row never re-decodes a PNG.
thread_local! {
    static LOGO_CACHE: RefCell<HashMap<&'static str, Option<Image>>> =
        RefCell::new(HashMap::new());
}

const APP_ICON: &[u8] = include_bytes!("../assets/app-icon.png");
const TRAY_ICON: &[u8] = include_bytes!("../assets/tray.png");
const HF_LOGO: &[u8] = include_bytes!("../assets/hf.png");

/// The site logos, keyed by the `icon_key` derived in `model.rs`.
const SITE_LOGOS: &[(&str, &[u8])] = &[
    ("google", include_bytes!("../assets/google.png")),
    ("pixiv", include_bytes!("../assets/pixiv.png")),
    ("hitomi", include_bytes!("../assets/hitomi.png")),
    ("poipiku", include_bytes!("../assets/poipiku.png")),
    ("booth", include_bytes!("../assets/booth.png")),
    ("steam", include_bytes!("../assets/steam.png")),
    ("github", include_bytes!("../assets/github.png")),
    ("ao3", include_bytes!("../assets/ao3.png")),
    ("eh", include_bytes!("../assets/eh.png")),
    ("hanime", include_bytes!("../assets/hanime.png")),
    ("nhentai", include_bytes!("../assets/nhentai.png")),
    ("hf", HF_LOGO),
    ("huggingface", HF_LOGO),
    ("x", include_bytes!("../assets/x.png")),
];

/// Look up a bundled logo by its key. Returns `None` for unknown sites, which
/// makes the view fall back to the initial-on-tinted-tile badge. The decoded
/// image is cached, so repeated calls (each refresh tick) never re-decode.
pub fn site_logo(key: &str) -> Option<ImageContent> {
    let entry = SITE_LOGOS.iter().find(|(name, _)| *name == key)?;
    let name = entry.0;
    LOGO_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let image = cache
            .entry(name)
            .or_insert_with(|| Image::from_png_bytes(entry.1).ok())
            .clone();
        image.map(|img| ImageContent::new(Some(img)))
    })
}

/// Drop every decoded logo. Called when the window closes so the decoded
/// pixmaps do not outlive the UI that showed them; the next window re-decodes
/// on demand (the PNGs stay embedded in the binary).
pub fn clear_logo_cache() {
    LOGO_CACHE.with(|cache| cache.borrow_mut().clear());
}

/// Every embedded logo key. Used by tests to keep the decode table and the
/// id-matching table in sync.
#[cfg(test)]
pub fn logo_keys() -> Vec<&'static str> {
    SITE_LOGOS.iter().map(|(key, _)| *key).collect()
}

/// Verify every bundled logo decodes to a non-empty image.
#[cfg(test)]
pub fn every_logo_decodes() -> bool {
    SITE_LOGOS.iter().all(|(key, bytes)| {
        Image::from_png_bytes(bytes)
            .map(|image| image.width() > 0 && image.height() > 0)
            .unwrap_or(false) && {
            let _ = key;
            true
        }
    })
}

/// Non-premultiplied RGBA bytes for the tray icon, decoded from the bundled PNG.
pub fn tray_icon_rgba() -> (u32, u32, Vec<u8>) {
    let image = Image::from_png_bytes(TRAY_ICON).expect("tray.png must decode");
    (image.width(), image.height(), image.to_rgba())
}

/// The window/application icon, decoded from the bundled PNG.
pub fn window_icon() -> WindowIcon {
    let image = Image::from_png_bytes(APP_ICON).expect("app-icon.png must decode");
    WindowIcon::from_image(&image).expect("app-icon.png must yield a window icon")
}
