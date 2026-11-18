//! Restores the window when the app is reactivated on macOS.

pub fn install() -> bool {
    imp::install()
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::rc::Retained;
    use objc2::runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject};
    use objc2::{define_class, msg_send, MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{NSApplication, NSApplicationDelegate, NSWindow};

    define_class!(
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "HakimiAppDelegate"]
        struct AppDelegate;

        unsafe impl NSObjectProtocol for AppDelegate {}

        unsafe impl NSApplicationDelegate for AppDelegate {
            #[unsafe(method(applicationShouldHandleReopen:hasVisibleWindows:))]
            fn application_should_handle_reopen(
                &self,
                _application: &NSApplication,
                _has_visible_windows: bool,
            ) -> Bool {
                // A minimized window counts as "visible" here, so this flag
                // cannot guard restoration — always try to reveal one.
                show_hidden_window();
                Bool::YES
            }
        }
    );

    fn show_hidden_window() {
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        let app = NSApplication::sharedApplication(mtm);

        let mut hidden: Option<Retained<NSWindow>> = None;
        for window in app.windows().iter() {
            // A miniaturized window is the one the user minimized, so restore it
            // before any merely-hidden helper — otherwise a Dock click reveals
            // the helper and needs a second click to reach the main window.
            if window.isMiniaturized() {
                window.deminiaturize(None);
                window.makeKeyAndOrderFront(None);
                crate::activate_app();
                return;
            }
            if !window.isVisible() {
                hidden.get_or_insert(window);
            }
        }
        if let Some(window) = hidden {
            window.makeKeyAndOrderFront(None);
            crate::activate_app();
        }
    }

    pub(super) fn install() -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        let app = NSApplication::sharedApplication(mtm);
        let delegate: Retained<AppDelegate> = unsafe { msg_send![AppDelegate::alloc(mtm), init] };
        app.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        std::mem::forget(delegate);
        true
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub(super) fn install() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn install_is_a_no_op_off_macos() {
        assert!(!super::install());
    }
}
