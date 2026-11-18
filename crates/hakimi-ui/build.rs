fn main() {
    // Explorer, shortcuts and the taskbar fall back to the executable's
    // resource icon before the window exists. windui needs no build-time code
    // generation; its UI is plain Rust compiled by cargo.
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/app-icon.ico");
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/app-icon.ico");
        resource
            .compile()
            .expect("embedding the Windows application icon");
    }
}
