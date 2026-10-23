fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).unwrap();

    // Explorer, shortcuts and the taskbar fall back to the executable's
    // resource icon before the window exists.
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
