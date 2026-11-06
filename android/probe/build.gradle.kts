plugins {
    id("com.android.application") version "9.3.0"
}

val repoRoot = rootProject.projectDir.parentFile.parentFile

/** Keep IDE builds in step with build.sh and the client workspace version. */
fun workspaceVersion(): String {
    val manifest = File(repoRoot, "Cargo.toml")
    var inPackage = false
    for (line in manifest.readLines()) {
        val trimmed = line.trim()
        if (trimmed.startsWith("[")) {
            inPackage = trimmed == "[workspace.package]"
            continue
        }
        if (inPackage) {
            val value = Regex("""^version\s*=\s*"([^"]+)"""")
                .find(trimmed)
                ?.groupValues
                ?.get(1)
            if (value != null) return value
        }
    }
    error("could not read [workspace.package] version from ${manifest.path}")
}

fun versionCodeFor(version: String): Int {
    val parts = version.substringBefore('-').substringBefore('+').split('.')
    val major = parts.getOrNull(0)?.toIntOrNull() ?: 0
    val minor = parts.getOrNull(1)?.toIntOrNull() ?: 0
    val patch = parts.getOrNull(2)?.toIntOrNull() ?: 0
    return major * 1_000_000 + minor * 1_000 + patch
}

val appVersion = workspaceVersion()

android {
    namespace = "com.hakimi.probe"
    compileSdk = 37
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "com.hakimi.probe"
        minSdk = 24
        targetSdk = 35
        versionCode = versionCodeFor(appVersion)
        versionName = appVersion
    }

    sourceSets {
        getByName("main") {
            // The probe keeps the custom build.sh layout instead of src/main/.
            manifest.srcFile("gradle/AndroidManifest.xml")
            java.srcDirs("src")
            kotlin.srcDirs("src")
            res.srcDirs("res")
            assets.srcDirs("assets")
            jniLibs.srcDirs("jniLibs")
        }
    }

    signingConfigs {
        getByName("debug") {
            // build.sh generates this keystore; reuse it so an IDE build can
            // replace an APK that was installed from the script.
            val store = file("debug.keystore")
            if (store.exists()) {
                storeFile = store
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isDebuggable = true
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Android Studio's Gradle build does not compile Rust on its own. Without
// this, jniLibs/ keeps whatever `build.sh` copied last and debug APKs ship a
// stale native core. Build it here and copy the result before packaging.
val cargoHome = System.getenv("CARGO_HOME")
    ?: File(System.getProperty("user.home"), ".cargo").absolutePath
val cargoBin = File(cargoHome, "bin")
val cargoName = if (System.getProperty("os.name").lowercase().contains("win")) {
    "cargo.exe"
} else {
    "cargo"
}
val cargo = File(cargoBin, cargoName).let {
    if (it.exists()) it.absolutePath else cargoName
}
fun sdkDirFromProperties(): String? {
    val properties = File(rootProject.projectDir, "local.properties")
    if (!properties.exists()) return null
    return properties.readLines()
        .firstOrNull { it.startsWith("sdk.dir=") }
        ?.substringAfter('=')
        ?.trim()
        ?.takeIf { it.isNotEmpty() }
}
val sdkDir = System.getenv("ANDROID_HOME")
    ?: System.getenv("ANDROID_SDK_ROOT")
    ?: sdkDirFromProperties()
    ?: File(System.getProperty("user.home"), "AppData/Local/Android/Sdk").absolutePath
/** Newest NDK revision installed under $SDK/ndk, or null when there is none. */
fun newestInstalledNdk(): String? {
    return File(sdkDir, "ndk")
        .listFiles()
        ?.filter { it.isDirectory && File(it, "source.properties").exists() }
        ?.maxWithOrNull(Comparator { a, b ->
            // Revisions look like 27.3.13750724; compare the numeric parts so
            // 27.10 sorts after 27.3 instead of before it as a string would.
            val left = a.name.split('.').mapNotNull { it.toIntOrNull() }
            val right = b.name.split('.').mapNotNull { it.toIntOrNull() }
            left.zip(right).map { (x, y) -> x.compareTo(y) }
                .firstOrNull { it != 0 }
                ?: left.size.compareTo(right.size)
        })
        ?.name
}

// Same resolution order as build.sh: ANDROID_NDK_HOME, then the newest NDK the
// SDK has installed. No revision is pinned, so any current NDK works.
val ndkHome = System.getenv("ANDROID_NDK_HOME")
    ?: newestInstalledNdk()?.let { File(sdkDir, "ndk/$it").absolutePath }
    ?: error(
        "no NDK found under ${File(sdkDir, "ndk").path}; " +
            "install one with sdkmanager or set ANDROID_NDK_HOME"
    )
val rustJniDir = File(repoRoot, "target/android-jni")

val buildRustJni = tasks.register<Exec>("buildRustJni") {
    workingDir = repoRoot
    environment("ANDROID_NDK_HOME", ndkHome)
    environment("PATH", cargoBin.absolutePath + File.pathSeparator + (System.getenv("PATH") ?: ""))
    commandLine(
        cargo, "ndk",
        "-t", "arm64-v8a",
        "-t", "armeabi-v7a",
        "-t", "x86_64",
        "-o", rustJniDir.absolutePath,
        "build", "-p", "hakimi-android", "--profile", "android-release", "--offline"
    )
}

val copyRustJni = tasks.register<Copy>("copyRustJni") {
    dependsOn(buildRustJni)
    from(rustJniDir) {
        include("**/libhakimi_android.so")
    }
    into(file("jniLibs"))
}

tasks.named("preBuild").configure {
    dependsOn(copyRustJni)
}
