plugins {
    id("com.android.application") version "9.3.0"
}

android {
    namespace = "com.hakimi.probe"
    compileSdk = 37
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "com.hakimi.probe"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.3"
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
val repoRoot = rootProject.projectDir.parentFile.parentFile
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
val ndkHome = System.getenv("ANDROID_NDK_HOME")
    ?: File(sdkDir, "ndk/27.2.12479018").absolutePath
val rustJniDir = File(repoRoot, "target/android-jni")

val buildRustJni = tasks.register<Exec>("buildRustJni") {
    workingDir = repoRoot
    environment("ANDROID_NDK_HOME", ndkHome)
    environment("PATH", cargoBin.absolutePath + File.pathSeparator + (System.getenv("PATH") ?: ""))
    commandLine(
        cargo, "ndk",
        "-t", "arm64-v8a",
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
