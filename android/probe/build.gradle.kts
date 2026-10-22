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
