#!/usr/bin/env bash
# Build the hakimi Android probe APK without Gradle.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
BUILD="$ROOT/build"
JNI_DIR="$REPO/target/android-jni"
# Restrict to `ABIS=arm64-v8a` for a much smaller release APK.
ABIS="${ABIS:-x86_64 arm64-v8a}"

if [ -n "${ANDROID_HOME:-}" ]; then
  SDK="$(cygpath -u "$ANDROID_HOME")"
else
  SDK="/d/Android/Sdk"
fi
BT="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
JBR="${JAVA_HOME_DIR:-/d/Android/Android Studio/jbr}"
JAVAC="$JBR/bin/javac.exe"
JAR="$JBR/bin/jar.exe"
KEYTOOL="$JBR/bin/keytool.exe"
KOTLIN_HOME="${KOTLIN_HOME:-/d/Android/Android Studio/plugins/Kotlin/kotlinc}"
KOTLINC="$KOTLIN_HOME/bin/kotlinc"
KOTLIN_STDLIB="$KOTLIN_HOME/lib/kotlin-stdlib.jar"

export JAVA_HOME="$(cygpath -w "$JBR")"

if [ "${SKIP_RUST:-0}" != "1" ]; then
  export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$SDK/ndk/27.2.12479018}"
  # `android-release` is size-first (opt-level=z, fat LTO, stripped) but keeps
  # the unwind panic strategy so the JNI shell's catch_unwind still works.
  TARGETS=()
  for abi in $ABIS; do
    TARGETS+=(-t "$abi")
  done
  (cd "$REPO" && cargo ndk "${TARGETS[@]}" -o "$JNI_DIR" \
      build -p hakimi-android --profile android-release --offline)
fi

# The probe CA is generated locally and never committed: its private key is
# packaged into the debug APK. Users must install it as a USER CA.
CA_DIR="$ROOT/assets/ca"
if [ ! -s "$CA_DIR/ca.pem" ] || [ ! -s "$CA_DIR/key.pem" ]; then
  mkdir -p "$CA_DIR"
  MSYS_NO_PATHCONV=1 openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 -out "$CA_DIR/key.pem"
  MSYS_NO_PATHCONV=1 openssl req -new -x509 -key "$CA_DIR/key.pem" \
    -out "$CA_DIR/ca.pem" -days 3650 \
    -subj "/CN=Hakimi Android Probe CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
fi
mkdir -p "$ROOT/res/raw"
cp "$CA_DIR/ca.pem" "$ROOT/res/raw/hakimi_ca.bin"

rm -rf "$BUILD"
mkdir -p "$BUILD/classes" "$BUILD/gen" "$BUILD/dex" "$BUILD/lib"
mkdir -p "$ROOT/jniLibs"

"$BT/aapt2.exe" compile --dir "$ROOT/res" -o "$BUILD/res.zip"
"$BT/aapt2.exe" link \
  -o "$BUILD/app-unsigned.apk" \
  -I "$PLATFORM" \
  --manifest "$ROOT/AndroidManifest.xml" \
  -A "$ROOT/assets" \
  --min-sdk-version 26 \
  --target-sdk-version 35 \
  --version-code 3 \
  --version-name 0.3 \
  --java "$BUILD/gen" \
  "$BUILD/res.zip"

# aapt2 generates R.java; compile it on its own so kotlinc can see the R class.
mkdir -p "$BUILD/rclasses"
"$JAVAC" --release 17 -classpath "$PLATFORM" -d "$BUILD/rclasses" \
  $(find "$BUILD/gen" -name '*.java')
"$JAR" cf "$BUILD/rclasses.jar" -C "$BUILD/rclasses" .

# Kotlin only: no AndroidX, no third-party runtime. kotlin-stdlib is the sole
# additional jar shipped in the APK.
"$KOTLINC" -no-jdk -jvm-target 17 -nowarn \
  -classpath "$(cygpath -w "$PLATFORM");$(cygpath -w "$BUILD/rclasses")" \
  -d "$BUILD/classes" \
  $(find "$ROOT/src" -name '*.kt')
"$JAR" cf "$BUILD/classes.jar" -C "$BUILD/classes" .

cmd //c "$(cygpath -w "$BT/d8.bat")" \
  --lib "$(cygpath -w "$PLATFORM")" \
  --min-api 26 \
  --output "$(cygpath -w "$BUILD/dex")" \
  "$(cygpath -w "$BUILD/classes.jar")" \
  "$(cygpath -w "$BUILD/rclasses.jar")" \
  "$(cygpath -w "$KOTLIN_STDLIB")"

for abi in $ABIS; do
  if [ -f "$JNI_DIR/$abi/libhakimi_android.so" ]; then
    mkdir -p "$BUILD/lib/$abi" "$ROOT/jniLibs/$abi"
    cp "$JNI_DIR/$abi/libhakimi_android.so" "$BUILD/lib/$abi/"
    cp "$JNI_DIR/$abi/libhakimi_android.so" "$ROOT/jniLibs/$abi/"
  fi
done

python - "$(cygpath -w "$BUILD/app-unsigned.apk")" \
  "$(cygpath -w "$BUILD/dex/classes.dex")" "$(cygpath -w "$BUILD/lib")" <<'PY'
import os
import sys
import zipfile

apk, dex, lib_dir = sys.argv[1:4]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
    archive.write(dex, "classes.dex")
    for abi in os.listdir(lib_dir):
        so = os.path.join(lib_dir, abi, "libhakimi_android.so")
        if os.path.exists(so):
            archive.write(so, "lib/%s/libhakimi_android.so" % abi)
PY

# apksigner rejects duplicate ZIP entries; fail early with a clear message.
if unzip -Z1 "$BUILD/app-unsigned.apk" | sort | uniq -d | grep -q .; then
  echo "duplicate ZIP entries in $BUILD/app-unsigned.apk" >&2
  exit 1
fi

"$BT/zipalign.exe" -P 16 -f 4 "$BUILD/app-unsigned.apk" "$BUILD/app-aligned.apk"

KEYSTORE="$ROOT/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -keystore "$KEYSTORE" \
    -alias androiddebugkey -storepass android -keypass android \
    -dname "CN=Android Debug,O=Android,C=US" -keyalg RSA -keysize 2048 \
    -validity 10000
fi

cmd //c "$(cygpath -w "$BT/apksigner.bat")" sign \
  --ks "$(cygpath -w "$KEYSTORE")" \
  --ks-pass pass:android --key-pass pass:android \
  --out "$(cygpath -w "$ROOT/hakimi-probe.apk")" \
  "$(cygpath -w "$BUILD/app-aligned.apk")"

echo "APK: $ROOT/hakimi-probe.apk"
