#!/usr/bin/env bash
# Build the hakimi Android probe APK without Gradle.
#
# Local default (Windows/Git Bash):
#   ./build.sh
# CI / Linux:
#   ANDROID_HOME=... KOTLIN_HOME=... VERSION_NAME=0.1.0 VERSION_CODE=1000 ./build.sh
#
# Release knobs:
#   ABIS=arm64-v8a                 (default; use x86_64 for an emulator)
#   VERSION_NAME / VERSION_CODE    (passed to aapt2, override the manifest)
#   APK_OUT                        (output path, default ./hakimi-probe.apk)
#   HAKIMI_OFFLINE=1               (add --offline to cargo)
#   ANDROID_KEYSTORE               (default: ./debug.keystore)
#   ANDROID_KEYSTORE_PASSWORD / ANDROID_KEY_ALIAS / ANDROID_KEY_PASSWORD
#   HAKIMI_CA_DIR                  (default: ./assets/ca)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
BUILD="$ROOT/build"
JNI_DIR="$REPO/target/android-jni"

# Official releases are arm64-only. Pass ABIS=x86_64 when building for an
# emulator, or ABIS="arm64-v8a x86_64" for a combined local build.
ABIS="${ABIS:-arm64-v8a}"

# Local builds follow the Rust workspace version so the APK, the desktop
# client and the core report the same number. Release CI passes VERSION_NAME
# and VERSION_CODE from the tag, which override these defaults.
workspace_version() {
  awk '
    /^\[workspace\.package\]/ { section = 1; next }
    /^\[/ { section = 0 }
    section && /^[[:space:]]*version[[:space:]]*=/ {
      sub(/^[^"]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' "$REPO/Cargo.toml"
}

DEFAULT_VERSION_NAME="$(workspace_version)"
if [ -z "$DEFAULT_VERSION_NAME" ]; then
  echo "could not read [workspace.package] version from Cargo.toml" >&2
  exit 1
fi
VERSION_NAME="${VERSION_NAME:-$DEFAULT_VERSION_NAME}"

# Same derivation as the release workflow: major * 1_000_000 + minor * 1_000
# + patch, ignoring prerelease/build metadata.
version_base="${VERSION_NAME%%[-+]*}"
IFS=. read -r version_major version_minor version_patch <<< "$version_base"
version_major="${version_major:-0}"
version_minor="${version_minor:-0}"
version_patch="${version_patch:-0}"
case "$version_major$version_minor$version_patch" in
  ''|*[!0-9]*)
    echo "VERSION_NAME must start with a numeric major.minor.patch: $VERSION_NAME" >&2
    exit 1
    ;;
esac
DEFAULT_VERSION_CODE=$((10#$version_major * 1000000 + 10#$version_minor * 1000 + 10#$version_patch))
VERSION_CODE="${VERSION_CODE:-$DEFAULT_VERSION_CODE}"
APK_OUT="${APK_OUT:-$ROOT/hakimi-probe.apk}"
MIN_SDK="${MIN_SDK:-26}"
TARGET_SDK="${TARGET_SDK:-35}"
COMPILE_SDK="${COMPILE_SDK:-37}"
BUILD_TOOLS="${BUILD_TOOLS:-37.0.0}"
NDK_VERSION="${NDK_VERSION:-27.2.12479018}"

case "$VERSION_CODE" in
  ''|*[!0-9]*)
    echo "VERSION_CODE must be an integer: $VERSION_CODE" >&2
    exit 1
    ;;
esac

# Windows Git Bash needs .exe suffixes and path translation; Linux/macOS do not.
EXE=""
CP_SEP=":"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    EXE=".exe"
    CP_SEP=";"
    ;;
esac

winpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

unixpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s' "$1"; fi
}

# SDK
if [ -n "${ANDROID_HOME:-}" ]; then
  SDK="$(unixpath "$ANDROID_HOME")"
elif [ -n "${ANDROID_SDK_ROOT:-}" ]; then
  SDK="$(unixpath "$ANDROID_SDK_ROOT")"
elif [ -d "/d/Android/Sdk" ]; then
  SDK="/d/Android/Sdk"
elif [ -d "$HOME/Android/Sdk" ]; then
  SDK="$HOME/Android/Sdk"
else
  echo "ANDROID_HOME is not set and no default Android SDK was found" >&2
  exit 1
fi
BT="${ANDROID_BUILD_TOOLS:-$SDK/build-tools/$BUILD_TOOLS}"
if [ -e "$SDK/platforms/android-$COMPILE_SDK/android.jar" ]; then
  PLATFORM="$SDK/platforms/android-$COMPILE_SDK/android.jar"
elif [ -e "$SDK/platforms/android-$COMPILE_SDK.0/android.jar" ]; then
  PLATFORM="$SDK/platforms/android-$COMPILE_SDK.0/android.jar"
else
  PLATFORM="$(find "$SDK/platforms" -maxdepth 2 -path "*/android-$COMPILE_SDK*/android.jar" -print -quit 2>/dev/null || true)"
fi

# JDK
if [ -n "${JAVA_HOME:-}" ]; then
  JBR="$(unixpath "$JAVA_HOME")"
elif [ -d "/d/Android/Android Studio/jbr" ]; then
  JBR="/d/Android/Android Studio/jbr"
else
  JBR="$(dirname "$(dirname "$(command -v java)")")"
fi
JAVA="$JBR/bin/java$EXE"
JAVAC="$JBR/bin/javac$EXE"
JAR="$JBR/bin/jar$EXE"
KEYTOOL="$JBR/bin/keytool$EXE"

# Kotlin
KOTLIN_HOME="${KOTLIN_HOME:-/d/Android/Android Studio/plugins/Kotlin/kotlinc}"
KOTLIN_HOME="$(unixpath "$KOTLIN_HOME")"
KOTLINC="$KOTLIN_HOME/bin/kotlinc"
KOTLIN_STDLIB="$KOTLIN_HOME/lib/kotlin-stdlib.jar"

export JAVA_HOME="$(winpath "$JBR")"

if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi

AAPT2="$BT/aapt2$EXE"
ZIPALIGN="$BT/zipalign$EXE"
APKSIGNER_JAR="$BT/lib/apksigner.jar"
R8_JAR="$BT/lib/d8.jar"

for tool in "$AAPT2" "$ZIPALIGN" "$APKSIGNER_JAR" "$R8_JAR" "$PLATFORM"; do
  if [ ! -e "$tool" ]; then
    echo "missing Android tool: $tool" >&2
    exit 1
  fi
done
for tool in "$JAVA" "$JAVAC" "$JAR" "$KEYTOOL" "$KOTLINC" "$KOTLIN_STDLIB"; do
  if [ ! -e "$tool" ]; then
    echo "missing JDK/Kotlin file: $tool" >&2
    exit 1
  fi
done

if [ "${SKIP_RUST:-0}" != "1" ]; then
  NDK_HOME="${ANDROID_NDK_HOME:-$SDK/ndk/$NDK_VERSION}"
  export ANDROID_NDK_HOME="$(unixpath "$NDK_HOME")"
  TARGETS=()
  for abi in $ABIS; do
    TARGETS+=(-t "$abi")
  done
  CARGO_ARGS=()
  if [ "${HAKIMI_OFFLINE:-0}" = "1" ]; then
    CARGO_ARGS+=(--offline)
  fi
  # `android-release` is size-first (opt-level=z, fat LTO, stripped) but keeps
  # the unwind panic strategy so the JNI shell's catch_unwind still works.
  (cd "$REPO" && cargo ndk "${TARGETS[@]}" -o "$JNI_DIR" \
      build -p hakimi-android --profile android-release "${CARGO_ARGS[@]}")
fi

# The probe CA is generated locally and never committed: its private key is
# packaged into the APK. Users must install it as a USER CA. CI supplies a
# stable CA via HAKIMI_CA_DIR so app updates do not require reinstalling it.
CA_DIR="${HAKIMI_CA_DIR:-$ROOT/assets/ca}"
if [ ! -s "$CA_DIR/ca.pem" ] || [ ! -s "$CA_DIR/key.pem" ]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "missing CA files in $CA_DIR and openssl is not installed" >&2
    exit 1
  fi
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

# The asset is what Bootstrap copies into the core data dir, while res/raw is
# the app's own trust anchor. Both must be the same CA, especially when a
# release supplies a stable pair through HAKIMI_CA_DIR.
mkdir -p "$ROOT/assets/ca"
if ! cmp -s "$CA_DIR/ca.pem" "$ROOT/assets/ca/ca.pem" 2>/dev/null \
    || ! cmp -s "$CA_DIR/key.pem" "$ROOT/assets/ca/key.pem" 2>/dev/null; then
  cp "$CA_DIR/ca.pem" "$ROOT/assets/ca/ca.pem"
  cp "$CA_DIR/key.pem" "$ROOT/assets/ca/key.pem"
fi

# One CA for the life of the app: fail early if the cert and key do not match.
if command -v openssl >/dev/null 2>&1; then
  CERT_PUB="$(mktemp)"
  KEY_PUB="$(mktemp)"
  if ! openssl x509 -in "$CA_DIR/ca.pem" -noout -pubkey >"$CERT_PUB" 2>/dev/null \
      || ! openssl pkey -in "$CA_DIR/key.pem" -pubout >"$KEY_PUB" 2>/dev/null \
      || ! cmp -s "$CERT_PUB" "$KEY_PUB"; then
    rm -f "$CERT_PUB" "$KEY_PUB"
    echo "CA certificate and key do not match in $CA_DIR" >&2
    exit 1
  fi
  rm -f "$CERT_PUB" "$KEY_PUB"
fi

mkdir -p "$ROOT/res/raw"
cp "$CA_DIR/ca.pem" "$ROOT/res/raw/hakimi_ca.bin"

rm -rf "$BUILD" "$ROOT/jniLibs"
mkdir -p "$BUILD/classes" "$BUILD/gen" "$BUILD/dex" "$BUILD/lib"
mkdir -p "$ROOT/jniLibs"

"$AAPT2" compile --dir "$ROOT/res" -o "$BUILD/res.zip"
"$AAPT2" link \
  -o "$BUILD/app-unsigned.apk" \
  -I "$PLATFORM" \
  --manifest "$ROOT/AndroidManifest.xml" \
  -A "$ROOT/assets" \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TARGET_SDK" \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  --java "$BUILD/gen" \
  "$BUILD/res.zip"

# aapt2 generates R.java; compile it on its own so kotlinc can see the R class.
mkdir -p "$BUILD/rclasses"
"$JAVAC" --release 17 -classpath "$(winpath "$PLATFORM")" -d "$BUILD/rclasses" \
  $(find "$BUILD/gen" -name '*.java')
"$JAR" cf "$BUILD/rclasses.jar" -C "$BUILD/rclasses" .

# Kotlin only: no AndroidX, no third-party runtime. kotlin-stdlib is the sole
# additional jar shipped in the APK.
"$KOTLINC" -no-jdk -jvm-target 17 -nowarn \
  -classpath "$(winpath "$PLATFORM")$CP_SEP$(winpath "$BUILD/rclasses")" \
  -d "$BUILD/classes" \
  $(find "$ROOT/src" -name '*.kt')
"$JAR" cf "$BUILD/classes.jar" -C "$BUILD/classes" .

# R8 removes the unused kotlin-stdlib code and strips debug info. The keep
# rules preserve the manifest components and the JNI entry point.
"$JAVA" -cp "$(winpath "$R8_JAR")" com.android.tools.r8.R8 \
  --release \
  --min-api "$MIN_SDK" \
  --lib "$(winpath "$PLATFORM")" \
  --pg-conf "$(winpath "$ROOT/proguard-rules.pro")" \
  --pg-map-output "$(winpath "$BUILD/mapping.txt")" \
  --output "$(winpath "$BUILD/dex")" \
  "$(winpath "$BUILD/classes.jar")" \
  "$(winpath "$BUILD/rclasses.jar")" \
  "$(winpath "$KOTLIN_STDLIB")"

for abi in $ABIS; do
  SO="$JNI_DIR/$abi/libhakimi_android.so"
  if [ ! -f "$SO" ]; then
    echo "missing native library: $SO (set SKIP_RUST=1 only after a Rust build)" >&2
    exit 1
  fi
  mkdir -p "$BUILD/lib/$abi" "$ROOT/jniLibs/$abi"
  cp "$SO" "$BUILD/lib/$abi/"
  cp "$SO" "$ROOT/jniLibs/$abi/"
done

# Keep the native libraries ZIP_DEFLATED so the download stays small; Android
# extracts them on install. compresslevel=9 also squeezes the dex a little.
"$PYTHON" - "$(winpath "$BUILD/app-unsigned.apk")" \
  "$(winpath "$BUILD/dex")" "$(winpath "$BUILD/lib")" <<'PY'
import glob
import os
import sys
import zipfile

apk, dex_dir, lib_dir = sys.argv[1:4]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for dex in sorted(glob.glob(os.path.join(dex_dir, "*.dex"))):
        archive.write(dex, os.path.basename(dex))
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

"$ZIPALIGN" -P 16 -f 4 "$BUILD/app-unsigned.apk" "$BUILD/app-aligned.apk"

KEYSTORE="${ANDROID_KEYSTORE:-$ROOT/debug.keystore}"
KS_PASS="${ANDROID_KEYSTORE_PASSWORD:-android}"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-androiddebugkey}"
KEY_PASS="${ANDROID_KEY_PASSWORD:-android}"
if [ ! -f "$KEYSTORE" ]; then
  "$KEYTOOL" -genkeypair -keystore "$(winpath "$KEYSTORE")" \
    -alias "$KEY_ALIAS" -storepass "$KS_PASS" -keypass "$KEY_PASS" \
    -dname "CN=Android Debug,O=Android,C=US" -keyalg RSA -keysize 2048 \
    -validity 10000
fi

mkdir -p "$(dirname "$APK_OUT")"
rm -f "$APK_OUT"
# minSdk is 26, so v1/JAR signing is dead weight; v2/v3 are enough.
"$JAVA" -jar "$(winpath "$APKSIGNER_JAR")" sign \
  --ks "$(winpath "$KEYSTORE")" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "pass:$KS_PASS" \
  --key-pass "pass:$KEY_PASS" \
  --v1-signing-enabled false \
  --v4-signing-enabled false \
  --out "$(winpath "$APK_OUT")" \
  "$(winpath "$BUILD/app-aligned.apk")"

echo "APK: $APK_OUT"
