# R8 rules for the hakimi Android probe.
#
# Keep the app package intact: the manifest declares the components by name,
# and the Rust core resolves the JNI entry points as
# Java_com_hakimi_probe_Native_*. R8 still removes the unused parts of
# kotlin-stdlib, which is the largest part of classes.dex.
-dontwarn **
-keep class com.hakimi.probe.** { *; }
