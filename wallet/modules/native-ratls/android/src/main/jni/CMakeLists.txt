cmake_minimum_required(VERSION 3.22)
project(ratls_jni C)

add_library(ratls_jni SHARED ratls_jni.c)

# 16 KB page-size support (required by Google Play for apps targeting Android 15+).
# Aligns loadable segments on a 16 KiB boundary so the .so works on both
# 4 KB and 16 KB page-size devices. See:
# https://developer.android.com/guide/practices/page-sizes
target_link_options(ratls_jni PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)

# Pre-built Rust shared library
add_library(ratls_mobile SHARED IMPORTED)
set_target_properties(ratls_mobile PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libratls_mobile.so"
)

target_link_libraries(ratls_jni ratls_mobile log)
