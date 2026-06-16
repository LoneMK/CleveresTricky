# Real-World Scenario: AOSP Native Component Migration and RTTI

This document provides a real-world scenario analysis of issues encountered when injecting native modules into Android Open Source Project (AOSP) system components like `keystore2`, specifically focusing on C++ compiler flags and their interaction with the Android linker.

## The Scenario

A user attempts to use a dynamic interception module (e.g., CleveresTricky) on an AOSP-based custom ROM (like LineageOS, PixelExperience, or pure AOSP). Upon startup or module injection, the target process (`keystore2`) crashes or logs a severe error, and the module fails to function.

The `logcat` output shows an error similar to this:
```
dlerror: dlopen failed: cannot locate symbol "_ZTIN7android7BBinderE" referenced by "/data/adb/modules/cleverestricky/libcleverestricky.so"
```

## The Root Cause: Run-Time Type Information (RTTI)

The error `cannot locate symbol "_ZTIN7android7BBinderE"` translates to "cannot locate `typeinfo for android::BBinder`" (`_ZTI` is the Itanium C++ ABI mangled prefix for `typeinfo`).

### Why does this happen?

1.  **AOSP Compilation Defaults**: By default, Android system libraries (such as `libbinder.so`, `libutils.so`) are compiled **without** RTTI (`-fno-rtti`) to save space and improve performance. This means the RTTI metadata structures (like `typeinfo`) are stripped from these libraries.
2.  **Module Compilation**: If a third-party native module (like `libcleverestricky.so`) interacts with AOSP classes (like `android::BBinder` or `android::Parcel`) and is compiled **with** RTTI enabled (which is often the default in NDK CMake builds if not explicitly disabled or if `rtti` is present in `ANDROID_CPP_FEATURES`), the compiler generates dependencies on the `typeinfo` of those AOSP classes.
3.  **The Linker Failure**: When `dlopen` tries to load `libcleverestricky.so` into the `keystore2` process, the dynamic linker attempts to resolve the required `typeinfo` symbol for `android::BBinder`. Because AOSP's `libbinder.so` was built without it, the symbol is unresolved, `dlopen` fails, and the injection is aborted.

## The Fix

To ensure compatibility with AOSP processes, native modules injecting into system domains must also be compiled without RTTI.

### 1. Gradle Configuration (`build.gradle.kts`)

Ensure that the NDK build arguments do not explicitly request RTTI. The `ANDROID_CPP_FEATURES` argument should **only** contain `exceptions` (if exceptions are needed) and explicitly omit `rtti`.

**Incorrect (Causes the crash):**
```kotlin
arguments(
    "-DANDROID_CPP_FEATURES=rtti exceptions",
    // ...
)
```

**Correct:**
```kotlin
arguments(
    "-DANDROID_CPP_FEATURES=exceptions",
    // ...
)
```

### 2. CMake Configuration (`CMakeLists.txt`)

Explicitly pass the `-fno-rtti` flag to the compiler to ensure it does not generate `typeinfo` metadata or RTTI dependencies.

**Correct:**
```cmake
add_compile_options(-Werror -Wall -Wextra -Wno-unused-parameter -fno-rtti)
```

## Prevention and Best Practices

1.  **Understand the Target Environment**: When writing code that runs within the context of Android system daemons (like `keystore2`, `zygote`, or `surfaceflinger`), you must adhere to the compilation standards of those environments. AOSP aggressively strips unused metadata.
2.  **Avoid `dynamic_cast` and `typeid`**: Without RTTI, you cannot use C++ features like `dynamic_cast` or `typeid`. If your code relies on these, it will fail to compile with `-fno-rtti`. Refactor code to use virtual functions, enum-based type checking, or `static_cast` if you are absolutely certain of the underlying type.
3.  **Use `c++filt` for Debugging**: When encountering cryptic unresolved symbols like `_ZTIN7android7BBinderE`, use the `c++filt` command-line tool (or `llvm-cxxfilt` in the NDK) to demangle the name and understand what the linker is looking for.
    ```bash
    $ c++filt _ZTIN7android7BBinderE
    typeinfo for android::BBinder
    ```
4.  **Rust Migration (Future-Proofing)**: As suggested by the user ("Mümkünse rust çevirsek daha güvenli olur"), migrating critical hooks and parsing logic to Rust mitigates many of these C++ ABI and RTTI issues. Rust handles polymorphism differently (via traits and fat pointers) and does not rely on global C++ `typeinfo` symbols, making it significantly safer and more reliable for cross-boundary injection scenarios. We have already begun migrating parsing logic (e.g., CBOR/COSE) to Rust, and further migrations are encouraged.
