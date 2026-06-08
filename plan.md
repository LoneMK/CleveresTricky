1.  **Replace `safe_memcpy` with pipe-based validation in `module/src/main/cpp/binder_interceptor.cpp`**.
    *   The current implementation uses `sigaction` and `sigsetjmp` to catch SIGSEGV/SIGBUS when probing memory bounds, which is unsafe in a multi-threaded daemon due to race conditions.
    *   We will replace `safe_memcpy` with a pipe-based approach (or similar robust solution). Since it's copying memory anyway, we can create a pipe, write `src` to `fd[1]`, and read into `dst` from `fd[0]`. This utilizes the kernel's built-in `EFAULT` handling for invalid pointers without risking process crash or signal interference.

2.  **Fix Kotlin Volatile Race Conditions in `service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt`**.
    *   Replace `@Volatile private var isFetchingTelegram = false` with `private val isFetchingTelegram = AtomicBoolean(false)`.
    *   Replace `@Volatile private var isFetchingBanned = false` with `private val isFetchingBanned = AtomicBoolean(false)`.
    *   Update `fetchTelegramCount()` and `fetchBannedCount()` to use `compareAndSet(false, true)` to ensure thread-safe atomic state transitions.

3.  **Enhance Path Traversal Protections in `service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt`**.
    *   Currently, there are manual checks like `filename.contains("..") || filename.contains("/")` sprinkled throughout the file.
    *   Instead of relying heavily on checking the input string (which can be bypassed by encoding), we will use the user's recommended "Canonical Path Validation" approach, ensuring the final resolved file's canonical path strictly starts with the target directory's canonical path. We already have `isSafePath` doing something similar, but the user requested a strict, unified `getSafeFile(baseDir, requestedPath)` approach.
    *   Since NanoHTTPD decode behavior is tricky, we'll implement `fun getSafeFile(baseDir: File, requestedPath: String): File?` and replace vulnerable `File(dir, filename)` patterns where user input is involved.
