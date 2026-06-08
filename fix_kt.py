import re

file_path = "service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt"
with open(file_path, "r") as f:
    content = f.read()

# Replace variables
content = content.replace(
    "@Volatile private var isFetchingTelegram = false",
    "private val isFetchingTelegram = java.util.concurrent.atomic.AtomicBoolean(false)"
)
content = content.replace(
    "@Volatile private var isFetchingBanned = false",
    "private val isFetchingBanned = java.util.concurrent.atomic.AtomicBoolean(false)"
)

# Fix fetchTelegramCount
# Replace:
# if (!isFetchingTelegram) {
#     isFetchingTelegram = true
# With:
# if (isFetchingTelegram.compareAndSet(false, true)) {
content = content.replace(
    "if (!isFetchingTelegram) {\n            isFetchingTelegram = true",
    "if (isFetchingTelegram.compareAndSet(false, true)) {"
)
# And the false setter
content = content.replace(
    "isFetchingTelegram = false\n                }",
    "isFetchingTelegram.set(false)\n                }"
)

# Fix fetchBannedCount
# Replace:
# if (!isFetchingBanned) {
#     isFetchingBanned = true
# With:
# if (isFetchingBanned.compareAndSet(false, true)) {
content = content.replace(
    "if (!isFetchingBanned) {\n            isFetchingBanned = true",
    "if (isFetchingBanned.compareAndSet(false, true)) {"
)
# And the false setter
content = content.replace(
    "isFetchingBanned = false\n                }",
    "isFetchingBanned.set(false)\n                }"
)

with open(file_path, "w") as f:
    f.write(content)
