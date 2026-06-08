import re

file_path = "service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt"
with open(file_path, "r") as f:
    content = f.read()

readfile_search = """                if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                    return ""
                }
                val file = File(configDir, filename)
                if (!isSafePath(file)) return ""
                if (file.exists()) {"""
readfile_replace = """                val file = getSafeFile(configDir, filename)
                if (file == null) return ""
                if (file.exists()) {"""
content = content.replace(readfile_search, readfile_replace)

with open(file_path, "w") as f:
    f.write(content)
