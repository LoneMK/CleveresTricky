file_path = "service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt"
with open(file_path, "r") as f:
    content = f.read()

# readFile
s1 = """                if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                    Logger.e("Path traversal attempt detected in filename: $filename")
                    return ""
                }
                val f = File(configDir, filename)
                if (!isSafePath(f)) {
                    Logger.e("Path traversal attempt detected: $filename")
                    return ""
                }"""
r1 = """                val f = getSafeFile(configDir, filename)
                if (f == null) {
                    Logger.e("Path traversal attempt detected: $filename")
                    return ""
                }"""
content = content.replace(s1, r1)

# saveFile
s2 = """                if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                    Logger.e("Path traversal attempt detected in save filename: $filename")
                    return false
                }
                val f = File(configDir, filename)
                if (!isSafePath(f)) {
                    Logger.e("Path traversal attempt detected during save: $filename")
                    return false
                }"""
r2 = """                val f = getSafeFile(configDir, filename)
                if (f == null) {
                    Logger.e("Path traversal attempt detected during save: $filename")
                    return false
                }"""
content = content.replace(s2, r2)

# fileExists
s3 = """        if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
            return false
        }
        synchronized(fileLock) {
            val f = File(configDir, filename)
            return isSafePath(f) && f.exists()
        }"""
r3 = """        synchronized(fileLock) {
            val f = getSafeFile(configDir, filename)
            return f != null && f.exists()
        }"""
content = content.replace(s3, r3)

# toggleFile
s4 = """        if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
            return false
        }
        synchronized(fileLock) {
            val f = File(configDir, filename)"""
r4 = """        synchronized(fileLock) {
            val f = getSafeFile(configDir, filename)
            if (f == null) return false"""
content = content.replace(s4, r4)

with open(file_path, "w") as f:
    f.write(content)
