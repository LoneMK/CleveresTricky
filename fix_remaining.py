file_path = "service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt"
with open(file_path, "r") as f:
    content = f.read()

# Lines 238+ readFile
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

# Lines 255+ writeFile
writefile_search = """                if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                    return false
                }
                val file = File(configDir, filename)
                if (!isSafePath(file)) return false
                SecureFile.writeText(file, content)"""
writefile_replace = """                val file = getSafeFile(configDir, filename)
                if (file == null) return false
                SecureFile.writeText(file, content)"""
content = content.replace(writefile_search, writefile_replace)

# Lines 274+ readKeybox
readkeybox_search = """        if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
            return ""
        }
        synchronized(fileLock) {
            return try {
                val keyboxDir = File(configDir, "keyboxes")
                val file = File(keyboxDir, filename)
                if (!isSafePath(file) || !file.canonicalPath.startsWith(keyboxDir.canonicalPath)) return ""
                if (file.exists()) {"""
readkeybox_replace = """        synchronized(fileLock) {
            return try {
                val keyboxDir = File(configDir, "keyboxes")
                val file = getSafeFile(keyboxDir, filename)
                if (file == null) return ""
                if (file.exists()) {"""
content = content.replace(readkeybox_search, readkeybox_replace)

# Lines 303+ serve -> readBytes
readbytes_search = """        if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
            return null
        }
        val file = File(configDir, filename)
        if (!isSafePath(file)) return null
        if (file.exists()) {"""
readbytes_replace = """        val file = getSafeFile(configDir, filename)
        if (file == null) return null
        if (file.exists()) {"""
content = content.replace(readbytes_search, readbytes_replace)

with open(file_path, "w") as f:
    f.write(content)
