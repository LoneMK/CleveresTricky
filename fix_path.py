import re

file_path = "service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt"
with open(file_path, "r") as f:
    content = f.read()

# Add getSafeFile to companion object
companion_match = re.search(r"companion object \{", content)
if companion_match:
    idx = companion_match.end()
    get_safe_file_method = """
        fun getSafeFile(baseDir: File, requestedPath: String): File? {
            val targetFile = File(baseDir, requestedPath)
            return try {
                val canonicalBase = baseDir.canonicalPath
                val canonicalTarget = targetFile.canonicalPath
                if (canonicalTarget.equals(canonicalBase) || canonicalTarget.startsWith(canonicalBase + File.separator)) {
                    targetFile
                } else {
                    Logger.w("Path Traversal attempt prevented! Target: $canonicalTarget")
                    null
                }
            } catch (e: Exception) {
                null
            }
        }
"""
    content = content[:idx] + get_safe_file_method + content[idx:]

# Remove contains("..") from isValidFilename
content = content.replace(
    'return cleveres.tricky.cleverestech.isValidFilename(name) && !name.contains("..") && !name.contains("/") && !name.contains("\\\\")',
    'return cleveres.tricky.cleverestech.isValidFilename(name)'
)

# Now we need to fix the specific areas

# readFile method:
# Replace:
#                 if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
#                     return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
#                 }
#                 val file = File(configDir, filename)
#                 if (!isSafePath(file)) {
#                     return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
#                 }
#                 if (file.exists()) {

readfile_search = """                if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
                }
                val file = File(configDir, filename)
                if (!isSafePath(file)) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                }
                if (file.exists()) {"""
readfile_replace = """                val file = getSafeFile(configDir, filename)
                if (file == null) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                }
                if (file.exists()) {"""
content = content.replace(readfile_search, readfile_replace)

# writeFile method:
writefile_search = """                if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
                }
                val file = File(configDir, filename)
                if (!isSafePath(file)) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                }"""
writefile_replace = """                val file = getSafeFile(configDir, filename)
                if (file == null) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                }"""
content = content.replace(writefile_search, writefile_replace)

# readKeybox method:
readkeybox_search = """        if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
            return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
        }
        synchronized(fileLock) {
            return try {
                val keyboxDir = File(configDir, "keyboxes")
                val file = File(keyboxDir, filename)
                if (!isSafePath(file) || !file.canonicalPath.startsWith(keyboxDir.canonicalPath)) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                }"""
readkeybox_replace = """        synchronized(fileLock) {
            return try {
                val keyboxDir = File(configDir, "keyboxes")
                val file = getSafeFile(keyboxDir, filename)
                if (file == null) {
                    return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                }"""
content = content.replace(readkeybox_search, readkeybox_replace)

# parseBody for zip / cbox:
cbox_zip_search = """                 if (originalName.contains("..") || originalName.contains("/") || originalName.contains("\\\\")) {
                     return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
                 }
                 val tmpFile = File(tmpFilePath)
                 val bytes = tmpFile.readBytes()

                 // Process as CBOX or ZIP
                 if (originalName.endsWith(".cbox") || originalName.endsWith(".zip")) {
                     val keyboxDir = File(configDir, "keyboxes")
                     SecureFile.mkdirs(keyboxDir, 448)
                     val dest = File(keyboxDir, originalName)
                     if (!dest.canonicalPath.startsWith(keyboxDir.canonicalPath + File.separator) && dest.canonicalPath != keyboxDir.canonicalPath) {
                         return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                     }"""
cbox_zip_replace = """                 val tmpFile = File(tmpFilePath)
                 val bytes = tmpFile.readBytes()

                 // Process as CBOX or ZIP
                 if (originalName.endsWith(".cbox") || originalName.endsWith(".zip")) {
                     val keyboxDir = File(configDir, "keyboxes")
                     SecureFile.mkdirs(keyboxDir, 448)
                     val dest = getSafeFile(keyboxDir, originalName)
                     if (dest == null) {
                         return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                     }"""
content = content.replace(cbox_zip_search, cbox_zip_replace)

# saveKeybox method:
savekeybox_search = """                     val keyboxDir = File(configDir, "keyboxes")
                     SecureFile.mkdirs(keyboxDir, 448)
                     if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                         return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
                     }
                     val file = File(keyboxDir, filename)
                     if (!isSafePath(file) || !file.canonicalPath.startsWith(keyboxDir.canonicalPath)) {
                         return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                     }"""
savekeybox_replace = """                     val keyboxDir = File(configDir, "keyboxes")
                     SecureFile.mkdirs(keyboxDir, 448)
                     val file = getSafeFile(keyboxDir, filename)
                     if (file == null) {
                         return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
                     }"""
content = content.replace(savekeybox_search, savekeybox_replace)

# deleteKeybox method:
deletekeybox_search = """                 if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
                     return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
                 }
                 synchronized(fileLock) {
                     val keyboxDir = File(configDir, "keyboxes")
                     val f = File(keyboxDir, filename)
                     if (isSafePath(f) && f.canonicalPath.startsWith(keyboxDir.canonicalPath) && f.exists()) {"""
deletekeybox_replace = """                 synchronized(fileLock) {
                     val keyboxDir = File(configDir, "keyboxes")
                     val f = getSafeFile(keyboxDir, filename)
                     if (f != null && f.exists()) {"""
content = content.replace(deletekeybox_search, deletekeybox_replace)

# zip extract logic
zip_extract_search = """                    if (name.contains("..") || name.startsWith("/") || name.contains("\\\\")) {
                        throw SecurityException("Zip entry contains path traversal: $name")
                    }
                    val file = File(configDir, name)
                    if (file.canonicalPath.equals(configDir.canonicalPath) || file.canonicalPath.startsWith(configDir.canonicalPath + File.separator)) {"""
zip_extract_replace = """                    val file = getSafeFile(configDir, name)
                    if (file != null) {"""
content = content.replace(zip_extract_search, zip_extract_replace)

# Wait we have `serve` returning file for generic download
serve_file_search = """        if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
            return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid filename")
        }
        val file = File(configDir, filename)
        if (!isSafePath(file)) {
            return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
        }"""
serve_file_replace = """        val file = getSafeFile(configDir, filename)
        if (file == null) {
            return secureResponse(Response.Status.BAD_REQUEST, "text/plain", "Path traversal attempt detected")
        }"""
content = content.replace(serve_file_search, serve_file_replace)

with open(file_path, "w") as f:
    f.write(content)
