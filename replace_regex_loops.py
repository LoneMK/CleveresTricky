import re

content = ""
with open("./service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt", "r") as f:
    content = f.read()

# Replace .matches(TARGET_PKG_REGEX) with a manual function `isValidTargetPkg(it)`
funcs = """
private fun isValidPkgName(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '.' || c == '*')) return false
    }
    return true
}

private fun isValidTemplateName(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '-')) return false
    }
    return true
}

private fun isValidKeyboxFilename(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '.' || c == '-')) return false
    }
    return true
}

private fun isValidKeyValue(s: String): Boolean {
    if (s.isEmpty()) return false
    val eqIdx = s.indexOf('=')
    if (eqIdx <= 0 || eqIdx == s.length - 1) return false
    for (i in 0 until eqIdx) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '.')) return false
    }
    return true
}

private fun isValidSafeBuildVarValue(s: String): Boolean {
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '-' || c == '.' || c.isWhitespace() || c == '/' || c == ':' || c == ',' || c == '+' || c == '=' || c == '(' || c == ')' || c == '@')) return false
    }
    return true
}

private fun isValidTargetPkg(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '.' || c == '*' || c == '!')) return false
    }
    return true
}

private fun isValidSecurityPatch(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '=' || c == '-')) return false
    }
    return true
}

private fun isValidFilename(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '.' || c == '_' || c == '-')) return false
    }
    return true
}

private fun isValidPermissions(s: String): Boolean {
    if (s.isEmpty()) return false
    for (i in 0 until s.length) {
        val c = s[i]
        if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '_' || c == '.' || c == ',')) return false
    }
    return true
}

"""

# Remove regex declarations
content = re.sub(r'private val WHITESPACE_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val WHITESPACE_FIND_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val PKG_NAME_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val TEMPLATE_NAME_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val KEYBOX_FILENAME_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val KEY_VALUE_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val SAFE_BUILD_VAR_VALUE_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val TARGET_PKG_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val SECURITY_PATCH_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val FILENAME_REGEX = Regex\([^)]+\)\n', '', content)
content = re.sub(r'private val PERMISSIONS_REGEX = Regex\([^)]+\)\n', funcs, content)

# Replace matches calls
content = re.sub(r'\.matches\(PKG_NAME_REGEX\)', '?.let { isValidPkgName(it) } == true', content)
content = content.replace('name.matches(FILENAME_REGEX)', 'cleveres.tricky.cleverestech.isValidFilename(name)')
content = content.replace('pkg.matches(PKG_NAME_REGEX)', 'isValidPkgName(pkg)')
content = content.replace('filename.matches(FILENAME_REGEX)', 'isValidFilename(filename)')
content = content.replace('line.matches(KEY_VALUE_REGEX)', 'isValidKeyValue(line)')
content = content.replace('value.matches(SAFE_BUILD_VAR_VALUE_REGEX)', 'isValidSafeBuildVarValue(value)')
content = content.replace('it.matches(TARGET_PKG_REGEX)', 'isValidTargetPkg(it)')
content = content.replace('it.matches(SECURITY_PATCH_REGEX)', 'isValidSecurityPatch(it)')
content = content.replace('name.matches(TEMPLATE_NAME_REGEX)', 'isValidTemplateName(name)')
content = content.replace('permissions.matches(PERMISSIONS_REGEX)', 'isValidPermissions(permissions)')
content = content.replace('keyboxFilename.matches(KEYBOX_FILENAME_REGEX)', 'isValidKeyboxFilename(keyboxFilename)')
content = content.replace('pkg.contains(WHITESPACE_FIND_REGEX)', 'pkg.any { it.isWhitespace() }')

with open("./service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt", "w") as f:
    f.write(content)
