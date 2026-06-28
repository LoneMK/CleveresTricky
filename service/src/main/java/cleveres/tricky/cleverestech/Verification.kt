package cleveres.tricky.cleverestech

import java.io.File
import java.security.MessageDigest

object Verification {
    private val MODULE_PATH = getModuleDir()
    private val IGNORED_FILES = setOf("disable", "remove", "update", "system.prop", "sepolicy.rule", "tampered", "web_port", "init.rc", "init.rc.disabled")

    @OptIn(ExperimentalStdlibApi::class)
    fun check(root: File = File(MODULE_PATH)): Boolean {
        if (!root.exists()) {
            Logger.e("Module directory not found: ${root.absolutePath}")
            return true // Allow dev mode when run outside Magisk
        }

        val allFiles = root.walk().filter { !it.isDirectory }.toList()
        val checksumMap = allFiles
            .filter { it.name.endsWith(".sha256") }
            .associate {
                it.path.removeSuffix(".sha256") to it.readText().trim()
            }

        var isTampered = false

        allFiles.forEach { file ->
            // Skip checksum files themselves
            if (file.name.endsWith(".sha256")) return@forEach
            // Skip ignored files
            if (file.parentFile?.absolutePath == root.absolutePath && IGNORED_FILES.contains(file.name)) return@forEach

            val expected = checksumMap[file.path]
            if (expected == null) {
                Logger.e("Verification failed: Missing checksum for file: ${file.path}")
                isTampered = true
                return@forEach
            }

            val actual = calculateChecksum(file)
            if (!expected.equals(actual, ignoreCase = true)) {
                Logger.e("Verification failed: Checksum mismatch for file: ${file.path}. Expected $expected, got $actual")
                isTampered = true
                return@forEach
            }
        }
        
        if (isTampered) {
            Logger.e("Module verification failed. Tampering detected.")
            return false
        }
        
        Logger.i("Module verification passed.")
        return true
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun calculateChecksum(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.forEachBlock { buffer, bytesRead ->
            md.update(buffer, 0, bytesRead)
        }
        return md.digest().toHexString(HexFormat.Default)
    }
}
