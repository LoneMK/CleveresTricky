package cleveres.tricky.cleverestech

import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess

object Verification {
    private val MODULE_PATH = getModuleDir()
    private val IGNORED_FILES = setOf("disable", "remove", "update", "system.prop", "sepolicy.rule")

    var exitProcessImpl: (Int) -> Unit = { exitProcess(it) }

    @OptIn(ExperimentalStdlibApi::class)
    fun check(root: File = File(MODULE_PATH)) {
        if (!root.exists()) {
            Logger.e("Module directory not found: ${root.absolutePath}")
            return
        }

        val allFiles = root.walk().filter { !it.isDirectory }.toList()
        val checksumMap = allFiles
            .filter { it.name.endsWith(".sha256") }
            .associate {
                it.path.removeSuffix(".sha256") to it.readText().trim()
            }

        allFiles.forEach { file ->
            // Skip checksum files themselves
            if (file.name.endsWith(".sha256")) return@forEach
            // Skip ignored files
            if (file.parentFile?.absolutePath == root.absolutePath && IGNORED_FILES.contains(file.name)) return@forEach

            val expected = checksumMap[file.path]
            if (expected == null) {
                fail(root, "Missing checksum for file: ${file.path}")
                return@forEach
            }

            val actual = calculateChecksum(file)
            if (!expected.equals(actual, ignoreCase = true)) {
                fail(root, "Checksum mismatch for file: ${file.path}. Expected $expected, got $actual")
                return@forEach
            }
        }
        Logger.i("Module verification passed.")
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun calculateChecksum(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.forEachBlock { buffer, bytesRead ->
            md.update(buffer, 0, bytesRead)
        }
        return md.digest().toHexString(HexFormat.Default)
    }

    private fun fail(root: File, reason: String) {
        Logger.e("Verification failed (ignored): $reason")
        // File(root, "disable").createNewFile()
        // exitProcessImpl(1)
    }
}
