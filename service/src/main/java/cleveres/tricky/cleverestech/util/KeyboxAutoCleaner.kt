package cleveres.tricky.cleverestech.util

import cleveres.tricky.cleverestech.Logger
import cleveres.tricky.cleverestech.WEB_UI_LOOPBACK_HOST
import cleveres.tricky.cleverestech.WEB_UI_PORT
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object KeyboxAutoCleaner {
    private fun isTokenValid(token: String): Boolean {
        if (token.isEmpty()) return false
        for (i in 0 until token.length) {
            val c = token[i]
            if (!(c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-')) {
                return false
            }
        }
        return true
    }

    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val configDir = File("/data/adb/cleverestricky")
    private val keyboxDir = File(configDir, "keyboxes")
    private val revokedDir = File(keyboxDir, "revoked")
    private val toggleFile = File(configDir, "auto_keybox_check")
    private val webPortFile = File(configDir, "web_port")

    fun start() {
        executor.scheduleAtFixedRate({
            runCheck()
        }, 1, 1440, TimeUnit.MINUTES) // Run 1 min after start, then every 24 hours
    }

    private fun runCheck() {
        if (!toggleFile.exists()) return

        Logger.i("AutoCleaner: Starting daily revocation check...")
        val results = KeyboxVerifier.verify(configDir)
        var revokedCount = 0

        if (!revokedDir.exists()) revokedDir.mkdirs()

        for (res in results) {
            if (res.status == KeyboxVerifier.Status.REVOKED || res.status == KeyboxVerifier.Status.INVALID) {
                Logger.i("AutoCleaner: Keybox ${res.filename} is ${res.status}. Moving to revoked.")
                val file = res.file
                val target = File(revokedDir, res.filename)
                if (file.exists()) {
                    try {
                        file.renameTo(target)
                        revokedCount++
                    } catch (e: Exception) {
                        Logger.e("AutoCleaner: Failed to move ${res.filename}", e)
                    }
                }
            }
        }

        if (revokedCount > 0) {
            cleveres.tricky.cleverestech.CboxManager.refresh()
            cleveres.tricky.cleverestech.Config.updateKeyBoxes()
            notifyUser(revokedCount)
        }
        Logger.i("AutoCleaner: Finished check. Revoked/Invalid files moved: $revokedCount")
    }

    private fun notifyUser(count: Int) {
        try {
            val url = readWebUiUrl()
            Logger.d("AutoCleaner: Posting notification for WebUI at $url")
            // Post a high-priority, actionable notification
            val cmd = arrayOf(
                "su", "-c", "cmd notification post -S bigtext -t CleveresTricky 'Keybox Revoked Alert' '$count keybox(es) were found to be revoked/invalid and have been disabled. Check WebUI!' -a 'android.intent.action.VIEW' -d '$url'"
            )
            val process = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val output = try {
                process.inputStream.bufferedReader().use { it.readText().trim() }
            } catch (_: Exception) { "" }
            val exitCode = process.waitFor()
            if (output.isNotBlank()) {
                Logger.d("AutoCleaner: notification output: $output")
            }
            if (exitCode != 0) {
                Logger.e("AutoCleaner: Failed to send notification (exit=$exitCode)")
            }
        } catch (e: Exception) {
            Logger.e("AutoCleaner: Failed to send notification", e)
        }
    }

    /**
     * Reads the `web_port` metadata file (`port|token`) and returns the tokenized WebUI URL.
     *
     * Falls back to the default loopback endpoint if the file is missing or malformed so the
     * notification still points at the local WebUI for debugging.
     */
    private fun readWebUiUrl(): String {
        return try {
            val raw = webPortFile.readText().trim()
            val pipeIdx = raw.indexOf('|')
            val portStr = if (pipeIdx != -1) raw.substring(0, pipeIdx) else raw
            val port = portStr.toIntOrNull()
            val token = if (pipeIdx != -1) raw.substring(pipeIdx + 1).trim() else ""
            if (port == null || port !in 1..65535 || token.isBlank() || !isTokenValid(token)) {
                Logger.e("AutoCleaner: Invalid web_port content '$raw'")
                "http://$WEB_UI_LOOPBACK_HOST:$WEB_UI_PORT"
            } else {
                "http://$WEB_UI_LOOPBACK_HOST:$port/?token=$token"
            }
        } catch (e: Exception) {
            Logger.e("AutoCleaner: Failed to read WebUI endpoint metadata", e)
            "http://$WEB_UI_LOOPBACK_HOST:$WEB_UI_PORT"
        }
    }
}
