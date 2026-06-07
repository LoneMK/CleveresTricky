package cleveres.tricky.cleverestech

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import cleveres.tricky.cleverestech.keystore.CertHack
import cleveres.tricky.cleverestech.util.CboxDecryptor
import cleveres.tricky.cleverestech.util.DeviceKeyManager
import cleveres.tricky.cleverestech.util.SecureFile
import cleveres.tricky.cleverestech.util.ZipProcessor

object ServerManager {
    data class ServerConfig(
        val id: String,
        val name: String,
        val url: String,
        var priority: Int,
        var enabled: Boolean,
        val authType: String,
        val authData: JSONObject,
        var autoRefresh: Boolean,
        var refreshIntervalHours: Int,
        var lastStatus: String = "OK",
        var lastChecked: Long = 0,
        var lastAuthor: String = "",
        // Encrypted fields (password, api key, etc) handled via authData
        // We can store a server-specific password for CBOX decryption
        var contentPassword: String? = null,
        var contentPublicKey: String? = null
    )

    private val serversList = CopyOnWriteArrayList<ServerConfig>()
    private val serversMap = ConcurrentHashMap<String, ServerConfig>()
    private val serverKeyboxes = ConcurrentHashMap<String, List<CertHack.KeyBox>>() // ServerID -> List<KeyBox>
    private val serverFile by lazy { File(Config.keyboxDirectory.parentFile, "servers.json") }

    fun initialize() {
        loadServers()
        // Try to load cached keyboxes if available?
        // Server keyboxes are usually transient or cached encrypted.
        // For simplicity, we re-fetch on boot if auto-refresh enabled, or load from a cache file.
        // To support offline boot, we should cache the *result* (decrypted keyboxes) encrypted with device key.
        loadCachedKeyboxes()
    }

    private fun loadServers() {
        if (!serverFile.exists()) return
        try {
            val content = serverFile.readText()
            val json = JSONArray(content)
            serversList.clear()
            serversMap.clear()
            for (i in 0 until json.length()) {
                val obj = json.getJSONObject(i)
                val s = parseServer(obj)
                serversList.add(s)
                serversMap[s.id] = s
            }
        } catch (e: Exception) {
            Logger.e("Failed to load servers", e)
        }
    }

    fun saveServers() {
        try {
            val json = JSONArray()
            serversList.forEach { server ->
                json.put(serializeServer(server))
            }
            SecureFile.writeText(serverFile, json.toString())
        } catch (e: Exception) {
            Logger.e("Failed to save servers", e)
        }
    }

    private fun parseServer(json: JSONObject): ServerConfig {
        return ServerConfig(
            id = json.getString("id"),
            name = json.getString("name"),
            url = json.getString("url"),
            priority = json.getInt("priority"),
            enabled = json.getBoolean("enabled"),
            authType = json.getString("authType"),
            authData = json.optJSONObject("authData") ?: JSONObject(),
            autoRefresh = json.getBoolean("autoRefresh"),
            refreshIntervalHours = json.getInt("refreshIntervalHours"),
            lastStatus = json.optString("lastStatus", "OK"),
            lastChecked = json.optLong("lastChecked", 0),
            lastAuthor = json.optString("lastAuthor", ""),
            contentPassword = json.optString("contentPassword").ifEmpty { null },
            contentPublicKey = json.optString("contentPublicKey").ifEmpty { null }
        )
    }

    private fun serializeServer(server: ServerConfig): JSONObject {
        val json = JSONObject()
        json.put("id", server.id)
        json.put("name", server.name)
        json.put("url", server.url)
        json.put("priority", server.priority)
        json.put("enabled", server.enabled)
        json.put("authType", server.authType)
        json.put("authData", server.authData)
        json.put("autoRefresh", server.autoRefresh)
        json.put("refreshIntervalHours", server.refreshIntervalHours)
        json.put("lastStatus", server.lastStatus)
        json.put("lastChecked", server.lastChecked)
        json.put("lastAuthor", server.lastAuthor)
        json.put("contentPassword", server.contentPassword ?: "")
        json.put("contentPublicKey", server.contentPublicKey ?: "")
        return json
    }

    fun getServers(): List<ServerConfig> = serversList.sortedBy { it.priority }

    fun addServer(server: ServerConfig) {
        serversList.add(server)
        serversMap[server.id] = server
        saveServers()
        fetchFromServer(server) // Initial fetch
    }

    fun removeServer(id: String) {
        serversList.removeIf { it.id == id }
        serversMap.remove(id)
        serverKeyboxes.remove(id)
        File(Config.keyboxDirectory.parentFile, "server_cache_${id}.enc").delete()
        saveServers()
        // Trigger update
        // We need a callback or Config listens to us?
        // Config calls getLoadedKeyboxes()
        // We should trigger Config.updateKeyBoxes via polling or callback?
        // ServerManager is static/object.
        // We can expose a listener.
    }

    fun updateServer(id: String, block: (ServerConfig) -> Unit) {
        val s = serversMap[id]
        if (s != null) {
            block(s)
            saveServers()
        }
    }

    private fun loadCachedKeyboxes() {
        serversList.forEach { server ->
            if (server.enabled) {
                val cacheFile = File(Config.keyboxDirectory.parentFile, "server_cache_${server.id}.enc")
                if (cacheFile.exists()) {
                    try {
                        val enc = cacheFile.readBytes()
                        val dec = DeviceKeyManager.decrypt(enc)
                        if (dec != null) {
                            val xml = String(dec, StandardCharsets.UTF_8)
                            val kbs = CertHack.parseKeyboxXml(StringReader(xml), "server_${server.name}")
                            if (kbs.isNotEmpty()) {
                                serverKeyboxes[server.id] = kbs
                                Logger.i("Loaded cached keyboxes for server: ${server.name}")
                            }
                        }
                    } catch (e: Exception) {
                        Logger.e("Failed to load server cache for ${server.name}", e)
                    }
                }
            }
        }
    }

    fun fetchFromServer(server: ServerConfig): Boolean {
        if (!server.enabled) return false

        try {
            server.lastChecked = System.currentTimeMillis()
            val url = URL(server.url)
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 15000
            conn.readTimeout = 30000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = true

            // Apply Auth
            when (server.authType) {
                "BEARER" -> {
                    val token = server.authData.optString("token")
                    // Decrypt token if needed (assuming DeviceKeyManager handles sensitive storage logic elsewhere,
                    // for now simple string)
                    if (token.isNotEmpty()) conn.setRequestProperty("Authorization", "Bearer $token")
                }
                "BASIC" -> {
                    val user = server.authData.optString("username")
                    val pass = server.authData.optString("password")
                    if (user.isNotEmpty() || pass.isNotEmpty()) {
                        val auth = Base64.encodeToString("$user:$pass".toByteArray(), Base64.NO_WRAP)
                        conn.setRequestProperty("Authorization", "Basic $auth")
                    }
                }
                "API_KEY" -> {
                    val key = server.authData.optString("key")
                    val header = server.authData.optString("headerName", "X-API-Key")
                    if (key.isNotEmpty()) conn.setRequestProperty(header, key)
                }
                "CUSTOM" -> {
                    val headers = server.authData.optJSONObject("headers")
                    headers?.keys()?.forEach { k ->
                        conn.setRequestProperty(k, headers.getString(k))
                    }
                }
                "TELEGRAM" -> {
                    // Telegram logic: User provides bot url + id + chat
                    // We assume authData has 'token' after verification in WebUI
                    val token = server.authData.optString("token")
                    if (token.isNotEmpty()) conn.setRequestProperty("Authorization", "Bearer $token")
                    // If not verified, fail
                }
            }

            if (conn.responseCode != 200) {
                server.lastStatus = "HTTP_${conn.responseCode}"
                saveServers()
                return false
            }

            // Cap response size to prevent OOM from malicious servers
            val maxResponseSize = 10 * 1024 * 1024 // 10MB
            val contentLength = conn.contentLength
            if (contentLength > maxResponseSize) {
                server.lastStatus = "RESPONSE_TOO_LARGE"
                saveServers()
                return false
            }
            val bytes = conn.inputStream.use { input ->
                val buffer = java.io.ByteArrayOutputStream(minOf(contentLength.coerceAtLeast(0), 65536))
                val chunk = ByteArray(8192)
                var totalRead = 0
                var n: Int
                while (input.read(chunk).also { n = it } != -1) {
                    totalRead += n
                    if (totalRead > maxResponseSize) {
                        throw SecurityException("Server response exceeds ${maxResponseSize / 1024 / 1024}MB limit")
                    }
                    buffer.write(chunk, 0, n)
                }
                buffer.toByteArray()
            }

            // Process Content
            val result = processContent(bytes, server)
            val keyboxes = result.first
            val xmlContent = result.second

            if (keyboxes.isNotEmpty()) {
                serverKeyboxes[server.id] = keyboxes
                server.lastStatus = "OK"
                val cert = keyboxes[0].certificates[0]
                if (cert is X509Certificate) {
                    server.lastAuthor = cert.subjectDN.name
                } else {
                    server.lastAuthor = "Unknown"
                }

                if (xmlContent != null) {
                    cacheXml(server.id, xmlContent)
                }

            } else {
                server.lastStatus = "INVALID_CONTENT"
                saveServers()
                return false
            }

            saveServers()
            return true
        } catch (e: Exception) {
            server.lastStatus = "NETWORK_ERROR"
            Logger.e("Server fetch failed: ${server.name}", e)
            saveServers()
            return false
        }
    }

    internal fun processContent(bytes: ByteArray, server: ServerConfig): Pair<List<CertHack.KeyBox>, String?> {
        val magic = if (bytes.size >= 4) String(bytes.copyOfRange(0, 4), StandardCharsets.US_ASCII) else ""

        if (magic == "CBOX") {
            // Direct CBOX
            val pwd = server.contentPassword ?: ""
            val stream = ByteArrayInputStream(bytes)
            val payload = CboxDecryptor.decrypt(stream, pwd)
            if (payload != null) {
                // Verify signature if key provided
                if (!server.contentPublicKey.isNullOrBlank()) {
                    if (!CboxDecryptor.verifySignature(payload, server.contentPublicKey!!)) {
                        Logger.e("Signature verification failed for server ${server.name}")
                    }
                }
                val kbs = CertHack.parseKeyboxXml(StringReader(payload.xmlContent), "server_${server.name}")
                if (kbs.isNotEmpty()) {
                    return Pair(kbs, payload.xmlContent)
                }
            }
        } else if (bytes.size > 4 && bytes[0] == 0x50.toByte() && bytes[1] == 0x4B.toByte()) {
            // ZIP
            val stream = ByteArrayInputStream(bytes)
            val pack = ZipProcessor.process(stream)
            if (pack != null) {
                val allKeys = ArrayList<CertHack.KeyBox>()
                val sb = StringBuilder()

                val pwd = pack.password ?: server.contentPassword ?: ""
                val pubKey = pack.publicKey ?: server.contentPublicKey

                pack.cboxFiles.forEach { (name, content) ->
                    val cboxStream = ByteArrayInputStream(content)
                    val payload = CboxDecryptor.decrypt(cboxStream, pwd)
                    if (payload != null) {
                         if (!pubKey.isNullOrBlank()) {
                             if (!CboxDecryptor.verifySignature(payload, pubKey)) {
                                 Logger.e("Signature verification failed for zip entry $name")
                             }
                         }
                         val kbs = CertHack.parseKeyboxXml(StringReader(payload.xmlContent), "server_${server.name}_$name")
                         allKeys.addAll(kbs)
                         sb.append(payload.xmlContent).append("\n")
                    }
                }

                if (allKeys.isNotEmpty()) {
                    return Pair(allKeys, sb.toString())
                }
            }
        } else {
            // Assume Plain XML
            val xml = String(bytes, StandardCharsets.UTF_8)
            if (xml.contains("AndroidAttestation")) {
                 val kbs = CertHack.parseKeyboxXml(StringReader(xml), "server_${server.name}")
                 if (kbs.isNotEmpty()) {
                     return Pair(kbs, xml)
                 }
            }
        }
        return Pair(emptyList(), null)
    }

    private fun cacheXml(serverId: String, xml: String) {
        try {
            val enc = DeviceKeyManager.encrypt(xml.toByteArray(StandardCharsets.UTF_8))
            if (enc != null) {
                val file = File(Config.keyboxDirectory.parentFile, "server_cache_$serverId.enc")
                SecureFile.writeBytes(file, enc)
            }
        } catch (e: Exception) {
            Logger.e("Failed to cache server content", e)
        }
    }

    fun getLoadedKeyboxes(): List<CertHack.KeyBox> {
        return serverKeyboxes.values.flatten()
    }

    fun refreshAll() {
        serversList.filter { it.enabled }.sortedBy { it.priority }.forEach {
            fetchFromServer(it)
        }
    }
}
