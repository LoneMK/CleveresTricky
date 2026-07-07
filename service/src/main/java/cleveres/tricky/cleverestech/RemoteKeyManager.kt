package cleveres.tricky.cleverestech

import android.hardware.security.rkp.RpcHardwareInfo
import java.util.Base64
import cleveres.tricky.cleverestech.keystore.XMLParser
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.File
import java.io.StringReader
import java.security.KeyPair
import java.security.SecureRandom

object RemoteKeyManager {
    private const val TAG = "RemoteKeyManager"

    data class RkpKey(
        val keyPair: KeyPair,
        val macedPublicKey: ByteArray?, // Pre-calculated COSE_Mac0
        val deviceInfo: ByteArray? // Pre-calculated CBOR DeviceInfo
    )

    @Volatile
    private var keys: List<RkpKey> = emptyList()
    @Volatile
    private var hardwareInfoOverride: RpcHardwareInfo? = null

    fun update(f: File?) = runCatching {
        if (f == null || !f.exists()) {
            Logger.i("$TAG: remote_keys.xml not found")
            keys = emptyList()
            hardwareInfoOverride = null
            return@runCatching
        }

        f.bufferedReader().use { reader ->
            val parser = XMLParser(reader)
            val loadedKeys = mutableListOf<RkpKey>()

            // Parse Keys
            val keysCount = parser.getChildCount("RemoteKeyProvisioning.Keys", "Key")
            for (i in 0 until keysCount) {
                try {
                    val keyPath = "RemoteKeyProvisioning.Keys.Key[$i]"
                    // Read PrivateKey
                    val keyText = parser.obtainPath("$keyPath.PrivateKey").get("text")
                    if (keyText != null) {
                        val keyPair = parsePemKeyPair(keyText)

                        // Read optional overrides
                        var macedKey: ByteArray? = null
                        try {
                            val macedText = parser.obtainPath("$keyPath.PublicKeyCose").get("text")
                            if (!macedText.isNullOrBlank()) {
                                macedKey = Base64.getDecoder().decode(macedText.trim())
                            }
                        } catch (e: Exception) { /* Ignore optional */ }

                        var deviceInfo: ByteArray? = null
                        try {
                            val infoText = parser.obtainPath("$keyPath.DeviceInfo").get("text")
                            if (!infoText.isNullOrBlank()) {
                                deviceInfo = Base64.getDecoder().decode(infoText.trim())
                            }
                        } catch (e: Exception) { /* Ignore optional */ }

                        if (keyPair != null) {
                            loadedKeys.add(RkpKey(keyPair, macedKey, deviceInfo))
                        }
                    }
                } catch (e: Exception) {
                    Logger.e("$TAG: Failed to parse key $i: ${e.message}")
                }
            }

            keys = loadedKeys
            Logger.i("$TAG: Loaded ${keys.size} remote keys")

            // Parse HardwareInfo override
            try {
                val hwPath = "RemoteKeyProvisioning.HardwareInfo"
                // Check version to confirm section exists
                val versionStr = parser.obtainPath("$hwPath.VersionNumber").get("text")
                if (versionStr != null) {
                    val info = RpcHardwareInfo()
                    info.versionNumber = versionStr.toInt()
                    info.rpcAuthorName = try { parser.obtainPath("$hwPath.RpcAuthorName").get("text") } catch(e:Exception) { "Google" }
                    info.supportedEekCurve = try { parser.obtainPath("$hwPath.SupportedEekCurve").get("text")?.toInt() ?: 2 } catch(e:Exception) { 2 }
                    info.uniqueId = "generic"
                    info.supportedNumKeysInCsr = try { parser.obtainPath("$hwPath.SupportedNumKeysInCsr").get("text")?.toInt() ?: 20 } catch(e:Exception) { 20 }
                    hardwareInfoOverride = info
                    Logger.i("$TAG: Loaded HardwareInfo override")
                }
            } catch (e: Exception) {
                // Ignore if missing
                hardwareInfoOverride = null
            }
        }
    }.onFailure {
        Logger.e("$TAG: Failed to update remote keys", it)
    }

    private fun parsePemKeyPair(pem: String): KeyPair? {
        return try {
            PEMParser(StringReader(pem.trim())).use { parser ->
                val obj = parser.readObject()
                if (obj is PEMKeyPair) {
                    JcaPEMKeyConverter().getKeyPair(obj)
                } else {
                    null
                }
            }
        } catch (e: Exception) {
            Logger.e("$TAG: Failed to parse PEM", e)
            null
        }
    }

    fun getKeyPair(): RkpKey? {
        val currentKeys = keys
        if (currentKeys.isEmpty()) return null
        // Random rotation for smart evasion (SecureRandom for unpredictability)
        return currentKeys[SecureRandom().nextInt(currentKeys.size)]
    }

    fun getHardwareInfo(): RpcHardwareInfo? {
        return hardwareInfoOverride
    }
}
