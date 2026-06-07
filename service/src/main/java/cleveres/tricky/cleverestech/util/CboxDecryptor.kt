package cleveres.tricky.cleverestech.util

import android.util.Base64
import org.json.JSONObject
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import cleveres.tricky.cleverestech.Logger

object CboxDecryptor {
    private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val ITERATION_COUNT = 250000
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = 16
    private const val IV_LENGTH = 12
    private const val CBOX_MAGIC = "CBOX"

    data class CboxPayload(
        val author: String,
        val xmlContent: String,
        val signatureBase64: String
    )

    fun decrypt(inputStream: InputStream, password: String): CboxPayload? {
        try {
            // 1. Read Header
            val magic = ByteArray(4)
            if (inputStream.read(magic) != 4 || String(magic, StandardCharsets.US_ASCII) != CBOX_MAGIC) {
                Logger.e("Invalid CBOX magic")
                return null
            }

            val versionBytes = ByteArray(4)
            if (inputStream.read(versionBytes) != 4) return null
            val version = java.nio.ByteBuffer.wrap(versionBytes).int
            if (version != 1) {
                Logger.e("Unsupported CBOX version: $version")
                return null
            }

            // 2. Read Salt & IV
            val salt = ByteArray(SALT_LENGTH)
            if (inputStream.read(salt) != SALT_LENGTH) return null
            val iv = ByteArray(IV_LENGTH)
            if (inputStream.read(iv) != IV_LENGTH) return null

            // 3. Read Ciphertext with size limit to prevent OOM
            val maxCiphertextSize = 50 * 1024 * 1024 // 50MB
            val ciphertextStream = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var totalRead = 0
            var n: Int
            while (inputStream.read(buf).also { n = it } != -1) {
                totalRead += n
                if (totalRead > maxCiphertextSize) {
                    Logger.e("CBOX ciphertext exceeds ${maxCiphertextSize / 1024 / 1024}MB limit")
                    return null
                }
                ciphertextStream.write(buf, 0, n)
            }
            val ciphertext = ciphertextStream.toByteArray()

            // 4. Derive Key
            val secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
            val passwordChars = password.toCharArray()
            val keyBytes: ByteArray
            try {
                val keySpec = PBEKeySpec(passwordChars, salt, ITERATION_COUNT, KEY_LENGTH)
                keyBytes = secretKeyFactory.generateSecret(keySpec).encoded
            } finally {
                passwordChars.fill('\u0000')
            }
            val secretKey = SecretKeySpec(keyBytes, "AES")

            // 5. Decrypt
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
            val plaintext = cipher.doFinal(ciphertext)

            // 6. Parse JSON
            val jsonStr = String(plaintext, StandardCharsets.UTF_8)
            val json = JSONObject(jsonStr)
            return CboxPayload(
                author = json.getString("author"),
                xmlContent = json.getString("xml_content"),
                signatureBase64 = json.getString("signature")
            )

        } catch (e: Exception) {
            Logger.e("Failed to decrypt CBOX: ${e.message}")
            return null
        }
    }

    fun verifySignature(payload: CboxPayload, publicKeyBase64: String): Boolean {
        return try {
            val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
            val keySpec = X509EncodedKeySpec(publicKeyBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(keySpec)

            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(publicKey)
            val data = (payload.author + payload.xmlContent).toByteArray(StandardCharsets.UTF_8)
            signature.update(data)

            val sigBytes = Base64.decode(payload.signatureBase64, Base64.DEFAULT)
            signature.verify(sigBytes)
        } catch (e: Exception) {
            Logger.e("Signature verification failed: ${e.message}")
            false
        }
    }
}
