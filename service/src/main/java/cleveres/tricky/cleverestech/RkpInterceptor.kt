package cleveres.tricky.cleverestech

import android.hardware.security.rkp.DeviceInfo
import android.hardware.security.rkp.IRemotelyProvisionedComponent
import android.hardware.security.rkp.MacedPublicKey
import android.hardware.security.rkp.ProtectedData
import android.hardware.security.rkp.RpcHardwareInfo
import android.os.IBinder
import android.os.Parcel
import cleveres.tricky.cleverestech.binder.BinderInterceptor
import cleveres.tricky.cleverestech.keystore.CertHack
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

/**
 * Handles RKP (Remote Key Provisioning) interception.
 * This intercepts calls to IRemotelyProvisionedComponent and returns
 * spoofed responses so Play Integrity sees valid attestation.
 */
class RkpInterceptor(
    private val original: IRemotelyProvisionedComponent,
    private val securityLevel: Int
) : BinderInterceptor() {

    companion object {
        private val getHardwareInfoTransaction = 
            getTransactCode(IRemotelyProvisionedComponent.Stub::class.java, "getHardwareInfo")
        private val generateEcdsaP256KeyPairTransaction = 
            getTransactCode(IRemotelyProvisionedComponent.Stub::class.java, "generateEcdsaP256KeyPair")
        private val generateCertificateRequestTransaction = 
            getTransactCode(IRemotelyProvisionedComponent.Stub::class.java, "generateCertificateRequest")
        private val generateCertificateRequestV2Transaction = 
            getTransactCode(IRemotelyProvisionedComponent.Stub::class.java, "generateCertificateRequestV2")

        val INTERCEPTED_CODES = intArrayOf(
            getHardwareInfoTransaction,
            generateEcdsaP256KeyPairTransaction,
            generateCertificateRequestTransaction,
            generateCertificateRequestV2Transaction
        )
        
        // we cache generated keys so they can be reused in cert requests
        private val keyPairCache = KeyCache<Int, KeyPairInfo>(100)
        private val keyPairCounter = java.util.concurrent.atomic.AtomicInteger(0)
        
        data class KeyPairInfo(
            val keyPair: KeyPair,
            val macedPublicKey: ByteArray,
            val privateKeyHandle: ByteArray,
            val deviceInfo: ByteArray? = null
        )
    }

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (!Config.shouldBypassRkp()) {
            // MODE 1: Strong General Simulation Mode (Legacy Keybox Fallback)
            // Block all RKP calls by returning UNKNOWN_TRANSACTION (2147483646)
            Logger.i("RKP is blocked (Mode 1), forcing Legacy Keybox fallback for uid=$callingUid")
            val p = Parcel.obtain()
            return OverrideReply(2147483646, p)
        }
        
        // MODE 2: Advanced RKP Compatibility Mode (Spoofing)
        
        when (code) {
            getHardwareInfoTransaction -> {
                Logger.i("intercepting RKP getHardwareInfo for uid=$callingUid")
                return interceptGetHardwareInfo()
            }
            generateEcdsaP256KeyPairTransaction -> {
                Logger.i("intercepting RKP generateEcdsaP256KeyPair for uid=$callingUid")
                return interceptKeyPairGeneration(callingUid, data)
            }
            generateCertificateRequestTransaction -> {
                Logger.i("intercepting RKP generateCertificateRequest for uid=$callingUid")
                return interceptCertificateRequest(callingUid, data, false)
            }
            generateCertificateRequestV2Transaction -> {
                Logger.i("intercepting RKP generateCertificateRequestV2 for uid=$callingUid")
                return interceptCertificateRequest(callingUid, data, true)
            }
        }
        return Skip
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        // nothing to do after the transaction
        return Skip
    }

    // returns fake hardware info that matches what Google expects
    private fun interceptGetHardwareInfo(): Result {
        // Optimization: Replace runCatching with try-catch to avoid Result object allocation in hot path
        try {
            val override = RemoteKeyManager.getHardwareInfo()
            val info = override ?: RpcHardwareInfo().apply {
                versionNumber = 3 // android 14+ uses version 3
                rpcAuthorName = "Google"
                supportedEekCurve = 2 // P-256 curve
                uniqueId = Config.getBuildVar("DEVICE") ?: "generic"
                supportedNumKeysInCsr = 20
            }

            val p = Parcel.obtain()
            p.writeNoException()
            p.writeTypedObject(info, 0)
            return OverrideReply(0, p)
        } catch (it: Exception) {
            Logger.e("failed to intercept getHardwareInfo", it)
        }
        return Skip
    }

    // generates a new EC P-256 key pair and wraps it in COSE format
    private fun interceptKeyPairGeneration(uid: Int, data: Parcel): Result {
        // Optimization: Replace runCatching with try-catch to avoid Result object allocation in hot path
        try {
            data.enforceInterface(IRemotelyProvisionedComponent.DESCRIPTOR)
            val testMode = data.readInt() != 0
            
            val rkpKey = RemoteKeyManager.getKeyPair()
            val keyPair: KeyPair
            val macedKey: ByteArray
            val deviceInfo: ByteArray?

            if (rkpKey != null) {
                keyPair = rkpKey.keyPair
                macedKey = rkpKey.macedPublicKey ?: createMacedPublicKey(keyPair)
                deviceInfo = rkpKey.deviceInfo
                Logger.i("Using remote key for uid=$uid")
            } else {
                // create new P-256 key
                val keyPairGen = KeyPairGenerator.getInstance("EC")
                keyPairGen.initialize(ECGenParameterSpec("secp256r1"))
                keyPair = keyPairGen.generateKeyPair()
                macedKey = createMacedPublicKey(keyPair)
                deviceInfo = null
            }
            
            // store handle for later use in cert requests
            val handleIndex = keyPairCounter.getAndIncrement() and 0x7FFFFFFF
            val privateKeyHandle = ByteArray(32)
            privateKeyHandle[0] = (handleIndex shr 24).toByte()
            privateKeyHandle[1] = (handleIndex shr 16).toByte()
            privateKeyHandle[2] = (handleIndex shr 8).toByte()
            privateKeyHandle[3] = handleIndex.toByte()
            
            keyPairCache[handleIndex] = KeyPairInfo(keyPair, macedKey, privateKeyHandle, deviceInfo)
            
            Logger.i("generated RKP key pair handle=$handleIndex for uid=$uid")
            
            val p = Parcel.obtain()
            p.writeNoException()
            val mpk = MacedPublicKey(macedKey)
            p.writeTypedObject(mpk, 0)
            p.writeByteArray(privateKeyHandle)
            
            return OverrideReply(0, p)
        } catch (it: Exception) {
            Logger.e("failed to intercept key pair generation for uid=$uid", it)
        }
        return Skip
    }

    // handles both v1 and v2 cert request formats
    private fun interceptCertificateRequest(uid: Int, data: Parcel, isV2: Boolean): Result {
        // Optimization: Replace runCatching with try-catch to avoid Result object allocation in hot path
        try {
            data.enforceInterface(IRemotelyProvisionedComponent.DESCRIPTOR)
            
            val keysToSign: Array<MacedPublicKey>?
            val challenge: ByteArray?
            
            if (isV2) {
                keysToSign = data.createTypedArray(MacedPublicKey.CREATOR)
                challenge = data.createByteArray()
            } else {
                // v1 has extra params we need to skip
                val testMode = data.readInt() != 0
                keysToSign = data.createTypedArray(MacedPublicKey.CREATOR)
                val endpointCertChain = data.createByteArray()
                challenge = data.createByteArray()
            }
            
            val deviceInfoBytes = resolveDeviceInfo(keysToSign, uid)
            val response = createCertificateRequestResponse(keysToSign, challenge, isV2, deviceInfoBytes)
            
            Logger.i("generated RKP certificate request response for uid=$uid isV2=$isV2")
            
            val p = Parcel.obtain()
            p.writeNoException()
            
            if (isV2) {
                p.writeByteArray(response)
            } else {
                // v1 needs extra out params
                p.writeByteArray(response)
                val deviceInfo = DeviceInfo(deviceInfoBytes)
                p.writeTypedObject(deviceInfo, 0)
                val protectedData = ProtectedData(createProtectedDataNatively())
                p.writeTypedObject(protectedData, 0)
            }
            
            return OverrideReply(0, p)
        } catch (it: Exception) {
            Logger.e("failed to intercept certificate request for uid=$uid", it)
        }
        return Skip
    }

    private fun createMacedPublicKey(keyPair: KeyPair): ByteArray {
        val pubKey = keyPair.public.encoded
        // Obtain key from the "Authority" (Local Proxy)
        val hmacKey = cleveres.tricky.cleverestech.rkp.LocalRkpProxy.getMacKey()
        
        // Provision the key (wrap in COSE_Mac0) using the device's keystore logic (CertHack)
        val macedKey = CertHack.generateMacedPublicKey(keyPair, hmacKey) ?: pubKey
        
        // Validate with Authority/Proxy (Schema Check / Proof of Trust)
        if (cleveres.tricky.cleverestech.rkp.LocalRkpProxy.validateMacedPublicKey(macedKey)) {
             Logger.d("RkpInterceptor: MacedPublicKey validated by LocalRkpProxy")
        } else {
             Logger.e("RkpInterceptor: MacedPublicKey validation FAILED by LocalRkpProxy")
             // In a real scenario, we might return failure here, but for "bypass" we proceed
        }
        
        return macedKey
    }

    private fun resolveDeviceInfo(keysToSign: Array<MacedPublicKey>?, uid: Int): ByteArray {
        val cachedEntries = keyPairCache.snapshotValues()
        if (keysToSign != null) {
            for (k in keysToSign) {
                if (k.macedKey == null) continue
                val cached = cachedEntries.find {
                    java.util.Arrays.equals(it.macedPublicKey, k.macedKey)
                }
                if (cached?.deviceInfo != null) return cached.deviceInfo
            }
        }
        return createDeviceInfo(uid)
    }

    private fun createCertificateRequestResponse(
        keysToSign: Array<MacedPublicKey>?,
        challenge: ByteArray?,
        isV2: Boolean,
        deviceInfo: ByteArray
    ): ByteArray {
        return CertHack.createCertificateRequestResponse(
            keysToSign?.map { it.macedKey }?.filterNotNull() ?: emptyList(),
            challenge ?: ByteArray(0),
            deviceInfo
        ) ?: ByteArray(0)
    }

    private fun createDeviceInfo(uid: Int): ByteArray {
        val brand = Config.getBuildVar("BRAND", uid) ?: "google"
        val manufacturer = Config.getBuildVar("MANUFACTURER", uid) ?: "Google"
        val product = Config.getBuildVar("PRODUCT", uid) ?: "generic"
        val model = Config.getBuildVar("MODEL", uid) ?: "Pixel"
        val device = Config.getBuildVar("DEVICE", uid) ?: "generic"
        
        return CertHack.createDeviceInfoCbor(brand, manufacturer, product, model, device)
            ?: ByteArray(0)
    }

    private external fun createProtectedDataNatively(): ByteArray


}
