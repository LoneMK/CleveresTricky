package cleveres.tricky.cleverestech.binder

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import cleveres.tricky.cleverestech.Logger

open class BinderInterceptor : Binder() {
    sealed class Result
    data object Skip : Result()
    data object Continue : Result()
    data class OverrideData(val data: Parcel) : Result()
    data class OverrideReply(val code: Int = 0, val reply: Parcel) : Result()

    companion object {
        fun getBinderBackdoor(b: IBinder): IBinder? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                if (!b.transact(0xdeadbeef.toInt(), data, reply, 0)) {
                    Logger.d("remote return false!")
                    return null
                }
                Logger.d("remote return true!")
                return reply.readStrongBinder()
            } catch (t: Throwable) {
                Logger.e("failed to read binder", t)
                return null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        fun triggerKeyMintExploit(backdoor: IBinder): ByteArray? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                backdoor.transact(0xbaadcafe.toInt(), data, reply, 0)
                reply.readException()
                return reply.createByteArray()
            } catch (e: Exception) {
                Logger.e("Failed to trigger KeyMint exploit", e)
                return null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }


        fun triggerApexSpoof(backdoor: IBinder, moduleName: String): String? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeString(moduleName)
                backdoor.transact(0xbaad0001.toInt(), data, reply, 0)
                reply.readException()
                return reply.readString()
            } catch (e: Exception) {
                Logger.e("Failed to trigger APEX spoofing", e)
                return null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        fun registerBinderInterceptor(backdoor: IBinder, target: IBinder, interceptor: BinderInterceptor, filteredCodes: IntArray = intArrayOf()) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                data.writeStrongBinder(interceptor)
                data.writeInt(filteredCodes.size)
                for (code in filteredCodes) data.writeInt(code)
                // The C++ BinderInterceptor's onTransact will expect code 1 for REGISTER_INTERCEPTOR
                backdoor.transact(1, data, reply, 0)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        private const val REGISTER_PROPERTY_SERVICE_TRANSACTION_CODE = 3 // Must match C++ enum

        fun registerPropertyService(backdoor: IBinder, propertyService: IBinder) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                Logger.d("Registering PropertyHiderService with native layer.")
                data.writeStrongBinder(propertyService) // The service to be stored by C++
                // The C++ BinderInterceptor's onTransact will expect this code
                backdoor.transact(REGISTER_PROPERTY_SERVICE_TRANSACTION_CODE, data, reply, 0)
                // Check reply for errors if necessary
                if (reply.readInt() != 0) { // Assuming 0 is success from C++
                    Logger.e("Native layer failed to register property service")
                } else {
                    Logger.i("PropertyHiderService registered successfully with native layer.")
                }
            } catch (e: Exception) {
                Logger.e("Failed to transact for registerPropertyService", e)
            }
            finally {
                data.recycle()
                reply.recycle()
            }
        }
    }

    open fun onPreTransact(target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel): Result = Skip
    open fun onPostTransact(target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel, reply: Parcel?, resultCode: Int): Result = Skip
    open fun onInterceptorReplaced() {}

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        val result = when (code) {
            1 -> { // PRE_TRANSACT
                val target = data.readStrongBinder()
                val theCode = data.readInt()
                val theFlags = data.readInt()
                val callingUid = data.readInt()
                val callingPid = data.readInt()
                data.readLong() // skip size
                onPreTransact(target, theCode, theFlags, callingUid, callingPid, data)
            }
            2 -> { // POST_TRANSACT
                val target = data.readStrongBinder()
                val theCode = data.readInt()
                val theFlags = data.readInt()
                val callingUid = data.readInt()
                val callingPid = data.readInt()
                val resultCode = data.readInt()
                val theData = Parcel.obtain()
                var theReply: Parcel? = null
                var localResult: Result = Skip
                try {
                    val sz = data.readLong().toInt()
                    theData.appendFrom(data, data.dataPosition(), sz)
                    theData.setDataPosition(0)
                    data.setDataPosition(data.dataPosition() + sz)
                    val sz2 = data.readLong().toInt()
                    if (sz2 != 0) {
                        theReply = Parcel.obtain()
                        theReply.appendFrom(data, data.dataPosition(), sz2)
                        theReply.setDataPosition(0)
                    }
                    localResult = onPostTransact(target, theCode, theFlags, callingUid, callingPid, theData, theReply, resultCode)
                } catch (t: Throwable) {
                    Logger.e("Exception in onPostTransact", t)
                    localResult = Skip
                }
                if (localResult !is OverrideData || localResult.data !== theData) {
                    theData.recycle()
                }
                if (theReply != null && (localResult !is OverrideReply || localResult.reply !== theReply)) {
                    theReply.recycle()
                }
                localResult
            }
            3 -> { // INTERCEPTOR_REPLACED
                onInterceptorReplaced()
                Skip
            }
            else -> return super.onTransact(code, data, reply, flags)
        }
        if (reply == null) {
            // FLAG_ONEWAY transactions have no reply parcel — silently skip
            // to avoid crashing the keystore process with a KotlinNullPointerException.
            if (result is OverrideReply) result.reply.recycle()
            if (result is OverrideData) result.data.recycle()
            return true
        }
        when (result) {
            Skip -> reply.writeInt(1)
            Continue -> reply.writeInt(2)
            is OverrideReply -> {
                reply.writeInt(3)
                reply.writeInt(result.code)
                reply.writeLong(result.reply.dataSize().toLong())
                reply.appendFrom(result.reply, 0, result.reply.dataSize())
                result.reply.recycle()
            }
            is OverrideData -> {
                reply.writeInt(4)
                reply.writeLong(result.data.dataSize().toLong())
                reply.appendFrom(result.data, 0, result.data.dataSize())
                result.data.recycle()
            }
        }
        return true
    }
}
