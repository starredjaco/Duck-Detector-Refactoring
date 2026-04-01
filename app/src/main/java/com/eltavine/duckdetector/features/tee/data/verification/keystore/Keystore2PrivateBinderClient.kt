package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.os.IBinder
import android.os.Parcel
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.security.SecureRandom

class Keystore2PrivateBinderClient {

    fun lookupBinder(): IBinder? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return null
        }
        ensureHiddenApiAccess()
        return runCatching {
            val serviceManager = loadClass("android.os.ServiceManager")
            val getService = serviceManager.getMethod("getService", String::class.java)
            getService.invoke(null, SERVICE_NAME) as? IBinder
        }.getOrNull()
    }

    fun buildGetKeyEntryRequest(alias: String): Keystore2BinderRequest {
        return Keystore2BinderRequest(
            interfaceDescriptor = INTERFACE_DESCRIPTOR,
            transactionCode = TRANSACTION_GET_KEY_ENTRY,
            alias = alias,
        ) { data ->
            data.writeInterfaceToken(INTERFACE_DESCRIPTOR)
            data.writeInt(1)
            data.writeInt(0)
            data.writeLong(-1L)
            data.writeString(alias)
            data.writeByteArray(null)
        }
    }

    fun executeRequest(
        binder: IBinder,
        request: Keystore2BinderRequest,
    ): BinderTransactionResult {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            request.writeTo(data)
            val success = binder.transact(request.transactionCode, data, reply, 0)
            val snapshot = captureReplySnapshot(reply)
            BinderTransactionResult(
                success = success,
                replySnapshot = snapshot,
                replyFailureReason = if (success) null else "Keystore2 transact() returned false for alias=${request.alias}",
            )
        } catch (throwable: Throwable) {
            BinderTransactionResult(
                success = false,
                throwable = throwable,
                replyFailureReason = throwable.message ?: "Keystore2 transact failed for alias=${request.alias}",
            )
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun transactGetKeyEntry(binder: IBinder, alias: String): BinderTransactionResult {
        return executeRequest(binder, buildGetKeyEntryRequest(alias))
    }

    fun openSession(useStrongBox: Boolean = false): Keystore2PrivateSessionResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy requires Android 12 or newer.",
            )
        }

        ensureHiddenApiAccess()
        val proxyInstalled = installPrivateBinderProxy()
        val binder = lookupBinder() ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 binder endpoint was not available.",
        )
        val service = getKeystoreService() ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 service interface was not available after installing the private binder proxy.",
        )
        val securityLevel = getSecurityLevel(
            service = service,
            level = if (useStrongBox) SECURITY_LEVEL_STRONGBOX else SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        ) ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 security level proxy was not available.",
        )

        val session = Keystore2PrivateSession(
            binder = binder,
            service = service,
            securityLevel = securityLevel,
            proxyInstalled = proxyInstalled,
            serviceProxyActive = Proxy.isProxyClass(service.javaClass),
            securityLevelProxyActive = Proxy.isProxyClass(securityLevel.javaClass),
        )
        return if (!session.serviceProxyActive || !session.securityLevelProxyActive) {
            Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy did not wrap both service and security-level interfaces.",
            )
        } else {
            Keystore2PrivateSessionResult(session = session)
        }
    }

    fun createKeyDescriptor(alias: String): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", 0)
        setField(descriptor, "nspace", -1L)
        setField(descriptor, "alias", alias)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun generateAttestationKey(securityLevel: Any, keyDescriptor: Any) {
        var lastFailure: Throwable? = null
        val parameterSets = listOf(
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 4),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 0),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x700001F7, true),
            ),
        )

        for (parameters in parameterSets) {
            try {
                invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
                return
            } catch (throwable: Throwable) {
                lastFailure = throwable
            }
        }

        throw lastFailure ?: IllegalStateException("Unable to provision PURPOSE_ATTEST_KEY test key.")
    }

    fun generateSigningKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        attest: Boolean,
    ) {
        val parameters = buildList {
            add(createKeyParameter(0x10000002, 3))
            add(createKeyParameter(0x30000003, 256))
            add(createKeyParameter(0x1000000A, 1))
            add(createKeyParameter(0x20000001, 2))
            add(createKeyParameter(0x20000005, 4))
            add(createKeyParameter(0x700001F7, true))
            if (attest) {
                add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
            }
        }
        invokeGenerateKey(securityLevel, keyDescriptor, attestationKeyDescriptor, parameters)
    }

    fun getKeyEntry(service: Any, keyDescriptor: Any) {
        service.javaClass
            .getMethod("getKeyEntry", keyDescriptor.javaClass)
            .invoke(service, keyDescriptor)
    }

    fun deleteKey(service: Any, keyDescriptor: Any) {
        runCatching {
            service.javaClass
                .getMethod("deleteKey", keyDescriptor.javaClass)
                .invoke(service, keyDescriptor)
        }
    }

    fun createTimingAliases(prefix: String = DEFAULT_ALIAS_PREFIX): TimingKeyAliases {
        val suffix = System.nanoTime()
        return TimingKeyAliases(
            aliasPrefix = prefix,
            attestedAlias = "${prefix}_Attested_$suffix",
            nonAttestedAlias = "${prefix}_NonAttested_$suffix",
            attestKeyAlias = "${prefix}_AttestKey_$suffix",
        )
    }

    private fun invokeGenerateKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ) {
        val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
        val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
        parameters.forEachIndexed { index, value ->
            java.lang.reflect.Array.set(array, index, value)
        }
        val generateKeyMethod = securityLevel.javaClass.methods.firstOrNull {
            it.name == "generateKey" && it.parameterTypes.size == 5
        } ?: throw NoSuchMethodException("Unable to find hidden generateKey signature on ${securityLevel.javaClass.name}")
        generateKeyMethod.isAccessible = true
        generateKeyMethod.invoke(
            securityLevel,
            keyDescriptor,
            attestationKeyDescriptor,
            array,
            0,
            ByteArray(0),
        )
    }

    private fun createKeyParameter(tag: Int, value: Any): Any {
        val parameterClass = loadClass(CLASS_KEY_PARAMETER)
        val parameter = parameterClass.getDeclaredConstructor().newInstance()
        setField(parameter, "tag", tag)

        val valueClass = loadClass(CLASS_KEY_PARAMETER_VALUE)
        val valueObject = valueClass.getDeclaredConstructor().newInstance()
        val setterName = setterNameForTag(tag)
        val setter = valueClass.declaredMethods.firstOrNull {
            it.name == setterName && it.parameterTypes.size == 1
        } ?: throw NoSuchMethodException("Unable to find $setterName on ${valueClass.name}")
        setter.isAccessible = true
        setter.invoke(valueObject, value)
        setField(parameter, "value", valueObject)
        return parameter
    }

    private fun setterNameForTag(tag: Int): String {
        return when (tag and 0xf0000000.toInt()) {
            0x10000000, 0x20000000 -> when (tag and 0x0fffffff) {
                1 -> "setKeyPurpose"
                2 -> "setAlgorithm"
                5 -> "setDigest"
                10 -> "setEcCurve"
                else -> "setInteger"
            }
            0x30000000, 0x40000000 -> "setInteger"
            0x70000000 -> "setBoolValue"
            0x80000000.toInt(), 0x90000000.toInt() -> "setBlob"
            else -> "setInteger"
        }
    }

    private fun ensureHiddenApiAccess() {
        runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
    }

    private fun getKeystoreService(): Any? {
        return runCatching {
            val binder = lookupBinder() ?: return null
            val stubClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub")
            val asInterface = stubClass.getMethod("asInterface", IBinder::class.java)
            asInterface.invoke(null, binder)
        }.getOrNull()
    }

    private fun getSecurityLevel(service: Any, level: Int): Any? {
        return runCatching {
            val method = service.javaClass.methods.firstOrNull {
                it.name == "getSecurityLevel" && it.parameterTypes.size == 1
            } ?: throw NoSuchMethodException("Unable to find hidden getSecurityLevel(int) on ${service.javaClass.name}")
            method.isAccessible = true
            method.invoke(service, level)
        }.getOrNull()
    }

    private fun installPrivateBinderProxy(): Boolean {
        return runCatching {
            val serviceManager = loadClass("android.os.ServiceManager")
            val cacheField = serviceManager.getDeclaredField("sCache")
            cacheField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val cache = cacheField.get(null) as? MutableMap<String, IBinder>
                ?: return false
            cache.remove(SERVICE_NAME)
            val getService = serviceManager.getDeclaredMethod("getService", String::class.java)
            val rawBinder = getService.invoke(null, SERVICE_NAME) as? IBinder ?: return false
            cache[SERVICE_NAME] = createKeystoreServiceBinderProxy(rawBinder)
            true
        }.getOrDefault(false)
    }

    private fun createKeystoreServiceBinderProxy(rawBinder: IBinder): IBinder {
        val serviceInterface = loadClass(CLASS_IKEYSTORE_SERVICE)
        val serviceProxyClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub\$Proxy")
        val constructor = serviceProxyClass.getDeclaredConstructor(IBinder::class.java)
        constructor.isAccessible = true
        val stubProxy = constructor.newInstance(rawBinder)

        val serviceProxy = Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(serviceInterface),
        ) { _, method, args ->
            invokeProxyMethod(stubProxy, method, args) { result ->
                if (method.name == "getSecurityLevel" && result != null) {
                    createSecurityLevelProxy(result)
                } else {
                    result
                }
            }
        }

        return Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(IBinder::class.java),
        ) { _, method, args ->
            when (method.name) {
                "queryLocalInterface" -> serviceProxy
                "transact" -> rawBinder.transact(
                    args[0] as Int,
                    args[1] as Parcel,
                    args[2] as? Parcel,
                    args[3] as Int,
                )
                else -> invokeProxyMethod(rawBinder, method, args)
            }
        } as IBinder
    }

    private fun createSecurityLevelProxy(realSecurityLevel: Any): Any {
        return runCatching {
            val securityLevelInterface = loadClass(CLASS_IKEYSTORE_SECURITY_LEVEL)
            val securityLevelProxyClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub\$Proxy")
            val asBinderMethod = realSecurityLevel.javaClass.getMethod("asBinder")
            val rawBinder = asBinderMethod.invoke(realSecurityLevel) as IBinder

            val binderProxy = Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                arrayOf(IBinder::class.java),
            ) { _, method, args ->
                when (method.name) {
                    "queryLocalInterface" -> null
                    "transact" -> rawBinder.transact(
                        args[0] as Int,
                        args[1] as Parcel,
                        args[2] as? Parcel,
                        args[3] as Int,
                    )
                    else -> invokeProxyMethod(rawBinder, method, args)
                }
            } as IBinder

            val constructor = securityLevelProxyClass.getDeclaredConstructor(IBinder::class.java)
            constructor.isAccessible = true
            val stubProxy = constructor.newInstance(binderProxy)
            Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                arrayOf(securityLevelInterface),
            ) { _, method, args ->
                if (method.name == "asBinder") {
                    binderProxy
                } else {
                    invokeProxyMethod(stubProxy, method, args)
                }
            }
        }.getOrElse { realSecurityLevel }
    }

    private fun invokeProxyMethod(
        target: Any,
        method: Method,
        args: Array<out Any?>?,
        mapper: ((Any?) -> Any?)? = null,
    ): Any? {
        return try {
            val result = method.invoke(target, *(args ?: emptyArray()))
            mapper?.invoke(result) ?: result
        } catch (throwable: InvocationTargetException) {
            throw throwable.cause ?: throwable
        }
    }

    private fun captureReplySnapshot(reply: Parcel): Keystore2ReplySnapshot? {
        val rawBytes = runCatching { reply.marshall() }.getOrDefault(ByteArray(0))
        if (rawBytes.isEmpty() && reply.dataSize() == 0) {
            return null
        }
        reply.setDataPosition(0)
        val exceptionCode = if (reply.dataSize() >= 4) reply.readInt() else null
        val secondWord = if (reply.dataSize() >= 8) reply.readInt() else null
        val trailingInts = buildList {
            while (reply.dataPosition() + 4 <= reply.dataSize() && size < 4) {
                add(reply.readInt())
            }
        }
        reply.setDataPosition(0)
        return Keystore2ReplySnapshot(
            rawPrefix = rawBytes
                .take(MAX_REPLY_PREFIX_BYTES)
                .joinToString(" ") { "%02X".format(it.toInt() and 0xFF) },
            exceptionCode = exceptionCode,
            secondWord = secondWord,
            trailingInts = trailingInts,
            dataSize = rawBytes.size,
        )
    }

    private fun setField(target: Any, name: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        field.set(target, value)
    }

    private fun loadClass(className: String): Class<*> {
        return try {
            Class.forName(className)
        } catch (primary: ClassNotFoundException) {
            try {
                ClassLoader.getSystemClassLoader().loadClass(className)
            } catch (secondary: ClassNotFoundException) {
                try {
                    HiddenApiBypass.invoke(Class::class.java, null, "forName", className) as Class<*>
                } catch (throwable: Throwable) {
                    throw ClassNotFoundException("Unable to load hidden class $className", throwable)
                }
            }
        }
    }

    companion object {
        const val SERVICE_NAME = "android.system.keystore2.IKeystoreService/default"
        const val INTERFACE_DESCRIPTOR = "android.system.keystore2.IKeystoreService"
        const val TRANSACTION_GET_KEY_ENTRY = 2
        const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val SECURITY_LEVEL_STRONGBOX = 2
        const val DEFAULT_ALIAS_PREFIX = "Budin_Key_DuckTiming"

        private const val CLASS_IKEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService"
        private const val CLASS_IKEYSTORE_SECURITY_LEVEL = "android.system.keystore2.IKeystoreSecurityLevel"
        private const val CLASS_KEY_DESCRIPTOR = "android.system.keystore2.KeyDescriptor"
        private const val CLASS_KEY_PARAMETER = "android.hardware.security.keymint.KeyParameter"
        private const val CLASS_KEY_PARAMETER_VALUE = "android.hardware.security.keymint.KeyParameterValue"
        private const val MAX_REPLY_PREFIX_BYTES = 32
    }
}

data class Keystore2BinderRequest(
    val interfaceDescriptor: String,
    val transactionCode: Int,
    val alias: String,
    val writeTo: (Parcel) -> Unit,
)

data class Keystore2ReplySnapshot(
    val rawPrefix: String? = null,
    val exceptionCode: Int? = null,
    val secondWord: Int? = null,
    val trailingInts: List<Int> = emptyList(),
    val dataSize: Int = 0,
)

data class BinderTransactionResult(
    val success: Boolean,
    val replySnapshot: Keystore2ReplySnapshot? = null,
    val replyFailureReason: String? = null,
    val throwable: Throwable? = null,
)

data class Keystore2PrivateSessionResult(
    val session: Keystore2PrivateSession? = null,
    val failureReason: String? = null,
)

data class Keystore2PrivateSession(
    val binder: IBinder,
    val service: Any,
    val securityLevel: Any,
    val proxyInstalled: Boolean,
    val serviceProxyActive: Boolean,
    val securityLevelProxyActive: Boolean,
)

data class TimingKeyAliases(
    val aliasPrefix: String,
    val attestedAlias: String,
    val nonAttestedAlias: String,
    val attestKeyAlias: String,
)
