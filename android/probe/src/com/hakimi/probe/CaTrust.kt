package com.hakimi.probe

import android.util.Log
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Reads AndroidCAStore to tell whether the app CA is in the user or system store. */
object CaTrust {
    private const val TAG = "Hakimi"

    data class Trust(val user: Boolean, val system: Boolean) {
        val any: Boolean get() = user || system
    }

    fun trust(caPem: String?): Trust {
        val targetDer = der(caPem) ?: return Trust(false, false)
        return try {
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
            var user = false
            var system = false
            val aliases = store.aliases()
            while (aliases.hasMoreElements() && (!user || !system)) {
                val alias = aliases.nextElement()
                val isUser = alias.startsWith("user:")
                val isSystem = alias.startsWith("system:")
                if (!isUser && !isSystem) continue
                val candidate = store.getCertificate(alias) ?: continue
                if (!candidate.encoded.contentEquals(targetDer)) continue
                if (isUser) user = true else system = true
            }
            Trust(user, system)
        } catch (error: Throwable) {
            Log.w(TAG, "CA store probe failed: $error")
            Trust(false, false)
        }
    }

    fun isUserTrusted(caPem: String?): Boolean = trust(caPem).user

    fun isSystemTrusted(caPem: String?): Boolean = trust(caPem).system

    fun isTrusted(caPem: String?): Boolean = trust(caPem).any

    fun describe(caPem: String?): String {
        if (caPem.isNullOrEmpty()) return "CA not generated yet"
        val trust = trust(caPem)
        return "user=${trust.user} system=${trust.system}"
    }

    /** Parses the PEM into the DER bytes the platform installers expect. */
    fun der(caPem: String?): ByteArray? {
        if (caPem.isNullOrEmpty()) return null
        return runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(caPem.toByteArray(Charsets.UTF_8)))
                .encoded
        }.getOrNull()
    }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun shortSha256(bytes: ByteArray, length: Int = 8): String =
        sha256Hex(bytes).take(length)

    /** Compact fingerprint for narrow UI rows: first 12 bytes, colon separated. */
    fun displaySha256(value: String): String =
        if (value.length <= 24) value
        else value.chunked(2).take(12).joinToString(":") + "…"

    /** Dump every AndroidCAStore entry (alias, subject, SHA-256) for diagnostics. */
    fun listTrusted(): String = buildString {
        try {
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
            val digest = MessageDigest.getInstance("SHA-256")
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                val certificate = store.getCertificate(alias)
                if (certificate !is X509Certificate) {
                    append(alias).append(" | <not x509>\n")
                    continue
                }
                val hash = digest.digest(certificate.encoded)
                append(alias).append(" | ")
                append(certificate.subjectX500Principal.name).append(" | ")
                hash.forEach { append("%02x".format(it.toInt() and 0xff)) }
                append('\n')
            }
        } catch (error: Throwable) {
            append("error: ").append(error).append('\n')
        }
    }
}
