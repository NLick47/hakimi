package com.hakimi.probe

import android.util.Log
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Reads AndroidCAStore to tell whether the app CA is in the user or system store. */
object CaTrust {
    private const val TAG = "Hakimi"

    fun isUserTrusted(caPem: String?): Boolean = contains(caPem, "user:")

    fun isSystemTrusted(caPem: String?): Boolean = contains(caPem, "system:")

    fun describe(caPem: String?): String {
        if (caPem.isNullOrEmpty()) return "CA not generated yet"
        return "user=${isUserTrusted(caPem)} system=${isSystemTrusted(caPem)}"
    }

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

    private fun contains(caPem: String?, prefix: String): Boolean {
        if (caPem.isNullOrEmpty()) return false
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            val target = factory.generateCertificate(
                ByteArrayInputStream(caPem.toByteArray(Charsets.UTF_8))
            ) as X509Certificate
            val targetDer = target.encoded

            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (!alias.startsWith(prefix)) continue
                val candidate: Certificate? = store.getCertificate(alias)
                if (candidate != null && candidate.encoded.contentEquals(targetDer)) {
                    return true
                }
            }
            false
        } catch (error: Throwable) {
            Log.w(TAG, "CA store probe failed: $error")
            false
        }
    }
}
