package com.hakimi.probe

import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.util.Log

/**
 * CA certificate files. The install path always targets one predictable file
 * in Downloads so the system certificate picker has a single candidate; old
 * auto-renamed copies created by this package are removed after a write.
 */
object CaStore {
    private const val TAG = "HakimiCa"
    const val MIME = "application/x-x509-ca-cert"
    const val INSTALL_NAME = "hakimi-ca.crt"

    private val OLD_NAME = Regex("""hakimi-ca \(\d+\)\.crt""")

    private data class Entry(val uri: Uri, val name: String, val owner: String?)

    /**
     * Writes [der] to Downloads, replacing a previous export by this package.
     * Returns the actual display name, which may carry a fingerprint suffix or
     * a MediaStore " (n)" suffix when a file we do not own occupies the fixed
     * name. [preferredName] lets a later export keep overwriting that file
     * instead of creating a new "(n)" copy every time.
     */
    fun saveToDownloads(
        resolver: ContentResolver,
        packageName: String,
        der: ByteArray,
        preferredName: String? = null,
    ): String {
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            "MediaStore.Downloads requires Android 10"
        }

        val candidates = LinkedHashSet<String>()
        candidates.add(INSTALL_NAME)
        if (!preferredName.isNullOrEmpty()) candidates.add(preferredName)

        for (name in candidates) {
            val existing = find(resolver, name) ?: continue
            val ours = existing.owner == null || existing.owner == packageName
            if (ours && overwrite(resolver, existing.uri, name, der)) {
                cleanup(resolver, packageName, existing.uri)
                return displayName(resolver, existing.uri).ifEmpty { name }
            }
            if (existing.owner == packageName) {
                runCatching { resolver.delete(existing.uri, null, null) }
                    .onFailure { Log.w(TAG, "deleting the old CA export failed", it) }
            }
        }

        // If the fixed name is still taken (another app's file, or an old file
        // this install can no longer see after clearing app data), use a
        // fingerprint suffix instead of letting MediaStore silently rename it.
        val name = if (find(resolver, INSTALL_NAME) != null) {
            "hakimi-ca-${CaTrust.shortSha256(der)}.crt"
        } else {
            INSTALL_NAME
        }

        val existing = find(resolver, name)
        if (existing != null &&
            (existing.owner == null || existing.owner == packageName) &&
            overwrite(resolver, existing.uri, name, der)
        ) {
            cleanup(resolver, packageName, existing.uri)
            return displayName(resolver, existing.uri).ifEmpty { name }
        }

        val uri = insert(resolver, name, der)
        cleanup(resolver, packageName, uri)
        return displayName(resolver, uri).ifEmpty { name }
    }

    /** Writes [der] to a SAF document chosen by the user. */
    fun writeDocument(resolver: ContentResolver, uri: Uri, der: ByteArray): Boolean {
        val wrote = try {
            resolver.openOutputStream(uri)?.use { it.write(der) } != null
        } catch (error: Throwable) {
            Log.w(TAG, "writing CA document failed", error)
            false
        }
        if (!wrote) return false
        // Read-back verification is best effort: a few providers grant write
        // access without a readable stream. The write itself already succeeded.
        val read = runCatching {
            resolver.openInputStream(uri)?.use { it.readBytes() }
        }.getOrNull()
        return read == null || read.contentEquals(der)
    }

    fun displayName(resolver: ContentResolver, uri: Uri): String = runCatching {
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) ?: "" else ""
        } ?: ""
    }.getOrDefault("")

    private fun find(resolver: ContentResolver, name: String): Entry? = runCatching {
        val collection = downloads()
        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.RELATIVE_PATH,
            MediaStore.MediaColumns.OWNER_PACKAGE_NAME,
        )
        resolver.query(
            collection,
            projection,
            "${MediaStore.MediaColumns.DISPLAY_NAME} = ?",
            arrayOf(name),
            null,
        )?.use { cursor ->
            val idColumn = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
            val nameColumn = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
            val pathColumn = cursor.getColumnIndex(MediaStore.MediaColumns.RELATIVE_PATH)
            val ownerColumn = cursor.getColumnIndex(MediaStore.MediaColumns.OWNER_PACKAGE_NAME)
            while (cursor.moveToNext()) {
                if (idColumn < 0) continue
                val path = if (pathColumn >= 0) cursor.getString(pathColumn) else null
                if (!isDownloadsRoot(path)) continue
                val id = cursor.getLong(idColumn)
                val actual = if (nameColumn >= 0) cursor.getString(nameColumn) ?: name else name
                val owner = if (ownerColumn >= 0) cursor.getString(ownerColumn) else null
                return@use Entry(ContentUris.withAppendedId(collection, id), actual, owner)
            }
            null
        }
    }.getOrNull()

    private fun overwrite(resolver: ContentResolver, uri: Uri, name: String, der: ByteArray): Boolean {
        return try {
            val stream = resolver.openOutputStream(uri, "wt")
            if (stream == null) {
                false
            } else {
                stream.use { it.write(der) }
                resolver.update(
                    uri,
                    ContentValues().apply {
                        put(MediaStore.MediaColumns.MIME_TYPE, MIME)
                        put(MediaStore.MediaColumns.DISPLAY_NAME, name)
                    },
                    null,
                    null,
                )
                verify(resolver, uri, der)
            }
        } catch (error: Throwable) {
            Log.w(TAG, "overwriting the CA export failed", error)
            false
        }
    }

    private fun insert(resolver: ContentResolver, name: String, der: ByteArray): Uri {
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, MIME)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/")
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri = resolver.insert(downloads(), values)
            ?: throw IllegalStateException("MediaStore insert returned null")
        try {
            resolver.openOutputStream(uri)?.use { it.write(der) }
                ?: throw IllegalStateException("cannot open $uri")
            resolver.update(
                uri,
                ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) },
                null,
                null,
            )
            if (!verify(resolver, uri, der)) {
                throw IllegalStateException("CA export verification failed")
            }
            return uri
        } catch (error: Throwable) {
            runCatching { resolver.delete(uri, null, null) }
                .onFailure { Log.w(TAG, "removing the failed CA export failed", it) }
            throw error
        }
    }

    private fun verify(resolver: ContentResolver, uri: Uri, expected: ByteArray): Boolean =
        runCatching {
            resolver.openInputStream(uri)?.use { it.readBytes() }?.contentEquals(expected) == true
        }.getOrDefault(false)

    /** Removes auto-renamed copies this package created in the Downloads root. */
    private fun cleanup(resolver: ContentResolver, packageName: String, keep: Uri) {
        runCatching {
            val collection = downloads()
            val projection = arrayOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.RELATIVE_PATH,
                MediaStore.MediaColumns.OWNER_PACKAGE_NAME,
            )
            resolver.query(
                collection,
                projection,
                "${MediaStore.MediaColumns.DISPLAY_NAME} LIKE ?",
                arrayOf("hakimi-ca%"),
                null,
            )?.use { cursor ->
                val idColumn = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
                val nameColumn = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                val pathColumn = cursor.getColumnIndex(MediaStore.MediaColumns.RELATIVE_PATH)
                val ownerColumn = cursor.getColumnIndex(MediaStore.MediaColumns.OWNER_PACKAGE_NAME)
                if (idColumn < 0 || nameColumn < 0 || ownerColumn < 0) return@use
                while (cursor.moveToNext()) {
                    val name = cursor.getString(nameColumn) ?: continue
                    if (name != INSTALL_NAME && !OLD_NAME.matches(name)) continue
                    if (!isDownloadsRoot(if (pathColumn >= 0) cursor.getString(pathColumn) else null)) {
                        continue
                    }
                    if (cursor.getString(ownerColumn) != packageName) continue
                    val uri = ContentUris.withAppendedId(collection, cursor.getLong(idColumn))
                    if (uri == keep) continue
                    runCatching { resolver.delete(uri, null, null) }
                        .onFailure { Log.w(TAG, "deleting the stale CA export failed", it) }
                }
            }
        }.onFailure { Log.w(TAG, "cleaning stale CA exports failed", it) }
    }

    private fun downloads(): Uri =
        MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)

    private fun isDownloadsRoot(path: String?): Boolean {
        if (path.isNullOrEmpty()) return true
        return path.trimEnd('/') == Environment.DIRECTORY_DOWNLOADS
    }
}
