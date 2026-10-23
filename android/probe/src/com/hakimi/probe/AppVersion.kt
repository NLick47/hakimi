package com.hakimi.probe

/**
 * Semver comparison for update checks.
 *
 * Local builds may carry a short versionName ("0.3" means "0.3.0"), so
 * missing components compare as zero. A version that cannot be parsed never
 * counts as newer: the worst case is a missed update prompt, never a bogus one.
 */
object AppVersion {
    fun isNewer(candidate: String, current: String): Boolean =
        compare(candidate, current) > 0

    fun compare(left: String, right: String): Int {
        val a = parse(left)
        val b = parse(right)
        if (a == null || b == null) return 0

        val size = maxOf(a.core.size, b.core.size)
        for (index in 0 until size) {
            val x = a.core.getOrElse(index) { 0L }
            val y = b.core.getOrElse(index) { 0L }
            if (x != y) return x.compareTo(y)
        }

        if (a.pre.isEmpty() && b.pre.isEmpty()) return 0
        if (a.pre.isEmpty()) return 1
        if (b.pre.isEmpty()) return -1

        val shared = minOf(a.pre.size, b.pre.size)
        for (index in 0 until shared) {
            val x = a.pre[index]
            val y = b.pre[index]
            val xn = x.toLongOrNull()
            val yn = y.toLongOrNull()
            val order = when {
                xn != null && yn != null -> xn.compareTo(yn)
                xn != null -> -1
                yn != null -> 1
                else -> x.compareTo(y)
            }
            if (order != 0) return order
        }
        return a.pre.size.compareTo(b.pre.size)
    }

    private class Parsed(val core: List<Long>, val pre: List<String>)

    private fun parse(value: String): Parsed? {
        var text = value.trim()
        if (text.startsWith("v")) text = text.substring(1)
        text = text.substringBefore('+').trim()
        if (text.isEmpty()) return null

        val coreText = text.substringBefore('-')
        val preText = if ('-' in text) text.substringAfter('-') else ""
        val core = coreText.split('.').map { part ->
            part.toLongOrNull() ?: return null
        }
        if (core.isEmpty()) return null
        val pre = if (preText.isEmpty()) emptyList() else preText.split('.')
        return Parsed(core, pre)
    }
}
