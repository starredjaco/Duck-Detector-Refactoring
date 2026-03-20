package com.eltavine.duckdetector.features.nativeroot.data.native

data class CgroupProcessLeakNativePath(
    val path: String,
    val uid: Int,
    val accessible: Boolean,
    val pidCount: Int,
)

data class CgroupProcessLeakNativeEntry(
    val uidPath: String,
    val cgroupUid: Int,
    val pid: Int,
    val procUid: Int?,
    val comm: String,
    val cmdline: String,
)

data class CgroupProcessLeakNativeSnapshot(
    val available: Boolean = false,
    val pathCheckCount: Int = 0,
    val accessiblePathCount: Int = 0,
    val processCount: Int = 0,
    val procDeniedCount: Int = 0,
    val paths: List<CgroupProcessLeakNativePath> = emptyList(),
    val entries: List<CgroupProcessLeakNativeEntry> = emptyList(),
)

class CgroupProcessLeakNativeBridge {

    fun collectSnapshot(): CgroupProcessLeakNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot())
        }.getOrDefault(CgroupProcessLeakNativeSnapshot())
    }

    internal fun parse(raw: String): CgroupProcessLeakNativeSnapshot {
        if (raw.isBlank()) {
            return CgroupProcessLeakNativeSnapshot()
        }

        var available = false
        var pathCheckCount = 0
        var accessiblePathCount = 0
        var processCount = 0
        var procDeniedCount = 0
        val paths = mutableListOf<CgroupProcessLeakNativePath>()
        val entries = mutableListOf<CgroupProcessLeakNativeEntry>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("PATH=") -> {
                        val parts = line.removePrefix("PATH=").split('\t', limit = 4)
                        val uid = parts.getOrNull(1)?.toIntOrNull()
                        val accessible = parts.getOrNull(2)
                        val pidCount = parts.getOrNull(3)?.toIntOrNull()
                        if (parts.size == 4 && uid != null && accessible != null && pidCount != null) {
                            paths += CgroupProcessLeakNativePath(
                                path = parts[0].decodeValue(),
                                uid = uid,
                                accessible = accessible == "1",
                                pidCount = pidCount,
                            )
                        }
                    }

                    line.startsWith("ENTRY=") -> {
                        val parts = line.removePrefix("ENTRY=").split('\t', limit = 6)
                        val cgroupUid = parts.getOrNull(1)?.toIntOrNull()
                        val pid = parts.getOrNull(2)?.toIntOrNull()
                        val procUid = parts.getOrNull(3)?.toIntOrNull()
                        if (parts.size == 6 && cgroupUid != null && pid != null) {
                            entries += CgroupProcessLeakNativeEntry(
                                uidPath = parts[0].decodeValue(),
                                cgroupUid = cgroupUid,
                                pid = pid,
                                procUid = procUid?.takeIf { it >= 0 },
                                comm = parts[4].decodeValue(),
                                cmdline = parts[5].decodeValue(),
                            )
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        when (key) {
                            "AVAILABLE" -> available = value == "1"
                            "PATH_CHECKS" -> pathCheckCount = value.toIntOrNull() ?: pathCheckCount
                            "PATH_ACCESSIBLE" -> accessiblePathCount =
                                value.toIntOrNull() ?: accessiblePathCount

                            "PROCESS_COUNT" -> processCount = value.toIntOrNull() ?: processCount
                            "PROC_DENIED" -> procDeniedCount =
                                value.toIntOrNull() ?: procDeniedCount
                        }
                    }
                }
            }

        return CgroupProcessLeakNativeSnapshot(
            available = available,
            pathCheckCount = pathCheckCount,
            accessiblePathCount = accessiblePathCount,
            processCount = processCount,
            procDeniedCount = procDeniedCount,
            paths = paths,
            entries = entries,
        )
    }

    private fun String.decodeValue(): String {
        return buildString(length) {
            var index = 0
            while (index < this@decodeValue.length) {
                val current = this@decodeValue[index]
                if (current == '\\' && index + 1 < this@decodeValue.length) {
                    when (this@decodeValue[index + 1]) {
                        'n' -> {
                            append('\n')
                            index += 2
                            continue
                        }

                        'r' -> {
                            append('\r')
                            index += 2
                            continue
                        }

                        't' -> {
                            append('\t')
                            index += 2
                            continue
                        }

                        '0' -> {
                            append('\u0000')
                            index += 2
                            continue
                        }

                        '\\' -> {
                            append('\\')
                            index += 2
                            continue
                        }
                    }
                }
                append(current)
                index += 1
            }
        }
    }

    private external fun nativeCollectSnapshot(): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
