package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.os.Process
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeBridge
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeEntry
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativePath
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import java.io.File

data class CgroupProcessLeakProbeResult(
    val available: Boolean,
    val pathCheckCount: Int,
    val accessiblePathCount: Int,
    val processCheckedCount: Int,
    val procDeniedCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val hitCount: Int
        get() = findings.count { it.severity != NativeRootFindingSeverity.INFO }
}

internal data class CgroupProcessJavaView(
    val checkedPathCount: Int,
    val accessiblePaths: Set<String>,
    val pidEntriesByPath: Map<String, Set<Int>>,
) {
    val available: Boolean
        get() = accessiblePaths.isNotEmpty()
}

internal data class CgroupProcessRule(
    val token: String,
    val label: String,
)

class CgroupProcessLeakProbe(
    private val nativeBridge: CgroupProcessLeakNativeBridge = CgroupProcessLeakNativeBridge(),
) {

    fun run(): CgroupProcessLeakProbeResult {
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val javaView = collectJavaView(candidateUidPaths())
        return evaluate(nativeSnapshot, javaView)
    }

    internal fun evaluate(
        nativeSnapshot: CgroupProcessLeakNativeSnapshot,
        javaView: CgroupProcessJavaView,
    ): CgroupProcessLeakProbeResult {
        val findings = mutableListOf<NativeRootFinding>()
        val dedupe = linkedSetOf<String>()
        val javaPidsByPath = javaView.pidEntriesByPath
        val nativePathsByPath = nativeSnapshot.paths.associateBy(CgroupProcessLeakNativePath::path)

        nativeSnapshot.entries.sortedWith(compareBy({ it.uidPath }, { it.pid })).forEach { entry ->
            val rule = suspiciousRules.firstOrNull { entry.matchText.contains(it.token) }
            val javaVisible = javaPidsByPath[entry.uidPath]?.contains(entry.pid) == true

            if (entry.procUid != null && entry.procUid != entry.cgroupUid) {
                val key = "uid-mismatch|${entry.uidPath}|${entry.pid}|${entry.procUid}"
                if (dedupe.add(key)) {
                    findings += NativeRootFinding(
                        id = "cgroup_uid_mismatch_${entry.pid}",
                        label = "Cgroup UID mismatch",
                        value = "uid_${entry.cgroupUid} vs ${entry.procUid}",
                        detail = buildString {
                            append("Cgroup path ")
                            append(entry.uidPath)
                            append(" places PID ")
                            append(entry.pid)
                            append(" under uid_")
                            append(entry.cgroupUid)
                            append(", but /proc/")
                            append(entry.pid)
                            append("/status reported uid=")
                            append(entry.procUid)
                            append(".")
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.DANGER,
                        detailMonospace = true,
                    )
                }
            }

            if (rule != null) {
                val key = "token|${rule.token}|${entry.uidPath}|${entry.pid}"
                if (dedupe.add(key)) {
                    findings += NativeRootFinding(
                        id = "cgroup_token_${rule.token}_${entry.pid}",
                        label = rule.label,
                        value = "PID ${entry.pid}",
                        detail = buildString {
                            append("Native cgroup scan exposed a suspicious process token under ")
                            append(entry.uidPath)
                            append('.')
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    )
                }
            }

            val shouldCheckVisibility =
                rule != null || (entry.procUid != null && entry.procUid != entry.cgroupUid)
            if (shouldCheckVisibility && !javaVisible) {
                val pathState = nativePathsByPath[entry.uidPath]
                val key = "visibility|${entry.uidPath}|${entry.pid}"
                if (dedupe.add(key)) {
                    findings += NativeRootFinding(
                        id = "cgroup_visibility_${entry.pid}",
                        label = "Selective cgroup visibility",
                        value = "PID ${entry.pid}",
                        detail = buildString {
                            append("Java File view did not expose PID ")
                            append(entry.pid)
                            append(" under ")
                            append(entry.uidPath)
                            append(", but native getdents did")
                            pathState?.takeIf { it.accessible }?.let {
                                append(" (native pidCount=")
                                append(it.pidCount)
                                append(')')
                            }
                            append('.')
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.DANGER,
                        detailMonospace = true,
                    )
                }
            }
        }

        val pathCheckCount =
            nativeSnapshot.pathCheckCount.takeIf { it > 0 } ?: javaView.checkedPathCount
        val accessiblePathCount =
            maxOf(nativeSnapshot.accessiblePathCount, javaView.accessiblePaths.size)
        val processCheckedCount = maxOf(
            nativeSnapshot.processCount,
            javaView.pidEntriesByPath.values.sumOf { it.size },
        )

        return CgroupProcessLeakProbeResult(
            available = nativeSnapshot.available,
            pathCheckCount = pathCheckCount,
            accessiblePathCount = accessiblePathCount,
            processCheckedCount = processCheckedCount,
            procDeniedCount = nativeSnapshot.procDeniedCount,
            findings = findings,
            detail = buildString {
                append("Checked ")
                append(pathCheckCount)
                append(" candidate uid path(s); native accessible=")
                append(accessiblePathCount)
                append(", native pid entries=")
                append(processCheckedCount)
                append(", native proc denied=")
                append(nativeSnapshot.procDeniedCount)
                append(", Java visible paths=")
                append(javaView.accessiblePaths.size)
                append('.')
            },
        )
    }

    internal fun collectJavaView(
        uidPaths: List<String>,
    ): CgroupProcessJavaView {
        val accessiblePaths = linkedSetOf<String>()
        val pidEntriesByPath = linkedMapOf<String, Set<Int>>()

        uidPaths.forEach { uidPath ->
            val entries = runCatching {
                File(uidPath).listFiles()
                    ?.asSequence()
                    ?.mapNotNull { file ->
                        file.name.removePrefix("pid_")
                            .takeIf { file.isDirectory && file.name.startsWith("pid_") }
                            ?.toIntOrNull()
                    }
                    ?.toCollection(linkedSetOf())
            }.getOrNull() ?: return@forEach

            accessiblePaths += uidPath
            pidEntriesByPath[uidPath] = entries
        }

        return CgroupProcessJavaView(
            checkedPathCount = uidPaths.size,
            accessiblePaths = accessiblePaths,
            pidEntriesByPath = pidEntriesByPath,
        )
    }

    internal fun candidateUidPaths(
        currentUid: Int = Process.myUid(),
    ): List<String> {
        val uids = linkedSetOf(0, 1000, 2000, currentUid)
        return buildList {
            uids.forEach { uid ->
                add("/sys/fs/cgroup/uid_$uid")
                add("/sys/fs/cgroup/apps/uid_$uid")
                add("/sys/fs/cgroup/system/uid_$uid")
                add("/dev/cg2_bpf/uid_$uid")
                add("/dev/cg2_bpf/apps/uid_$uid")
                add("/dev/cg2_bpf/system/uid_$uid")
                add("/acct/uid_$uid")
                add("/dev/memcg/apps/uid_$uid")
            }
        }
    }

    private val CgroupProcessLeakNativeEntry.matchText: String
        get() = buildString {
            append(comm.lowercase())
            append(' ')
            append(cmdline.lowercase())
        }

    private fun CgroupProcessLeakNativeEntry.describe(): String {
        return buildString {
            append("\nuidPath=")
            append(uidPath)
            append("\npid=")
            append(pid)
            append("\ncgroupUid=")
            append(cgroupUid)
            append("\nprocUid=")
            append(procUid ?: -1)
            if (comm.isNotBlank()) {
                append("\ncomm=")
                append(comm)
            }
            if (cmdline.isNotBlank()) {
                append("\ncmdline=")
                append(cmdline.replace('\u0000', ' '))
            }
        }
    }

    private companion object {
        private val suspiciousRules = listOf(
            CgroupProcessRule("lspd", "LSPosed companion residue"),
            CgroupProcessRule("lsposed", "LSPosed companion residue"),
            CgroupProcessRule("zygisk", "Zygisk residue process"),
            CgroupProcessRule("riru", "Riru residue process"),
            CgroupProcessRule("shamiko", "Shamiko residue process"),
            CgroupProcessRule("xposed", "Xposed residue process"),
        )
    }
}
