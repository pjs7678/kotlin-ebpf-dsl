package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * filelife — Track file creation and deletion per cgroup.
 *
 * Inspired by BCC's filelife. Counts file create and unlink (delete)
 * operations per cgroup. Useful for detecting pods with high filesystem
 * churn (e.g., temporary file abuse, log rotation storms).
 *
 * Programs:
 *   - kprobe/vfs_create  — file creation (mkdir, mknod, etc.)
 *   - kprobe/vfs_unlink  — file deletion (unlink, rmdir)
 *
 * Map: file_stats (LRU_HASH, cgroup_key -> file_stats)
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */

object FileStats : BpfStruct("file_stats") {
    val creates by u64()
    val deletes by u64()
}

fun filelife() = ebpf("filelife") {
    license("GPL")
    targetKernel("5.3")

    val fileStats by lruHashMap(CgroupKey, FileStats, maxEntries = 10240)

    kprobe("vfs_create") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = fileStats.lookup(key)
        ifNonNull(entry) { e ->
            e[FileStats.creates].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(FileStats) { it[FileStats.creates] = literal(1u, BpfScalar.U64) }
            fileStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("vfs_unlink") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = fileStats.lookup(key)
        ifNonNull(entry) { e ->
            e[FileStats.deletes].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(FileStats) { it[FileStats.deletes] = literal(1u, BpfScalar.U64) }
            fileStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
