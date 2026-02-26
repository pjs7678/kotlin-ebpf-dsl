package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * vfsstat — Count VFS operations per cgroup.
 *
 * Inspired by BCC's vfsstat. Counts VFS read, write, open, and fsync
 * calls per cgroup for file system activity monitoring.
 *
 * Programs:
 *   - kprobe/vfs_read   — count read operations
 *   - kprobe/vfs_write  — count write operations
 *   - kprobe/vfs_open   — count open operations
 *   - kprobe/vfs_fsync  — count fsync operations
 *
 * Map: vfs_stats (LRU_HASH, cgroup_key -> vfs_stats)
 *
 * Kernel: 4.7+ (cgroup_id helper), any architecture
 */

object VfsStats : BpfStruct("vfs_stats") {
    val reads by u64()
    val writes by u64()
    val opens by u64()
    val fsyncs by u64()
}

fun vfsstat() = ebpf("vfsstat") {
    license("GPL")
    targetKernel("5.3")

    val vfsStats by lruHashMap(CgroupKey, VfsStats, maxEntries = 10240)

    kprobe("vfs_read") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = vfsStats.lookup(key)
        ifNonNull(entry) { e ->
            e[VfsStats.reads].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(VfsStats) {
                it[VfsStats.reads] = literal(1u, BpfScalar.U64)
            }
            vfsStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("vfs_write") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = vfsStats.lookup(key)
        ifNonNull(entry) { e ->
            e[VfsStats.writes].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(VfsStats) {
                it[VfsStats.writes] = literal(1u, BpfScalar.U64)
            }
            vfsStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("vfs_open") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = vfsStats.lookup(key)
        ifNonNull(entry) { e ->
            e[VfsStats.opens].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(VfsStats) {
                it[VfsStats.opens] = literal(1u, BpfScalar.U64)
            }
            vfsStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("vfs_fsync") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = vfsStats.lookup(key)
        ifNonNull(entry) { e ->
            e[VfsStats.fsyncs].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(VfsStats) {
                it[VfsStats.fsyncs] = literal(1u, BpfScalar.U64)
            }
            vfsStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
