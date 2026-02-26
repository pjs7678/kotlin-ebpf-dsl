package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * slabtop — Track slab/kmalloc allocation counts per cgroup.
 *
 * Inspired by BCC's slabtop/memleak. Counts kernel memory allocation and
 * free events per cgroup via kmalloc/kfree. Useful for identifying pods
 * that cause excessive kernel memory allocation pressure.
 *
 * Programs:
 *   - kprobe/kmem_cache_alloc — slab cache allocation
 *   - kprobe/kmem_cache_free  — slab cache free
 *
 * Map: slab_stats (PERCPU_HASH, cgroup_key -> slab_stats)
 *
 * Uses PERCPU_HASH to avoid cross-CPU cache-line contention on this
 * high-frequency path (fires on every kernel slab allocation/free).
 * Userspace must sum per-CPU values at read time.
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */

object SlabStats : BpfStruct("slab_stats") {
    val allocs by u64()
    val frees by u64()
}

fun slabtop() = ebpf("slabtop") {
    license("GPL")

    val slabStats by percpuHashMap(CgroupKey, SlabStats, maxEntries = 10240)

    kprobe("kmem_cache_alloc") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = slabStats.lookup(key)
        ifNonNull(entry) { e ->
            e[SlabStats.allocs].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(SlabStats) { it[SlabStats.allocs] = literal(1u, BpfScalar.U64) }
            slabStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("kmem_cache_free") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = slabStats.lookup(key)
        ifNonNull(entry) { e ->
            e[SlabStats.frees].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(SlabStats) { it[SlabStats.frees] = literal(1u, BpfScalar.U64) }
            slabStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
