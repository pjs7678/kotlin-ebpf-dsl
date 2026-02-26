package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * cachestat — Track page cache statistics per cgroup.
 *
 * Inspired by BCC's cachestat. Counts page cache operations per cgroup:
 * accesses (hits), additions (misses that brought pages in), and dirtied pages.
 *
 * Programs:
 *   - kprobe/mark_page_accessed        — page cache access (hit)
 *   - kprobe/add_to_page_cache_lru     — page added to cache (miss)
 *   - kprobe/account_page_dirtied      — page dirtied
 *   - kprobe/mark_buffer_dirty         — buffer dirtied
 *
 * Map: cache_stats (LRU_HASH, cgroup_key -> cache_stats)
 *
 * Note: Function names are for kernels < 5.18. For 5.18+, the folio
 * equivalents (folio_mark_accessed, filemap_add_folio, folio_account_dirtied)
 * should be used instead.
 *
 * Kernel: 4.7+ (cgroup_id), < 5.18 (pre-folio API)
 */

object CacheStats : BpfStruct("cache_stats") {
    val accesses by u64()
    val additions by u64()
    val dirtied by u64()
    val bufDirtied by u64()
}

fun cachestat() = ebpf("cachestat") {
    license("GPL")
    targetKernel("5.3")

    val cacheStats by lruHashMap(CgroupKey, CacheStats, maxEntries = 10240)

    kprobe("mark_page_accessed") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.accesses].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.accesses] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("add_to_page_cache_lru") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.additions].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.additions] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("account_page_dirtied") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.dirtied].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.dirtied] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("mark_buffer_dirty") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.bufDirtied].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.bufDirtied] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
