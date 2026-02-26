package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * bitesize — Block I/O request size distribution per cgroup.
 *
 * Inspired by BCC's bitesize. Records per-cgroup histograms of block I/O
 * request sizes (in bytes). Useful for understanding I/O patterns — sequential
 * large reads vs random small writes — and tuning filesystem/block settings.
 *
 * Program:
 *   - kprobe/blk_mq_start_request — extract request size via __data_len
 *
 * Maps:
 *   - io_size: LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram of bytes)
 *
 * Kernel: 5.8+ (BTF, cgroup_id, blk-mq), any architecture
 */
fun bitesize() = ebpf("bitesize") {
    license("GPL")
    preamble(LOG2_PREAMBLE)

    val ioSize by lruHashMap(HistKey, HistValue, maxEntries = 10240)

    kprobe("blk_mq_start_request") {
        // Complex kprobe struct pointer + field access — no single IR node for this pattern
        @Suppress("DEPRECATION")
        val bytes = declareVar(
            "bytes",
            raw("(__u64)((struct request *)PT_REGS_PARM1(ctx))->__data_len", BpfScalar.U64)
        )
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        val hkey = stackVar(HistKey) { it[HistKey.cgroupId] = cgroupId }
        val hval = ioSize.lookup(hkey)
        ifNonNull(hval) { he ->
            val slot = declareVar("slot", histSlot(bytes, 27))
            he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.sumNs].atomicAdd(bytes)
        }.elseThen {
            val slot2 = declareVar("slot2", histSlot(bytes, 27))
            val newHval = stackVar(HistValue) {
                it[HistValue.count] = literal(1u, BpfScalar.U64)
                it[HistValue.sumNs] = bytes
            }
            declareVar("_arr_set", structArraySet(newHval, HistValue.slots, slot2, literal(1uL, BpfScalar.U64)))
            ioSize.update(hkey, newHval, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
