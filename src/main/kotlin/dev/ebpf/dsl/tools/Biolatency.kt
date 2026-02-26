package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * biolatency — Measure block I/O latency per cgroup.
 *
 * Inspired by BCC's biolatency. Records per-cgroup histograms of block I/O
 * request latency (time from issue to completion).
 *
 * Programs:
 *   - kprobe/blk_mq_start_request — record request start time and cgroup
 *   - kprobe/blk_mq_end_request   — compute latency and update histogram
 *
 * Maps:
 *   - req_info:     HASH (req_key -> req_info, request pointer -> timestamp + cgroup)
 *   - bio_latency:  LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *   - bio_count:    LRU_HASH (cgroup_key -> counter, total I/O count)
 *
 * Note: cgroup_id is captured at issue time (not completion), since completions
 * can happen on a different CPU/thread via interrupt context.
 *
 * Kernel: 5.8+ (BTF, cgroup_id, blk-mq), any architecture
 */

object ReqKey : BpfStruct("req_key") {
    val reqPtr by u64()
}

object ReqInfo : BpfStruct("req_info") {
    val startTs by u64()
    val cgroupId by u64()
}

fun biolatency() = ebpf("biolatency") {
    license("GPL")
    targetKernel("5.3")
    preamble(LOG2_PREAMBLE)

    val reqInfo by hashMap(ReqKey, ReqInfo, maxEntries = 10240)
    val bioLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val bioCount by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    // Record start time and cgroup when I/O request begins
    kprobe("blk_mq_start_request") {
        val rq = declareVar("rq", kprobeParam(1, "unsigned long"))
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val ts = declareVar("ts", ktimeGetNs())

        val key = stackVar(ReqKey) {
            it[ReqKey.reqPtr] = rq
        }
        val info = stackVar(ReqInfo) {
            it[ReqInfo.startTs] = ts
            it[ReqInfo.cgroupId] = cgroupId
        }
        reqInfo.update(key, info, flags = BPF_ANY)
        returnValue(literal(0, BpfScalar.S32))
    }

    // Compute latency when I/O request completes
    kprobe("blk_mq_end_request") {
        val rq = declareVar("rq", kprobeParam(1, "unsigned long"))
        val key = stackVar(ReqKey) {
            it[ReqKey.reqPtr] = rq
        }
        val info = reqInfo.lookup(key)
        ifNonNull(info) { e ->
            val deltaNs = declareVar("delta_ns", ktimeGetNs() - e[ReqInfo.startTs])

            // Update I/O count
            val ckey = stackVar(CgroupKey) {
                it[CgroupKey.cgroupId] = e[ReqInfo.cgroupId]
            }
            val cnt = bioCount.lookup(ckey)
            ifNonNull(cnt) { c ->
                c[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
            }.elseThen {
                val newCnt = stackVar(Counter) {
                    it[Counter.count] = literal(1u, BpfScalar.U64)
                }
                bioCount.update(ckey, newCnt, flags = BPF_NOEXIST)
            }

            // Update latency histogram
            val hkey = stackVar(HistKey) {
                it[HistKey.cgroupId] = e[ReqInfo.cgroupId]
            }
            val hval = bioLatency.lookup(hkey)
            ifNonNull(hval) { he ->
                val slot = declareVar("slot", histSlot(deltaNs, 27))
                he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.sumNs].atomicAdd(deltaNs)
            }.elseThen {
                val slot2 = declareVar("slot2", histSlot(deltaNs, 27))
                val newHval = stackVar(HistValue) {
                    it[HistValue.count] = literal(1u, BpfScalar.U64)
                    it[HistValue.sumNs] = deltaNs
                }
                declareVar("_arr_set", structArraySet(newHval, HistValue.slots, slot2, literal(1uL, BpfScalar.U64)))
                bioLatency.update(hkey, newHval, flags = BPF_NOEXIST)
            }
            reqInfo.delete(key)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
