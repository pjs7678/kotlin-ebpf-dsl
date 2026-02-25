package dev.ebpf.dsl.tools

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// Shared struct definitions used by multiple BCC-style tools

object CgroupKey : BpfStruct("cgroup_key") {
    val cgroupId by u64()
}

object Counter : BpfStruct("counter") {
    val count by u64()
}

object HistKey : BpfStruct("hist_key") {
    val cgroupId by u64()
}

object HistValue : BpfStruct("hist_value") {
    val slots by array(BpfScalar.U64, 27)
    val count by u64()
    val sumNs by u64()
}

/** C preamble with log2l helper for histogram bucketing. */
val LOG2_PREAMBLE = """
#define MAX_ENTRIES 10240
#define MAX_SLOTS 27

static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}
""".trimIndent()
