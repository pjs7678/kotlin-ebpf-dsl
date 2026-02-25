package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ScalarMapTest {

    @Test
    fun `hashMap with scalar key and value generates correct C`() {
        val program = ebpf("scalar_map") {
            license("GPL")
            val tsMap by scalarHashMap(
                keyType = BpfScalar.U32,
                valueType = BpfScalar.U64,
                maxEntries = 10240,
                mapName = "wakeup_ts"
            )
            tracepoint("sched", "sched_wakeup") {
                val pid = declareVar("pid", literal(42u, BpfScalar.U32))
                val ts = declareVar("ts", ktimeGetNs())
                tsMap.update(pid, ts, flags = BPF_ANY)
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).contains("__type(key, __u32)")
        assertThat(c).contains("__type(value, __u64)")
        assertThat(c).contains("BPF_MAP_TYPE_HASH")
        assertThat(c).contains("bpf_map_update_elem(&wakeup_ts, &pid, &ts, 0)")
    }

    @Test
    fun `BPF flag constants have correct values`() {
        val program = ebpf("flags") {
            license("GPL")
            val m by scalarHashMap(BpfScalar.U32, BpfScalar.U64, 1024, mapName = "m")
            tracepoint("sched", "sched_switch") {
                val k = declareVar("k", literal(1u, BpfScalar.U32))
                val v = declareVar("v", literal(2u, BpfScalar.U64))
                m.update(k, v, flags = BPF_NOEXIST)
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).contains(", 1)")  // BPF_NOEXIST = 1
    }

    @Test
    fun `scalar LRU hash map generates correct C`() {
        val program = ebpf("scalar_lru") {
            license("GPL")
            val cache by scalarLruHashMap(BpfScalar.U64, BpfScalar.U64, 4096, mapName = "cache")
            tracepoint("sched", "sched_switch") {
                val key = declareVar("key", literal(1u, BpfScalar.U64))
                val entry = cache.lookup(key)
                ifNonNull(entry) { e ->
                    // use lookup result so it appears in generated C
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
        assertThat(c).contains("bpf_map_lookup_elem(&cache, &key)")
    }
}
