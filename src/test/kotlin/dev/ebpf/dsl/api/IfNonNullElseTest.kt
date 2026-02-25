package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class IfNonNullElseTest {

    object Key : BpfStruct("key") {
        val id by u64()
    }
    object Val : BpfStruct("val") {
        val count by u64()
    }

    @Test
    fun `ifNonNull with elseThen generates correct C`() {
        val program = ebpf("test_else") {
            license("GPL")
            val myMap by lruHashMap(Key, Val, maxEntries = 1024, mapName = "my_map")
            tracepoint("sched", "sched_switch") {
                val key = stackVar(Key) {
                    it[Key.id] = literal(1u, BpfScalar.U64)
                }
                val entry = myMap.lookup(key)
                ifNonNull(entry) { e ->
                    e[Val.count].atomicAdd(literal(1u, BpfScalar.U64))
                }.elseThen {
                    val newVal = stackVar(Val) {
                        it[Val.count] = literal(1u, BpfScalar.U64)
                    }
                    myMap.update(key, newVal, flags = 1) // BPF_NOEXIST
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        assertThat(c).contains("if (entry_")
        assertThat(c).contains("} else {")
        assertThat(c).contains("bpf_map_update_elem")
        assertThat(c).contains(", 1)")
    }

    @Test
    fun `ifNonNull without elseThen still works`() {
        val program = ebpf("test_no_else") {
            license("GPL")
            val myMap by lruHashMap(Key, Val, maxEntries = 1024, mapName = "my_map")
            tracepoint("sched", "sched_switch") {
                val key = stackVar(Key) {
                    it[Key.id] = literal(1u, BpfScalar.U64)
                }
                ifNonNull(myMap.lookup(key)) { e ->
                    e[Val.count].atomicAdd(literal(1u, BpfScalar.U64))
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).doesNotContain("} else {")
    }
}
