package dev.ebpf.dsl.validation

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SemanticAnalyzerTest {

    // 480 bytes (60 * 8 bytes)
    object Big : BpfStruct("big") {
        val data by array(BpfScalar.U64, 60)
    }

    object Small : BpfStruct("small") {
        val id by u64()
    }

    object SmallVal : BpfStruct("sv") {
        val count by u64()
    }

    @Test
    fun `stack overflow detected`() {
        // Big is 480 bytes; two would be 960 > 512
        val model = ebpf("overflow") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val x = stackVar(Big) {}
                val y = stackVar(Big) {}
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.errors).anyMatch { it.code == "stack-overflow" }
    }

    @Test
    fun `unreachable code after return`() {
        val model = ebpf("unreach") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
                val x = declareVar("x", ktimeGetNs()) // unreachable
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.errors).anyMatch { it.code == "unreachable-code" }
    }

    @Test
    fun `division by variable warns`() {
        val model = ebpf("divwarn") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = literal(100u, BpfScalar.U64)
                val b = ktimeGetNs()
                val c = declareVar("c", a / b) // variable divisor
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.warnings).anyMatch { it.code == "unchecked-divisor" }
    }

    @Test
    fun `division by literal does not warn`() {
        val model = ebpf("divok") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = literal(100u, BpfScalar.U64)
                val c = declareVar("c", a / literal(10u, BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.warnings).noneMatch { it.code == "unchecked-divisor" }
    }

    @Test
    fun `hash map with high max entries warns`() {
        val model = ebpf("warn") {
            license("GPL")
            val m by hashMap(Small, SmallVal, maxEntries = 100000)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.warnings).anyMatch { it.code == "prefer-lru-hash" }
    }

    @Test
    fun `lru hash does not warn`() {
        val model = ebpf("ok") {
            license("GPL")
            val m by lruHashMap(Small, SmallVal, maxEntries = 100000)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.warnings).noneMatch { it.code == "prefer-lru-hash" }
    }

    @Test
    fun `valid program passes`() {
        val model = ebpf("ok") {
            license("GPL")
            val m by lruHashMap(Small, SmallVal, maxEntries = 1024)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `stack usage within limit passes`() {
        val model = ebpf("ok") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val x = stackVar(Small) {} // 8 bytes, well within 512
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.errors).noneMatch { it.code == "stack-overflow" }
    }

    @Test
    fun `no unreachable code when return is last`() {
        val model = ebpf("ok") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val t = declareVar("t", ktimeGetNs())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = SemanticAnalyzer(model).analyze()
        assertThat(result.errors).noneMatch { it.code == "unreachable-code" }
    }
}
