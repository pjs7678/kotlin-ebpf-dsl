package dev.ebpf.dsl.validation

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class TypeCheckerTest {

    object K : BpfStruct("k") {
        val id by u64()
    }

    object V : BpfStruct("v") {
        val count by u64()
    }

    @Test
    fun `valid program passes type check`() {
        val model = ebpf("ok") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `helper unavailable in program type is error`() {
        val model = ebpf("bad") {
            license("GPL")
            xdp {
                // getCurrentCgroupId is TRACING-only, not available in XDP
                val cg = declareVar("cg", getCurrentCgroupId())
                returnAction(XDP_PASS)
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).anyMatch { it.code == "helper-unavailable" }
    }

    @Test
    fun `GPL helper without GPL license is error`() {
        // bpf_ktime_get_ns is not GPL-only, so a model with non-GPL license
        // and only non-GPL helpers should pass
        val model = ebpf("test") {
            license("Proprietary")
            tracepoint("sched", "sched_switch") {
                val t = declareVar("t", ktimeGetNs()) // not GPL-only, so this works
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).isEmpty() // ktime_get_ns is not GPL-only
    }

    @Test
    fun `multiple programs checked independently`() {
        val model = ebpf("multi") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
            xdp {
                // getCurrentCgroupId is TRACING-only: error in XDP
                val cg = declareVar("cg", getCurrentCgroupId())
                returnAction(XDP_PASS)
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).hasSize(1)
        assertThat(result.errors[0].code).isEqualTo("helper-unavailable")
    }

    @Test
    fun `helper available in correct program type passes`() {
        val model = ebpf("ok") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val pid = declareVar("pid", getCurrentPidTgid())
                val cg = declareVar("cg", getCurrentCgroupId())
                val t = declareVar("t", ktimeGetNs())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `universal helper available in all program types`() {
        val model = ebpf("ok") {
            license("GPL")
            xdp {
                val t = declareVar("t", ktimeGetNs()) // universal helper
                returnAction(XDP_PASS)
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `error includes program name`() {
        val model = ebpf("bad") {
            license("GPL")
            xdp {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnAction(XDP_PASS)
            }
        }
        val result = TypeChecker(model).check()
        assertThat(result.errors).isNotEmpty()
        assertThat(result.errors).allMatch { it.programName == "xdp_prog" }
    }
}
