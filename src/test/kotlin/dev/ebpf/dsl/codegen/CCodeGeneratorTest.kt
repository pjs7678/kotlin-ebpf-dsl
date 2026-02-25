package dev.ebpf.dsl.codegen

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CCodeGeneratorTest {
    object CK : BpfStruct("counter_key") { val cgroupId by u64() }
    object CV : BpfStruct("counter_value") { val count by u64() }

    @Test
    fun `generates includes and license`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("#include \"vmlinux.h\"")
        assertThat(code).contains("#include <bpf/bpf_helpers.h>")
        assertThat(code).contains("char LICENSE[] SEC(\"license\") = \"GPL\";")
    }

    @Test
    fun `generates struct definitions`() {
        val model = ebpf("test") {
            license("GPL")
            val m by lruHashMap(CK, CV, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("struct counter_key {")
        assertThat(code).contains("__u64 cgroup_id;")
        assertThat(code).contains("struct counter_value {")
        assertThat(code).contains("__u64 count;")
    }

    @Test
    fun `generates map definitions`() {
        val model = ebpf("test") {
            license("GPL")
            val m by lruHashMap(CK, CV, maxEntries = 10240)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__uint(type, BPF_MAP_TYPE_LRU_HASH);")
        assertThat(code).contains("__uint(max_entries, 10240);")
        assertThat(code).contains("__type(key, struct counter_key);")
        assertThat(code).contains("__type(value, struct counter_value);")
        assertThat(code).contains("SEC(\".maps\")")
    }

    @Test
    fun `generates tracepoint with SEC`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("SEC(\"tp/oom/mark_victim\")")
        assertThat(code).contains("return 0;")
    }

    @Test
    fun `generates helper calls`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val cg = declareVar("cgroup_id", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("bpf_get_current_cgroup_id()")
    }

    @Test
    fun `generates atomic add`() {
        val model = ebpf("test") {
            license("GPL")
            val m by lruHashMap(CK, CV, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                val key = stackVar(CK) {
                    it[CK.cgroupId] = getCurrentCgroupId()
                }
                val entry = m.lookup(key)
                ifNonNull(entry) { e ->
                    e[CV.count].atomicAdd(literal(1u, BpfScalar.U64))
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__sync_fetch_and_add")
    }

    @Test
    fun `generates kprobe with pt_regs context`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("tcp_sendmsg") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("SEC(\"kprobe/tcp_sendmsg\")")
        assertThat(code).contains("struct pt_regs *ctx")
    }

    @Test
    fun `generates xdp with xdp_md context`() {
        val model = ebpf("test") {
            license("GPL")
            xdp {
                returnAction(XDP_PASS)
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("SEC(\"xdp\")")
        assertThat(code).contains("struct xdp_md *ctx")
    }

    @Test
    fun `generates bounded loop`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                boundedLoop(literal(27u, BpfScalar.U32)) { i ->
                    // empty body
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("#pragma unroll")
        assertThat(code).contains("for (")
    }

    @Test
    fun `generates if-else`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = literal(1u, BpfScalar.U32)
                ifThen(a ne literal(0u, BpfScalar.U32)) {
                    returnValue(literal(1, BpfScalar.S32))
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("if (")
    }

    @Test
    fun `generates raw C code verbatim`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                declareVar("x", raw("bpf_custom_helper(ctx, 42)", BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("bpf_custom_helper(ctx, 42)")
    }

    @Test
    fun `generates ringbuf map without key value types`() {
        val model = ebpf("test") {
            license("GPL")
            val events by ringBuf(maxEntries = 256 * 1024)
            tracepoint("sched", "sched_switch") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("BPF_MAP_TYPE_RINGBUF")
        assertThat(code).doesNotContain("__type(key")
    }
}
