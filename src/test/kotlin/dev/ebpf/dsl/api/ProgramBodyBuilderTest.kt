package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfStmt
import dev.ebpf.dsl.programs.ProgramType
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class ProgramBodyBuilderTest {

    object TK : BpfStruct("t_key") {
        val cgroupId by u64()
    }

    object TV : BpfStruct("t_value") {
        val count by u64()
    }

    @Test
    fun `literal creates typed expression`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val x = literal(42u, BpfScalar.U64)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs[0].body).isNotEmpty()
    }

    @Test
    fun `helper call creates HelperCall expression`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val cg = getCurrentCgroupId()
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs).hasSize(1)
        assertThat(model.programs[0].body).isNotEmpty()
    }

    @Test
    fun `missing GPL license throws for GPL helper`() {
        assertThatThrownBy {
            ebpf("bad") {
                license("Proprietary")
                tracepoint("sched", "sched_switch") {
                    probeReadKernel(literal(0L, BpfScalar.U64), BpfScalar.U32)
                }
            }
        }.hasMessageContaining("GPL")
    }

    @Test
    fun `ifNonNull creates IfNonNull statement`() {
        val model = ebpf("test") {
            license("GPL")
            val m by lruHashMap(TK, TV, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                val key = stackVar(TK) {
                    it[TK.cgroupId] = getCurrentCgroupId()
                }
                val entry = m.lookup(key)
                ifNonNull(entry) { e ->
                    e[TV.count].atomicAdd(literal(1u, BpfScalar.U64))
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val body = model.programs[0].body
        val ifNonNullStmts = body.filterIsInstance<BpfStmt.IfNonNull>()
        assertThat(ifNonNullStmts).hasSize(1)
    }

    @Test
    fun `boundedLoop creates BoundedLoop statement`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                boundedLoop(literal(27u, BpfScalar.U32)) { i ->
                    // body
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val loops = model.programs[0].body.filterIsInstance<BpfStmt.BoundedLoop>()
        assertThat(loops).hasSize(1)
    }

    @Test
    fun `ifThen without else creates If with null else`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = literal(1u, BpfScalar.U32)
                val b = literal(0u, BpfScalar.U32)
                ifThen(a ne b) {
                    returnValue(literal(1, BpfScalar.S32))
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val ifs = model.programs[0].body.filterIsInstance<BpfStmt.If>()
        assertThat(ifs).hasSize(1)
        assertThat(ifs[0].else_).isNull()
    }

    @Test
    fun `arithmetic operators create BinaryOp`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = literal(1u, BpfScalar.U32)
                val b = literal(2u, BpfScalar.U32)
                val c = a + b
                val d = a and literal(0xFFu, BpfScalar.U32)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs[0].body).isNotEmpty()
    }

    @Test
    fun `raw escape hatch creates Raw expression`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val x = raw("bpf_some_helper(ctx, 42)", BpfScalar.U64)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs[0].body).isNotEmpty()
    }

    @Test
    fun `XDP program with returnAction`() {
        val model = ebpf("test") {
            license("GPL")
            xdp {
                returnAction(XDP_PASS)
            }
        }
        assertThat(model.programs).hasSize(1)
        assertThat(model.programs[0].type).isEqualTo(ProgramType.Xdp)
    }

    @Test
    fun `cast changes expression type`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val pid = getCurrentPidTgid()
                val tid = cast(pid, BpfScalar.U32)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs[0].body).isNotEmpty()
    }

    @Test
    fun `ifThen with elseThen creates If with else block`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = literal(1u, BpfScalar.U32)
                val b = literal(0u, BpfScalar.U32)
                ifThen(a eq b) {
                    returnValue(literal(0, BpfScalar.S32))
                }.elseThen {
                    returnValue(literal(1, BpfScalar.S32))
                }
            }
        }
        val ifs = model.programs[0].body.filterIsInstance<BpfStmt.If>()
        assertThat(ifs).hasSize(1)
        assertThat(ifs[0].else_).isNotNull()
        assertThat(ifs[0].else_).isNotEmpty()
    }

    @Test
    fun `declareVar emits VarDecl statement`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val x = declareVar("counter", literal(0u, BpfScalar.U64), mutable = true)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val varDecls = model.programs[0].body.filterIsInstance<BpfStmt.VarDecl>()
        assertThat(varDecls).hasSize(1)
        assertThat(varDecls[0].variable.name).isEqualTo("counter")
        assertThat(varDecls[0].variable.mutable).isTrue()
    }

    @Test
    fun `stackVar emits VarDecl and field assignments`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                val key = stackVar(TK) {
                    it[TK.cgroupId] = literal(42u, BpfScalar.U64)
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val body = model.programs[0].body
        val varDecls = body.filterIsInstance<BpfStmt.VarDecl>()
        val assigns = body.filterIsInstance<BpfStmt.Assign>()
        assertThat(varDecls).hasSize(1)
        assertThat(assigns).hasSize(1)
    }

    @Test
    fun `map update emits ExprStmt with MapUpdate`() {
        val model = ebpf("test") {
            license("GPL")
            val m by hashMap(TK, TV, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                val key = stackVar(TK) {
                    it[TK.cgroupId] = literal(1u, BpfScalar.U64)
                }
                val value = stackVar(TV) {
                    it[TV.count] = literal(0u, BpfScalar.U64)
                }
                m.update(key, value)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val exprStmts = model.programs[0].body.filterIsInstance<BpfStmt.ExprStmt>()
        assertThat(exprStmts).isNotEmpty()
    }

    @Test
    fun `map delete emits MapDelete statement`() {
        val model = ebpf("test") {
            license("GPL")
            val m by hashMap(TK, TV, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                val key = stackVar(TK) {
                    it[TK.cgroupId] = literal(1u, BpfScalar.U64)
                }
                m.delete(key)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val deletes = model.programs[0].body.filterIsInstance<BpfStmt.MapDelete>()
        assertThat(deletes).hasSize(1)
    }

    @Test
    fun `forRange creates bounded loop`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                forRange(0, 10) { i ->
                    // loop body
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val loops = model.programs[0].body.filterIsInstance<BpfStmt.BoundedLoop>()
        assertThat(loops).hasSize(1)
    }

    @Test
    fun `null license throws for GPL helper`() {
        assertThatThrownBy {
            ebpf("bad") {
                // no license set at all
                tracepoint("sched", "sched_switch") {
                    probeReadKernel(literal(0L, BpfScalar.U64), BpfScalar.U32)
                }
            }
        }.hasMessageContaining("GPL")
    }
}
