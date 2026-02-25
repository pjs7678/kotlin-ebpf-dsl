package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class EbpfProgramBuilderTest {

    object MyKey : BpfStruct("my_key") {
        val id by u64()
    }

    object MyValue : BpfStruct("my_value") {
        val count by u64()
    }

    @Test
    fun `builds model with license and maps`() {
        val model = ebpf("test_prog") {
            license("GPL")
            val myMap by lruHashMap(MyKey, MyValue, maxEntries = 1024)
        }
        assertThat(model.name).isEqualTo("test_prog")
        assertThat(model.license).isEqualTo("GPL")
        assertThat(model.maps).hasSize(1)
        assertThat(model.maps[0].name).isEqualTo("my_map")
    }

    @Test
    fun `map name from property name converted to snake_case`() {
        val model = ebpf("test") {
            license("GPL")
            val oomKills by lruHashMap(MyKey, MyValue, maxEntries = 100)
        }
        assertThat(model.maps[0].name).isEqualTo("oom_kills")
    }

    @Test
    fun `duplicate map names throw`() {
        assertThatThrownBy {
            ebpf("bad") {
                val a by hashMap(MyKey, MyValue, maxEntries = 100)
                val b by hashMap(MyKey, MyValue, maxEntries = 100, mapName = "a")
            }
        }.hasMessageContaining("Duplicate")
    }

    @Test
    fun `structs are collected`() {
        val model = ebpf("test") {
            license("GPL")
            val m by lruHashMap(MyKey, MyValue, maxEntries = 100)
        }
        assertThat(model.structs).contains(MyKey, MyValue)
    }

    @Test
    fun `multiple programs in one model`() {
        val model = ebpf("multi") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
            kprobe("tcp_sendmsg") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs).hasSize(2)
    }

    @Test
    fun `explicit map name overrides property name`() {
        val model = ebpf("test") {
            license("GPL")
            val myMap by hashMap(MyKey, MyValue, maxEntries = 100, mapName = "custom_map")
        }
        assertThat(model.maps[0].name).isEqualTo("custom_map")
    }

    @Test
    fun `array map has U32 key`() {
        val model = ebpf("test") {
            license("GPL")
            val arr by array(MyValue, maxEntries = 64)
        }
        assertThat(model.maps[0].keyType).isEqualTo(BpfScalar.U32)
    }

    @Test
    fun `ringbuf has null key and value`() {
        val model = ebpf("test") {
            license("GPL")
            val rb by ringBuf(maxEntries = 256 * 1024)
        }
        assertThat(model.maps[0].keyType).isNull()
        assertThat(model.maps[0].valueType).isNull()
    }

    @Test
    fun `model with no license`() {
        val model = ebpf("test") {
            // no license set
        }
        assertThat(model.license).isNull()
    }

    @Test
    fun `program names follow naming convention`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                returnValue(literal(0, BpfScalar.S32))
            }
            kprobe("tcp_sendmsg") {
                returnValue(literal(0, BpfScalar.S32))
            }
            xdp {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.programs[0].name).isEqualTo("tp_sched_sched_switch")
        assertThat(model.programs[1].name).isEqualTo("kprobe_tcp_sendmsg")
        assertThat(model.programs[2].name).isEqualTo("xdp_prog")
    }
}
