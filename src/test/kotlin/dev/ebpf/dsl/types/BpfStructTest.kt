package dev.ebpf.dsl.types

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class BpfStructTest {

    @Test
    fun `simple struct computes size and offsets`() {
        val struct = object : BpfStruct("test_key") {
            val cgroupId by u64()
        }
        assertThat(struct.sizeBytes).isEqualTo(8)
        assertThat(struct.fields).hasSize(1)
        assertThat(struct.fields[0].name).isEqualTo("cgroup_id")
        assertThat(struct.fields[0].offset).isEqualTo(0)
    }

    @Test
    fun `multi-field struct with padding`() {
        val struct = object : BpfStruct("padded") {
            val a by u8()
            val b by u32() // needs 3 bytes padding after a
        }
        assertThat(struct.fields[0].offset).isEqualTo(0)  // a at 0
        assertThat(struct.fields[1].offset).isEqualTo(4)  // b at 4 (aligned to 4)
        assertThat(struct.sizeBytes).isEqualTo(8)          // padded to max alignment (4)
    }

    @Test
    fun `struct with array field`() {
        val struct = object : BpfStruct("hist_value") {
            val slots by array(BpfScalar.U64, 27)
            val count by u64()
            val sumNs by u64()
        }
        assertThat(struct.sizeBytes).isEqualTo(232) // 27*8 + 8 + 8
        assertThat(struct.fields[0].offset).isEqualTo(0)
        assertThat(struct.fields[1].offset).isEqualTo(216)
        assertThat(struct.fields[2].offset).isEqualTo(224)
    }

    @Test
    fun `duplicate field name throws`() {
        assertThatThrownBy {
            object : BpfStruct("bad") {
                val a by u32()
                val a2 by u32(cName = "a")
            }.fields
        }.isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("Duplicate")
    }

    @Test
    fun `camelCase converts to snake_case`() {
        val struct = object : BpfStruct("my_struct") {
            val myCgroupId by u64()
        }
        assertThat(struct.fields[0].name).isEqualTo("my_cgroup_id")
    }

    @Test
    fun `cName is used as struct name`() {
        val struct = object : BpfStruct("counter_key") {}
        assertThat(struct.cName).isEqualTo("counter_key")
    }

    @Test
    fun `complex padding scenario`() {
        // struct { u8 a; u16 b; u8 c; u64 d; }
        // a: offset 0, size 1
        // b: offset 2 (aligned to 2), size 2
        // c: offset 4, size 1
        // d: offset 8 (aligned to 8), size 8
        // total: 16 (padded to alignment 8)
        val struct = object : BpfStruct("complex") {
            val a by u8()
            val b by u16()
            val c by u8()
            val d by u64()
        }
        assertThat(struct.fields[0].offset).isEqualTo(0)
        assertThat(struct.fields[1].offset).isEqualTo(2)
        assertThat(struct.fields[2].offset).isEqualTo(4)
        assertThat(struct.fields[3].offset).isEqualTo(8)
        assertThat(struct.sizeBytes).isEqualTo(16)
    }
}
