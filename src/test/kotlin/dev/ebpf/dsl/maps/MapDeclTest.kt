package dev.ebpf.dsl.maps

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test

class MapDeclTest {
    object TestKey : BpfStruct("test_key") {
        val id by u64()
    }
    object TestValue : BpfStruct("test_value") {
        val count by u64()
    }

    @Test
    fun `hash map supports lookup, update, delete`() {
        val map = MapDecl("cache", MapType.HASH, TestKey, TestValue, 10240)
        assertThat(map.capabilities.canLookup).isTrue()
        assertThat(map.capabilities.canUpdate).isTrue()
        assertThat(map.capabilities.canDelete).isTrue()
        assertThat(map.capabilities.canReserve).isFalse()
    }

    @Test
    fun `lru hash supports lookupOrInit`() {
        val map = MapDecl("stats", MapType.LRU_HASH, TestKey, TestValue, 10240)
        assertThat(map.capabilities.canLookupOrInit).isTrue()
    }

    @Test
    fun `array map does not support delete`() {
        val map = MapDecl("arr", MapType.ARRAY, BpfScalar.U32, TestValue, 100)
        assertThat(map.capabilities.canDelete).isFalse()
        assertThat(map.capabilities.canLookup).isTrue()
    }

    @Test
    fun `ring buffer supports reserve and submit`() {
        val map = MapDecl("events", MapType.RINGBUF, null, null, 256 * 1024)
        assertThat(map.capabilities.canReserve).isTrue()
        assertThat(map.capabilities.canLookup).isFalse()
    }

    @Test
    fun `map name over 15 chars throws`() {
        assertThatThrownBy {
            MapDecl("this_name_is_way_too_long", MapType.HASH, TestKey, TestValue, 100)
        }.isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("15")
    }

    @Test
    fun `max entries must be positive`() {
        assertThatThrownBy {
            MapDecl("bad", MapType.HASH, TestKey, TestValue, 0)
        }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `ringbuf max entries must be power of 2`() {
        assertThatThrownBy {
            MapDecl("rb", MapType.RINGBUF, null, null, 1000)
        }.isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("power of 2")
    }

    @Test
    fun `array key must be U32`() {
        assertThatThrownBy {
            MapDecl("arr", MapType.ARRAY, TestKey, TestValue, 100)
        }.isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("U32")
    }

    @Test
    fun `C map type constant is correct`() {
        assertThat(MapType.HASH.cName).isEqualTo("BPF_MAP_TYPE_HASH")
        assertThat(MapType.LRU_HASH.cName).isEqualTo("BPF_MAP_TYPE_LRU_HASH")
        assertThat(MapType.RINGBUF.cName).isEqualTo("BPF_MAP_TYPE_RINGBUF")
    }

    @Test
    fun `perf event array supports output`() {
        val map = MapDecl("perf", MapType.PERF_EVENT_ARRAY, BpfScalar.U32, BpfScalar.U32, 128)
        assertThat(map.capabilities.canOutput).isTrue()
        assertThat(map.capabilities.canLookup).isFalse()
    }

    @Test
    fun `stack trace supports getStackId`() {
        val map = MapDecl("stacks", MapType.STACK_TRACE, BpfScalar.U32, BpfScalar.U64, 4096)
        assertThat(map.capabilities.canGetStackId).isTrue()
    }
}
