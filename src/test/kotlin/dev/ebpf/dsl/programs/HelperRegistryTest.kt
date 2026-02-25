package dev.ebpf.dsl.programs

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HelperRegistryTest {

    @Test
    fun `ktime_get_ns available in all program types`() {
        val helper = HelperRegistry.findByName("bpf_ktime_get_ns")!!
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Kprobe::class)).isTrue()
    }

    @Test
    fun `get_current_cgroup_id NOT available in XDP`() {
        val helper = HelperRegistry.findByName("bpf_get_current_cgroup_id")!!
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isFalse()
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isTrue()
    }

    @Test
    fun `get_current_pid_tgid NOT available in XDP`() {
        val helper = HelperRegistry.findByName("bpf_get_current_pid_tgid")!!
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isFalse()
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isTrue()
    }

    @Test
    fun `probe_read_kernel is GPL only`() {
        val helper = HelperRegistry.findByName("bpf_probe_read_kernel")!!
        assertThat(helper.gplOnly).isTrue()
    }

    @Test
    fun `ktime_get_ns is not GPL only`() {
        val helper = HelperRegistry.findByName("bpf_ktime_get_ns")!!
        assertThat(helper.gplOnly).isFalse()
    }

    @Test
    fun `helper has typed return`() {
        val helper = HelperRegistry.findByName("bpf_ktime_get_ns")!!
        assertThat(helper.returnType.cName).isEqualTo("__u64")
    }

    @Test
    fun `findById works`() {
        val helper = HelperRegistry.findById(5)!!
        assertThat(helper.name).isEqualTo("bpf_ktime_get_ns")
    }

    @Test
    fun `xdp_adjust_head only available in XDP`() {
        val helper = HelperRegistry.findByName("bpf_xdp_adjust_head")!!
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isFalse()
        assertThat(helper.isAvailableIn(ProgramType.TcClassifier::class)).isFalse()
    }

    @Test
    fun `redirect available in XDP and TC`() {
        val helper = HelperRegistry.findByName("bpf_redirect")!!
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.TcClassifier::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isFalse()
    }

    @Test
    fun `ringbuf_reserve is available everywhere`() {
        val helper = HelperRegistry.findByName("bpf_ringbuf_reserve")!!
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isTrue()
    }

    @Test
    fun `at least 30 helpers registered`() {
        assertThat(HelperRegistry.all().size).isGreaterThanOrEqualTo(30)
    }

    @Test
    fun `map_lookup_elem is universal`() {
        val helper = HelperRegistry.findByName("bpf_map_lookup_elem")!!
        assertThat(helper.id).isEqualTo(1)
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.SockOps::class)).isTrue()
    }

    @Test
    fun `map_update_elem is universal`() {
        val helper = HelperRegistry.findByName("bpf_map_update_elem")!!
        assertThat(helper.id).isEqualTo(2)
    }

    @Test
    fun `map_delete_elem is universal`() {
        val helper = HelperRegistry.findByName("bpf_map_delete_elem")!!
        assertThat(helper.id).isEqualTo(3)
    }

    @Test
    fun `get_current_task_btf is GPL only`() {
        val helper = HelperRegistry.findByName("bpf_get_current_task_btf")!!
        assertThat(helper.gplOnly).isTrue()
    }

    @Test
    fun `probe_read_user is GPL only`() {
        val helper = HelperRegistry.findByName("bpf_probe_read_user")!!
        assertThat(helper.gplOnly).isTrue()
    }

    @Test
    fun `skb_store_bytes only available in TC`() {
        val helper = HelperRegistry.findByName("bpf_skb_store_bytes")!!
        assertThat(helper.isAvailableIn(ProgramType.TcClassifier::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isFalse()
        assertThat(helper.isAvailableIn(ProgramType.Tracepoint::class)).isFalse()
    }

    @Test
    fun `skb_load_bytes available in TC, CgroupSkb, SocketFilter`() {
        val helper = HelperRegistry.findByName("bpf_skb_load_bytes")!!
        assertThat(helper.isAvailableIn(ProgramType.TcClassifier::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.CgroupSkb::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.SocketFilter::class)).isTrue()
        assertThat(helper.isAvailableIn(ProgramType.Xdp::class)).isFalse()
    }

    @Test
    fun `perf_event_output is universal`() {
        val helper = HelperRegistry.findByName("bpf_perf_event_output")!!
        assertThat(helper.id).isEqualTo(25)
    }

    @Test
    fun `spin lock and unlock are universal`() {
        val lock = HelperRegistry.findByName("bpf_spin_lock")!!
        val unlock = HelperRegistry.findByName("bpf_spin_unlock")!!
        assertThat(lock.id).isEqualTo(93)
        assertThat(unlock.id).isEqualTo(94)
        assertThat(lock.isAvailableIn(ProgramType.Tracepoint::class)).isTrue()
        assertThat(unlock.isAvailableIn(ProgramType.Xdp::class)).isTrue()
    }

    @Test
    fun `all helper ids are unique`() {
        val ids = HelperRegistry.all().map { it.id }
        assertThat(ids).doesNotHaveDuplicates()
    }

    @Test
    fun `all helper names are unique`() {
        val names = HelperRegistry.all().map { it.name }
        assertThat(names).doesNotHaveDuplicates()
    }

    @Test
    fun `findByName returns null for unknown helper`() {
        assertThat(HelperRegistry.findByName("bpf_nonexistent")).isNull()
    }

    @Test
    fun `findById returns null for unknown id`() {
        assertThat(HelperRegistry.findById(99999)).isNull()
    }
}
