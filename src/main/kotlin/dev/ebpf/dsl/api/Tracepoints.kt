package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar

/** sched/sched_switch — context switch event */
object SchedSwitch : TracepointDef("sched", "sched_switch", "trace_event_raw_sched_switch") {
    val prevPid = field("prev_pid", BpfScalar.U32)
    val nextPid = field("next_pid", BpfScalar.U32)
    val prevState = field("prev_state", BpfScalar.S64)
}

/** sched/sched_wakeup — task wakeup event */
object SchedWakeup : TracepointDef("sched", "sched_wakeup", "trace_event_raw_sched_wakeup_template") {
    val pid = field("pid", BpfScalar.U32)
}

/** sock/inet_sock_set_state — TCP state transition */
object InetSockSetState : TracepointDef("sock", "inet_sock_set_state", "trace_event_raw_inet_sock_set_state") {
    val newstate = field("newstate", BpfScalar.S32)
    val sport = field("sport", BpfScalar.U16)
    val dport = field("dport", BpfScalar.U16)
    val oldstate = field("oldstate", BpfScalar.S32)
}

/** tcp/tcp_probe — TCP probe event */
object TcpProbe : TracepointDef("tcp", "tcp_probe", "trace_event_raw_tcp_probe") {
    val srtt = field("srtt", BpfScalar.U32)
}

/** irq/irq_handler_entry — hardware interrupt entry */
object IrqHandlerEntry : TracepointDef("irq", "irq_handler_entry", "trace_event_raw_irq_handler_entry") {
    val irq = field("irq", BpfScalar.S32)
}

/** irq/irq_handler_exit — hardware interrupt exit */
object IrqHandlerExit : TracepointDef("irq", "irq_handler_exit", "trace_event_raw_irq_handler_exit") {
    val irq = field("irq", BpfScalar.S32)
    val ret = field("ret", BpfScalar.S32)
}

/** irq/softirq_entry — software interrupt entry */
object SoftirqEntry : TracepointDef("irq", "softirq_entry", "trace_event_raw_softirq") {
    val vec = field("vec", BpfScalar.U32)
}

/** irq/softirq_exit — software interrupt exit */
object SoftirqExit : TracepointDef("irq", "softirq_exit", "trace_event_raw_softirq") {
    val vec = field("vec", BpfScalar.U32)
}

/** sched/sched_process_exec — process exec event */
object SchedProcessExec : TracepointDef("sched", "sched_process_exec", "trace_event_raw_sched_process_exec") {
    val pid = field("pid", BpfScalar.U32)
}

/** sched/sched_process_exit — process exit event */
object SchedProcessExit : TracepointDef("sched", "sched_process_exit", "trace_event_raw_sched_process_template") {
    val pid = field("pid", BpfScalar.U32)
}

/** sched/sched_process_fork — process fork event */
object SchedProcessFork : TracepointDef("sched", "sched_process_fork", "trace_event_raw_sched_process_fork") {
    val parentPid = field("parent_pid", BpfScalar.U32)
    val childPid = field("child_pid", BpfScalar.U32)
}

/** tcp/tcp_retransmit_skb — TCP retransmit event */
object TcpRetransmitSkb : TracepointDef("tcp", "tcp_retransmit_skb", "trace_event_raw_tcp_event_sk") {
    // no fields commonly accessed
}

/** signal/signal_deliver — signal delivery event */
object SignalDeliver : TracepointDef("signal", "signal_deliver", "trace_event_raw_signal_deliver") {
    val sig = field("sig", BpfScalar.S32)
}

/** writeback/writeback_start — writeback start event */
object WritebackStart : TracepointDef("writeback", "writeback_start", "trace_event_raw_writeback_work") {
    // no fields commonly accessed
}

/** writeback/writeback_written — writeback completion event */
object WritebackWritten : TracepointDef("writeback", "writeback_written", "trace_event_raw_writeback_work") {
    // no fields commonly accessed
}

/** mm/mm_vmscan_direct_reclaim_begin — direct reclaim start */
object DirectReclaimBegin : TracepointDef("mm", "mm_vmscan_direct_reclaim_begin", "trace_event_raw_mm_vmscan_direct_reclaim_begin_template") {
    // no fields commonly accessed
}

/** mm/mm_vmscan_direct_reclaim_end — direct reclaim end */
object DirectReclaimEnd : TracepointDef("mm", "mm_vmscan_direct_reclaim_end", "trace_event_raw_mm_vmscan_direct_reclaim_end_template") {
    val nrReclaimed = field("nr_reclaimed", BpfScalar.U64)
}
