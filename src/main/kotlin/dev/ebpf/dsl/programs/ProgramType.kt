package dev.ebpf.dsl.programs

sealed class ProgramType {
    abstract val sectionPrefix: String

    data class Tracepoint(val category: String, val name: String) : ProgramType() {
        override val sectionPrefix = "tp/$category/$name"
    }

    data class RawTracepoint(val name: String) : ProgramType() {
        override val sectionPrefix = "raw_tp/$name"
    }

    data class Kprobe(val function: String) : ProgramType() {
        override val sectionPrefix = "kprobe/$function"
    }

    data class Kretprobe(val function: String) : ProgramType() {
        override val sectionPrefix = "kretprobe/$function"
    }

    data class Fentry(val function: String) : ProgramType() {
        override val sectionPrefix = "fentry/$function"
    }

    data class Fexit(val function: String) : ProgramType() {
        override val sectionPrefix = "fexit/$function"
    }

    data object Xdp : ProgramType() {
        override val sectionPrefix = "xdp"
    }

    data object TcClassifier : ProgramType() {
        override val sectionPrefix = "tc"
    }

    data class CgroupSkb(val direction: String) : ProgramType() {
        override val sectionPrefix = "cgroup_skb/$direction"
    }

    data class Lsm(val hook: String) : ProgramType() {
        override val sectionPrefix = "lsm/$hook"
    }

    data object SockOps : ProgramType() {
        override val sectionPrefix = "sockops"
    }

    data object SocketFilter : ProgramType() {
        override val sectionPrefix = "socket"
    }

    data class Iter(val type: String) : ProgramType() {
        override val sectionPrefix = "iter/$type"
    }

    data class SchedClassifier(val name: String) : ProgramType() {
        override val sectionPrefix = "struct_ops/$name"
    }
}
