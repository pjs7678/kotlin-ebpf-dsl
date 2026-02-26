package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.BpfProgramModel

/**
 * Metadata for a BCC-style eBPF tool.
 *
 * @property name Short identifier (e.g. "biolatency")
 * @property description One-line summary of what the tool measures
 * @property hookTypes Kernel hook types used (e.g. "kprobe", "tracepoint")
 * @property build Factory function that creates the BpfProgramModel
 */
data class BpfTool(
    val name: String,
    val description: String,
    val hookTypes: List<String>,
    val build: () -> BpfProgramModel,
)

/**
 * Registry of all built-in BCC-style eBPF tools.
 *
 * ```kotlin
 * import dev.ebpf.dsl.tools.ToolRegistry
 * import dev.ebpf.dsl.api.*
 *
 * // List all tools
 * ToolRegistry.all().forEach { println("${it.name}: ${it.description}") }
 *
 * // Build a specific tool by name
 * val program = ToolRegistry.byName("biolatency")!!.build()
 * program.validate().throwOnError()
 * println(program.generateC())
 * ```
 */
object ToolRegistry {

    private val tools: List<BpfTool> = listOf(
        BpfTool(
            name = "execsnoop",
            description = "Process exec/exit/fork counting per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::execsnoop,
        ),
        BpfTool(
            name = "oomkill",
            description = "OOM kill event counting per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::oomkill,
        ),
        BpfTool(
            name = "runqlat",
            description = "CPU run queue latency histogram per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::runqlat,
        ),
        BpfTool(
            name = "tcpconnect",
            description = "TCP bytes, retransmits, connections, and RTT per cgroup",
            hookTypes = listOf("kprobe", "tracepoint"),
            build = ::tcpconnect,
        ),
        BpfTool(
            name = "vfsstat",
            description = "VFS read/write/open/fsync counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::vfsstat,
        ),
        BpfTool(
            name = "biolatency",
            description = "Block I/O latency histogram per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::biolatency,
        ),
        BpfTool(
            name = "hardirqs",
            description = "Hardware interrupt latency histogram per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::hardirqs,
        ),
        BpfTool(
            name = "softirqs",
            description = "Software interrupt latency histogram per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::softirqs,
        ),
        BpfTool(
            name = "cachestat",
            description = "Page cache hit/add/dirty counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::cachestat,
        ),
        BpfTool(
            name = "cpudist",
            description = "On-CPU time distribution histogram per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::cpudist,
        ),
        BpfTool(
            name = "dcstat",
            description = "Directory cache (dcache) hit/miss counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::dcstat,
        ),
        BpfTool(
            name = "tcpdrop",
            description = "TCP packet drop counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::tcpdrop,
        ),
        BpfTool(
            name = "tcplife",
            description = "TCP connection duration histogram per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::tcplife,
        ),
        BpfTool(
            name = "syscount",
            description = "System call counting per cgroup",
            hookTypes = listOf("raw_tracepoint"),
            build = ::syscount,
        ),
        BpfTool(
            name = "capable",
            description = "Security capability check counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::capable,
        ),
        BpfTool(
            name = "filelife",
            description = "File creation/deletion counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::filelife,
        ),
        BpfTool(
            name = "slabtop",
            description = "Slab/kmalloc allocation counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::slabtop,
        ),
        BpfTool(
            name = "writeback",
            description = "Dirty page writeback event counting per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::writeback,
        ),
        BpfTool(
            name = "bitesize",
            description = "Block I/O request size distribution per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::bitesize,
        ),
        BpfTool(
            name = "drsnoop",
            description = "Direct memory reclaim event counting per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::drsnoop,
        ),
        BpfTool(
            name = "signalsnoop",
            description = "Signal delivery counting per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::signalsnoop,
        ),
        BpfTool(
            name = "solisten",
            description = "Socket listen event counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::solisten,
        ),
        BpfTool(
            name = "pidpersec",
            description = "Process creation rate (fork/exec) per cgroup",
            hookTypes = listOf("tracepoint"),
            build = ::pidpersec,
        ),
        BpfTool(
            name = "tcpsynbl",
            description = "TCP SYN backlog completion counting per cgroup",
            hookTypes = listOf("kprobe"),
            build = ::tcpsynbl,
        ),
    )

    /** All registered tools. */
    fun all(): List<BpfTool> = tools

    /** Find a tool by name, or null if not found. */
    fun byName(name: String): BpfTool? = tools.find { it.name == name }

    /** All tool names. */
    fun names(): List<String> = tools.map { it.name }

    /** Tools that use the given hook type (e.g. "kprobe", "tracepoint"). */
    fun byHookType(hookType: String): List<BpfTool> =
        tools.filter { hookType in it.hookTypes }
}
