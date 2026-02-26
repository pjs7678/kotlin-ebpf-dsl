package dev.ebpf.dsl.api

/**
 * Standard eBPF license strings.
 *
 * GPL is required for most helper functions. Dual licenses permit
 * proprietary code that still uses GPL-only helpers.
 */
enum class BpfLicense(val licenseString: String) {
    GPL("GPL"),
    GPL_V2("GPL v2"),
    DUAL_BSD_GPL("Dual BSD/GPL"),
    DUAL_MIT_GPL("Dual MIT/GPL"),
    ;
}
