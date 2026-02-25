package dev.ebpf.dsl.api

import dev.ebpf.dsl.maps.MapCapabilities
import dev.ebpf.dsl.maps.MapDecl

class MapHandle(val decl: MapDecl) {
    val name: String get() = decl.name
    val capabilities: MapCapabilities get() = decl.capabilities
}
