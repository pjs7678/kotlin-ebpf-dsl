package dev.ebpf.dsl.types

import kotlin.properties.ReadOnlyProperty
import kotlin.reflect.KProperty

open class BpfStruct(override val cName: String) : BpfType() {

    private val _fields = mutableListOf<StructField>()
    private val _names = mutableSetOf<String>()
    private var _currentOffset = 0
    private var _maxAlignment = 1
    private var _frozen = false
    private var _sizeBytes = 0

    val fields: List<StructField>
        get() {
            freeze()
            return _fields.toList()
        }

    override val size: Int
        get() {
            freeze()
            return _sizeBytes
        }

    override val alignment: Int
        get() {
            freeze()
            return _maxAlignment
        }

    val sizeBytes: Int get() = size

    private fun freeze() {
        if (!_frozen) {
            _frozen = true
            val rem = _currentOffset % _maxAlignment
            _sizeBytes = if (rem == 0) _currentOffset
            else _currentOffset + (_maxAlignment - rem)
        }
    }

    /**
     * Field provider that uses [provideDelegate] to register fields at delegation time
     * (when `by` is evaluated during class init), NOT lazily at first property access.
     */
    protected inner class FieldProvider(private val type: BpfType, private val explicitCName: String?) {
        operator fun provideDelegate(
            thisRef: BpfStruct,
            prop: KProperty<*>,
        ): ReadOnlyProperty<BpfStruct, StructField> {
            val field = addField(prop.name, type, explicitCName)
            return ReadOnlyProperty { _, _ -> field }
        }
    }

    private fun addField(kotlinName: String, type: BpfType, explicitCName: String?): StructField {
        check(!_frozen) { "Struct already frozen" }
        val cFieldName = explicitCName ?: camelToSnake(kotlinName)
        require(_names.add(cFieldName)) { "Duplicate field name: '$cFieldName'" }

        val align = type.alignment
        if (align > _maxAlignment) _maxAlignment = align

        val rem = _currentOffset % align
        if (rem != 0) _currentOffset += (align - rem)

        val field = StructField(
            name = cFieldName,
            type = type,
            offset = _currentOffset,
            kotlinName = kotlinName,
        )
        _fields.add(field)
        _currentOffset += type.size
        return field
    }

    // Scalar field helpers
    protected fun u8(cName: String? = null) = FieldProvider(BpfScalar.U8, cName)
    protected fun u16(cName: String? = null) = FieldProvider(BpfScalar.U16, cName)
    protected fun u32(cName: String? = null) = FieldProvider(BpfScalar.U32, cName)
    protected fun u64(cName: String? = null) = FieldProvider(BpfScalar.U64, cName)
    protected fun s8(cName: String? = null) = FieldProvider(BpfScalar.S8, cName)
    protected fun s16(cName: String? = null) = FieldProvider(BpfScalar.S16, cName)
    protected fun s32(cName: String? = null) = FieldProvider(BpfScalar.S32, cName)
    protected fun s64(cName: String? = null) = FieldProvider(BpfScalar.S64, cName)
    protected fun bool(cName: String? = null) = FieldProvider(BpfScalar.Bool, cName)

    // Array field helper
    protected fun array(elementType: BpfType, length: Int, cName: String? = null) =
        FieldProvider(BpfArrayType(elementType, length), cName)

    companion object {
        fun camelToSnake(name: String): String =
            name.replace(Regex("([a-z])([A-Z])")) { "${it.groupValues[1]}_${it.groupValues[2]}" }
                .lowercase()
    }
}
