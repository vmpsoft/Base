#pragma once

namespace coff
{
    class string_table : public std::vector<char>
    {
    public:
        void load(base::architecture &file);
        std::string resolve(size_t offset) const;
    };

#pragma pack(push, 1)
    class format {
    public:
        struct string_t
        {
            union
            {
                char                 short_name[8];
                struct
                {
                    uint32_t         is_short;
                    uint32_t         long_name_offset;
                };
            };
        };

        enum special_section_id : uint16_t
        {
            symbol_undefined = 0,
            symbol_absolute = 0xFFFF,
            symbol_debug = 0xFFFE,
        };

        enum class storage_class_id : uint8_t
        {
            none = 0,
            auto_variable = 1,
            public_symbol = 2,
            private_symbol = 3,
            register_variable = 4,
            external_definition = 5,
            label = 6,
            undefined_label = 7,
            struct_member = 8,
            function_argument = 9,
            struct_tag = 10,
            union_member = 11,
            union_tag = 12,
            type_definition = 13,
            undefined_static = 14,
            enum_tag = 15,
            enum_member = 16,
            register_parameter = 17,
            bitfield = 18,
            auto_argument = 19,
            end_of_block = 20,
            block_delimiter = 100,
            function_delimiter = 101,
            struct_end = 102,
            file_name = 103,
            line_number = 104,
            section = 104,
            alias_entry = 105,
            weak_external = 105,
            hidden_ext_symbol = 106,
            clr_token = 107,
            phys_end_of_function = 255,
        };

        enum class base_type_id : uint16_t
        {
            none = 0,
            t_void = 1,
            t_char = 2,
            t_short = 3,
            t_int = 4,
            t_long = 5,
            t_float = 6,
            t_double = 7,
            t_struct = 8,
            t_union = 9,
            t_enum = 10,
            t_enum_mem = 11,
            t_uchar = 12,
            t_ushort = 13,
            t_uint = 14,
            t_ulong = 15,
        };

        enum class derived_type_id : uint16_t
        {
            none = 0,
            pointer = 1,
            function = 2,
            c_array = 3,
        };

        struct symbol_t
        {
            string_t                 name;
            int32_t                  value;
            uint16_t                 section_index;
            base_type_id             base_type : 4;
            derived_type_id          derived_type : 12;
            storage_class_id         storage_class;
            uint8_t                  num_auxiliary;
        };
    };
#pragma pack(pop)
}
