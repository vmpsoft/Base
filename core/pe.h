#pragma once

namespace pe
{
	class string_table : public std::vector<char>
	{
	public:
		void load(base::architecture &file);
		std::string resolve(size_t offset) const;
	};

#pragma pack(push, 1)
	class format : public base::format
	{
	public:
		static constexpr uint16_t dos_signature = 0x5A4D;
		static constexpr uint32_t nt_signature = 0x00004550;

		struct dos_header_t
		{
			uint16_t        e_magic;
			uint16_t        e_cblp;
			uint16_t        e_cp;
			uint16_t        e_crlc;
			uint16_t        e_cparhdr;
			uint16_t        e_minalloc;
			uint16_t        e_maxalloc;
			uint16_t        e_ss;
			uint16_t        e_sp;
			uint16_t        e_csum;
			uint16_t        e_ip;
			uint16_t        e_cs;
			uint16_t        e_lfarlc;
			uint16_t        e_ovno;
			uint16_t        e_res[4];
			uint16_t        e_oemid;
			uint16_t        e_oeminfo;
			uint16_t        e_res2[10];
			uint32_t        e_lfanew;
		};

		enum class machine_id : uint16_t
		{
			unknown =       0x0000,
			target_host =   0x0001,
			i386 =          0x014C,
			r3000 =         0x0162,
			r4000 =         0x0166,
			r10000 =        0x0168,
			wcemipsv2 =     0x0169,
			alpha =         0x0184,
			sh3 =           0x01A2,
			sh3dsp =        0x01A3,
			sh3e =          0x01A4,
			sh4 =           0x01A6,
			sh5 =           0x01A8,
			arm =           0x01C0,
			thumb =         0x01C2,
			armnt =         0x01C4,
			am33 =          0x01D3,
			powerpc =       0x01F0,
			powerpcfp =     0x01F1,
			ia64 =          0x0200,
			mips16 =        0x0266,
			alpha64 =       0x0284,
			mipsfpu =       0x0366,
			mipsfpu16 =     0x0466,
			axp64 =         0x0284,
			tricore =       0x0520,
			cef =           0x0CEF,
			ebc =           0x0EBC,
			amd64 =         0x8664,
			m32r =          0x9041,
			arm64 =         0xAA64,
			cee =           0xC0EE
		};

		struct file_header_t
		{
			machine_id  machine;
			uint16_t    num_sections;
			uint32_t    timedate_stamp;
			uint32_t    ptr_symbols;
			uint32_t    num_symbols;
			uint16_t    size_optional_header;
			uint16_t    characteristics;
		};

		union version_t
		{
			uint16_t    identifier;
			struct
			{
				uint8_t major;
				uint8_t minor;
			};
		};
		union ex_version_t
		{
			uint32_t     identifier;
			struct
			{
				uint16_t major;
				uint16_t minor;
			};
		};

		enum class subsystem_id : uint16_t
		{
			unknown =                  0x0000,
			native =                   0x0001,
			windows_gui =              0x0002,
			windows_cui =              0x0003,
			os2_cui =                  0x0005,
			posix_cui =                0x0007,
			native_windows =           0x0008,
			windows_ce_gui =           0x0009,
			efi_application =          0x000A,
			efi_boot_service_driver =  0x000B,
			efi_runtime_driver =       0x000C,
			efi_rom =                  0x000D,
			xbox =                     0x000E,
			windows_boot_application = 0x0010,
			xbox_code_catalog =        0x0011,
		};

		static constexpr uint16_t hdr32_magic = 0x010B;
		static constexpr uint16_t hdr64_magic = 0x020B;

		struct optional_header_64_t
		{
			uint16_t        magic;
			version_t       linker_version;
			uint32_t        size_code;
			uint32_t        size_init_data;
			uint32_t        size_uninit_data;
			uint32_t        entry_point;
			uint32_t        base_of_code;
			uint64_t        image_base;
			uint32_t        section_alignment;
			uint32_t        file_alignment;
			ex_version_t    os_version;
			ex_version_t    img_version;
			ex_version_t    subsystem_version;
			uint32_t        win32_version_value;
			uint32_t        size_image;
			uint32_t        size_headers;
			uint32_t        checksum;
			subsystem_id    subsystem;
			uint16_t        characteristics;
			uint64_t        size_stack_reserve;
			uint64_t        size_stack_commit;
			uint64_t        size_heap_reserve;
			uint64_t        size_heap_commit;
			uint32_t        ldr_flags;
			uint32_t        num_data_directories;
		};

		struct optional_header_32_t
		{
			uint16_t        magic;
			version_t       linker_version;
			uint32_t        size_code;
			uint32_t        size_init_data;
			uint32_t        size_uninit_data;
			uint32_t        entry_point;
			uint32_t        base_of_code;
			uint32_t        base_of_data;
			uint32_t        image_base;
			uint32_t        section_alignment;
			uint32_t        file_alignment;
			ex_version_t    os_version;
			ex_version_t    img_version;
			ex_version_t    subsystem_version;
			uint32_t        win32_version_value;
			uint32_t        size_image;
			uint32_t        size_headers;
			uint32_t        checksum;
			subsystem_id    subsystem;
			uint16_t        characteristics;
			uint32_t        size_stack_reserve;
			uint32_t        size_stack_commit;
			uint32_t        size_heap_reserve;
			uint32_t        size_heap_commit;
			uint32_t        ldr_flags;
			uint32_t        num_data_directories;
		};

		enum directory_id : uint8_t
		{
			exports =           0,
			import =            1,
			resource =          2,
			exception =         3,
			security =          4,
			basereloc =         5,
			debug =             6,
			architecture =      7,
			globalptr =         8,
			tls =               9,
			load_config =       10,
			bound_import =      11,
			iat =               12,
			delay_import =      13,
			com_descriptor =    14,
			reserved =          15,
		};

		struct data_directory_t
		{
			uint32_t	rva;
			uint32_t	size;
		};

		struct section_name_t
		{
			char		short_name[8];

			std::string to_string(string_table *table) const
			{
				if (table && short_name[0] == '/') {
					char *end = (char *)std::end(short_name);
					return table->resolve(strtoll(short_name + 1, &end, 10));
				}

				size_t len = 0;
				while (len < std::size(short_name) && short_name[len]) len++;
				return { short_name, len };
			};
		};

		union section_characteristics_t
		{
			uint32_t flags;
			struct
			{
				uint32_t _pad0                  : 5;
				uint32_t cnt_code               : 1;
				uint32_t cnt_init_data          : 1;
				uint32_t cnt_uninit_data        : 1;
				uint32_t _pad1                  : 1;
				uint32_t lnk_info               : 1;
				uint32_t _pad2                  : 1;
				uint32_t lnk_remove             : 1;
				uint32_t lnk_comdat             : 1;
				uint32_t _pad3                  : 1;
				uint32_t no_defer_spec_exc      : 1;
				uint32_t mem_far                : 1;
				uint32_t _pad4                  : 1;
				uint32_t mem_purgeable          : 1;
				uint32_t mem_locked             : 1;
				uint32_t mem_preload            : 1;
				uint32_t alignment              : 4;
				uint32_t lnk_nreloc_ovfl        : 1;
				uint32_t mem_discardable        : 1;
				uint32_t mem_not_cached         : 1;
				uint32_t mem_not_paged          : 1;
				uint32_t mem_shared             : 1;
				uint32_t mem_execute            : 1;
				uint32_t mem_read               : 1;
				uint32_t mem_write              : 1;
			};
		};

		struct section_header_t
		{
			section_name_t  name;
			union
			{
				uint32_t    physical_address;
				uint32_t    virtual_size;
			};
			uint32_t        virtual_address;
			uint32_t        size_raw_data;
			uint32_t        ptr_raw_data;
			uint32_t        ptr_relocs;
			uint32_t        ptr_line_numbers;
			uint16_t        num_relocs;
			uint16_t        num_line_numbers;
			section_characteristics_t        characteristics;
		};

		struct import_directory_t
		{
			union
			{
				uint32_t  characteristics;
				uint32_t  rva_original_first_thunk;
			};
			uint32_t      timedate_stamp;
			uint32_t      forwarder_chain;
			uint32_t      rva_name;
			uint32_t      rva_first_thunk;
		};

		struct image_thunk_data_64_t
		{
			union
			{
				uint64_t        forwarder_string;
				uint64_t        function;
				uint64_t        address;
				struct
				{
					uint64_t    ordinal : 16;
					uint64_t    reserved : 47;
					uint64_t    is_ordinal : 1;
				};
			};
		};

		struct image_thunk_data_32_t
		{
			union
			{
				uint32_t        forwarder_string;
				uint32_t        function;
				uint32_t        address;
				struct
				{
					uint32_t    ordinal : 16;
					uint32_t    reserved : 15;
					uint32_t    is_ordinal : 1;
				};
			};
		};

		struct export_directory_t
		{
			uint32_t                    characteristics;
			uint32_t                    timedate_stamp;
			ex_version_t                version;
			uint32_t                    name;
			uint32_t                    base;
			uint32_t                    num_functions;
			uint32_t                    num_names;
			uint32_t                    rva_functions;
			uint32_t                    rva_names;
			uint32_t                    rva_name_ordinals;
		};

		struct reloc_directory_t
		{
			uint32_t        rva;
			uint32_t        size;
		};

		enum class reloc_id_t : uint16_t
		{
			absolute         = 0,
			high             = 1,
			low              = 2,
			highlow          = 3,
			highadj          = 4,
			mips_jmpaddr     = 5,
			mips_jmpaddr16   = 9,
			ia64_imm64       = 9,
			dir64            = 10
		};
		
		struct reloc_value_t
		{
			uint16_t    offset : 12;
			reloc_id_t  type : 4;
		};

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

			std::string to_string(string_table *table) const
			{
				if (table && !is_short)
					return table->resolve(long_name_offset);
				size_t len = 0;
				while (len < std::size(short_name) && short_name[len]) len++;
				return { short_name, len };
			}
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

		enum class resource_id : uint16_t
		{
			cursor =                    1,
			bitmap =                    2,
			icon =                      3,
			menu =                      4,
			dialog =                    5,
			string =                    6,
			font_dir =                  7,
			font =                      8,
			accelerator =               9,
			rcdata =                    10,
			message_table =             11,
			group_cursor =              12,
			group_icon =                14,
			version =                   16,
			dlg_include =               17,
			plug_play =                 19,
			vxd =                       20,
			ani_cursor =                21,
			ani_icon =                  22,
			html =                      23,
			manifest =                  24,
			dialog_init =               240,
			toolbar =                   241,
		};

		struct rsrc_generic_t
		{
			union
			{
				struct
				{
					uint32_t            offset_name : 31;
					uint32_t            is_named : 1;
				};
				uint16_t                identifier;
			};
			uint32_t                    offset : 31;
			uint32_t                    is_directory : 1;
		};

		struct rsrc_directory_t
		{
			uint32_t                    characteristics;
			uint32_t                    timedate_stamp;
			ex_version_t                version;
			uint16_t                    num_named_entries;
			uint16_t                    num_id_entries;
		};

		struct rsrc_data_t
		{
			uint32_t                    rva_data;
			uint32_t                    size_data;
			uint32_t                    code_page;
			uint32_t                    reserved;
		};

		virtual bool check(base::stream &stream) const;
		virtual std::unique_ptr<base::file> instance() const;
	};
#pragma pack(pop)

	class file;
	class architecture;
	class directory_list;
	class segment_list;
	class import_list;
	class import;

	class directory : public base::load_command
	{
	public:
		directory(directory_list *owner, format::directory_id type);
		directory(directory_list *owner, const directory &src);
		std::unique_ptr<directory> clone(directory_list *owner) const;
		virtual uint64_t address() const { return address_; }
		virtual uint32_t size() const { return size_; }
		virtual size_t type() const { return static_cast<size_t>(type_); }
		virtual std::string name() const;
		void load(architecture &file);
	private:
		format::directory_id type_;
		uint64_t address_;
		uint32_t size_;
	};

	class directory_list : public base::load_command_list_t<directory>
	{
	public:
		using base::load_command_list_t<directory>::load_command_list_t;
		directory_list(architecture *owner, const directory_list &src);
		std::unique_ptr<directory_list> clone(architecture *owner) const;
		void load(architecture &file, size_t count);
		template <typename... Args>
		directory &add(Args&&... params) { return base::load_command_list::add<directory>(this, std::forward<Args>(params)...); }
	};

	class segment : public base::segment
	{
	public:
		using base::segment::segment;
		segment(segment_list *owner, const segment &src);
		std::unique_ptr<segment> clone(segment_list *owner) const;
		void load(architecture &file, string_table *table);
		virtual uint64_t address() const { return address_; }
		virtual uint64_t size() const { return size_; }
		virtual uint32_t physical_offset() const { return physical_offset_; }
		virtual uint32_t physical_size() const { return physical_size_; }
		virtual std::string name() const { return name_; }
		virtual base::memory_type_t memory_type() const;
	private:
		uint64_t address_;
		uint32_t size_;
		uint32_t physical_offset_;
		uint32_t physical_size_;
		format::section_characteristics_t characteristics_;
		std::string name_;
	};

	class segment_list : public base::segment_list_t<segment>
	{
	public:
		using base::segment_list_t<segment>::segment_list_t;
		segment_list(architecture *owner, const segment_list &src);
		std::unique_ptr<segment_list> clone(architecture *owner) const;
		void load(architecture &file, size_t count, string_table *string_table);
	};

	class section_list : public base::section_list
	{
	};

	class import_function : public base::import_function
	{
	public:
		import_function(import *owner, uint64_t address);
		bool load(architecture &file);
		virtual uint64_t address() const { return address_; }
		virtual std::string name() const { return name_; }
		virtual std::string version() const { return {}; }
	private:
		uint64_t address_;
		std::string name_;
		bool is_ordinal_;
		uint32_t ordinal_;
	};

	class import : public base::import
	{
	public:
		using base::import::import;
		template <typename... Args>
		import_function & add(Args&&... params) { return base::import::add<import_function>(this, std::forward<Args>(params)...); }
		bool load(architecture &file);
		virtual std::string name() const { return name_; }
	private:
		std::string name_;
	};

	class import_list : public base::import_list
	{
	public:
		using base::import_list::import_list;
		template <typename... Args>
		import &add(Args&&... params) { return base::import_list::add<import>(this, std::forward<Args>(params)...); }
		void load(architecture &file);
	};

	class export_symbol : public base::export_symbol
	{
	public:
		export_symbol(uint64_t address, uint32_t ordinal) : address_(address), ordinal_(ordinal) {}
		void load(architecture &file, uint64_t name_address, bool is_forwarded);
		virtual uint64_t address() const { return address_; }
		virtual std::string name() const { return name_; }
		uint32_t ordinal() const { return ordinal_; }
	private:
		uint64_t address_;
		uint32_t ordinal_;
		std::string name_;
		std::string forwarded_;
	};

	class export_list : public base::export_list
	{
		using iterator = _CastIterator<list::iterator, export_symbol>;
		using const_iterator = _CastIterator<list::const_iterator, const export_symbol>;
		iterator begin() { return list::begin(); }
		iterator end() { return list::end(); }
		const_iterator begin() const { return list::begin(); }
		const_iterator end() const { return list::end(); }
	public:
		void load(architecture &file);
		template <typename... Args>
		export_symbol &add(Args&&... params) { return base::export_list::add<export_symbol>(std::forward<Args>(params)...); }
	};

	class reloc : public base::reloc
	{
	public:
		using base::reloc::reloc;
		reloc(uint64_t address, format::reloc_id_t type) : address_(address), type_(type) {}
		virtual uint64_t address() const { return address_; }
	private:
		uint64_t address_;
		format::reloc_id_t type_;
	};

	class reloc_list : public base::reloc_list
	{
	public:
		void load(architecture &file);
	};

	class resource : public base::resource_t<resource>
	{
	public:
		void load(architecture &file, uint64_t address, bool is_root = false);
		virtual uint64_t address() const { return address_; }
		virtual uint32_t data_size() const { return size_; }
		virtual std::string name() const { return name_; }
	private:
		uint64_t address_;
		uint32_t size_;
		std::string name_;
		format::resource_id type_;
	};

	class resource_list : public base::resource_list_t<resource>
	{
	public:
		void load(architecture &file);
	};

	class architecture : public base::architecture
	{
	public:
		architecture(file *owner, uint64_t offset, uint64_t size);
		architecture(file *owner, const architecture &src);
		virtual std::unique_ptr<base::architecture> clone(file *owner) const;
		virtual std::string name() const;
		virtual base::status load();
		virtual uint64_t image_base() const { return image_base_; }
		virtual uint64_t entry_point() const { return entry_point_; }
		virtual base::operand_size address_size() const { return address_size_; }
		virtual directory_list &commands() const { return *directory_list_; }
		virtual segment_list &segments() const { return *segment_list_; }
		virtual section_list &sections() const { return *section_list_; }
		virtual import_list &imports() const { return *import_list_; }
		virtual export_list &exports() const { return *export_list_; }
		virtual reloc_list &relocs() const { return *reloc_list_; }
		virtual resource_list &resources() const { return *resource_list_; }
	private:
		format::machine_id machine_;
		uint64_t image_base_;
		uint64_t entry_point_;
		format::subsystem_id subsystem_;
		base::operand_size address_size_;
		std::unique_ptr<directory_list> directory_list_;
		std::unique_ptr<segment_list> segment_list_;
		std::unique_ptr<import_list> import_list_;
		std::unique_ptr<export_list> export_list_;
		std::unique_ptr<section_list> section_list_;
		std::unique_ptr<reloc_list> reloc_list_;
		std::unique_ptr<resource_list> resource_list_;
	};

	class file : public base::file
	{
	public:
		virtual std::string format() const { return "PE"; }
		virtual base::status load();
	};
}