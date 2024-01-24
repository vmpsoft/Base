#pragma once

namespace elf
{
	class format : public base::format
	{
	public:
		static constexpr uint32_t elf_signature = 0x464c457f;

		enum class class_id_t : uint8_t
		{
			none,
			x32,
			x64
		};

		enum class osabi_id_t : uint8_t
		{
			none        = 0,
			hpux        = 1,
			netbsd      = 2,
			gnu         = 3,
			solaris     = 6,
			aix         = 7,
			irix        = 8,
			freebsd     = 9,
			tru64       = 10,
			modesto     = 11,
			openbsd     = 12,
			arm_aeabi   = 64,
			arm         = 97,
			standalone  = 255
		};

		enum class machine_id_t : uint16_t
		{
			none          = 0,
			m32           = 1,
			sparc         = 2,
			i386          = 3,
			m68k          = 4,
			m88k          = 5,
			i486          = 6,
			i860          = 7,
			mips          = 8,
			s370          = 9,
			mips_rs3_le   = 10,
			parisc        = 15,
			vpp500        = 17,
			sparc32plus   = 18,
			i960          = 19,
			ppc           = 20,
			ppc64         = 21,
			s390          = 22,
			spu           = 23,
			v800          = 36,
			fr20          = 37,
			rh32          = 38,
			rce           = 39,
			arm           = 40,
			alpha         = 41,
			sh            = 42,
			sparcv9       = 43,
			tricore       = 44,
			arc           = 45,
			h8_300        = 46,
			h8_300h       = 47,
			h8s           = 48,
			h8_500        = 49,
			ia_64         = 50,
			mips_x        = 51,
			coldfire      = 52,
			m68hc12       = 53,
			mma           = 54,
			pcp           = 55,
			ncpu          = 56,
			ndr1          = 57,
			starcore      = 58,
			me16          = 59,
			st100         = 60,
			tinyj         = 61,
			x86_64        = 62,
			pdsp          = 63,
			pdp10         = 64,
			pdp11         = 65,
			fx66          = 66,
			st9plus       = 67,
			st7           = 68,
			m68hc16       = 69,
			m68hc11       = 70,
			m68hc08       = 71,
			m68hc05       = 72,
			svx           = 73,
			st19          = 74,
			vax           = 75,
			cris          = 76,
			javelin       = 77,
			firepath      = 78,
			zsp           = 79,
			mmix          = 80,
			huany         = 81,
			prism         = 82,
			avr           = 83,
			fr30          = 84,
			d10v          = 85,
			d30v          = 86,
			v850          = 87,
			m32r          = 88,
			mn10300       = 89,
			mn10200       = 90,
			pj            = 91,
			openrisc      = 92,
			arc_compact   = 93,
			xtensa        = 94,
			videocore     = 95,
			tmm_gpp       = 96,
			ns32k         = 97,
			tpc           = 98,
			snp1k         = 99,
			st200         = 100,
			ip2k          = 101,
			max           = 102,
			cr            = 103,
			f2mc16        = 104,
			msp430        = 105,
			blackfin      = 106,
			se_c33        = 107,
			sep           = 108,
			arca          = 109,
			unicore       = 110,
			excess        = 111,
			dxp           = 112,
			altera_nios2  = 113,
			crx           = 114,
			xgate         = 115,
			c166          = 116,
			m16c          = 117,
			dspic30f      = 118,
			ce            = 119,
			m32c          = 120,
			tsk3000       = 131,
			rs08          = 132,
			sharc         = 133,
			ecog2         = 134,
			score7        = 135,
			dsp24         = 136,
			videocore3    = 137,
			latticemico32 = 138,
			se_c17        = 139,
			ti_c6000      = 140,
			ti_c2000      = 141,
			ti_c5500      = 142,
			mmdsp_plus    = 160,
			cypress_m8c   = 161,
			r32c          = 162,
			trimedia      = 163,
			hexagon       = 164,
			m8051         = 165,
			stxp7x        = 166,
			nds32         = 167,
			ecog1         = 168,
			ecog1x        = 168,
			maxq30        = 169,
			ximo16        = 170,
			manik         = 171,
			craynv2       = 172,
			rx            = 173,
			metag         = 174,
			mcst_elbrus   = 175,
			ecog16        = 176,
			cr16          = 177,
			etpu          = 178,
			sle9x         = 179,
			l10m          = 180,
			k10m          = 181,
			aarch64       = 183,
			avr32         = 185,
			stm8          = 186,
			tile64        = 187,
			tilepro       = 188,
			cuda          = 190,
			tilegx        = 191,
			cloudshield   = 192,
			corea_1st     = 193,
			corea_2nd     = 194,
			arc_compact2  = 195,
			open8         = 196,
			rl78          = 197,
		};

		struct ident_t
		{
			uint32_t       signature;
			class_id_t  eclass;
			uint8_t        data;
			uint8_t        version;
			osabi_id_t     os_abi;
			uint8_t        abi_version;
			uint8_t        pad[7];
		};

		enum class type_id_t : uint16_t
		{
			none = 0,
			rel = 1,
			exec = 2,
			dyn = 3,
			core = 4
		};

		struct header_32_t
		{
			ident_t        ident;
			type_id_t      type;
			machine_id_t   machine;
			uint32_t       version;
			uint32_t       entry;
			uint32_t       phoff;
			uint32_t       shoff;
			uint32_t       flags;
			uint16_t       ehsize;
			uint16_t       phentsize;
			uint16_t       phnum;
			uint16_t       shentsize;
			uint16_t       shnum;
			uint16_t       shstrndx;
		};

		struct header_64_t
		{
			ident_t        ident;
			type_id_t      type;
			machine_id_t   machine;
			uint32_t       version;
			uint64_t       entry;
			uint64_t       phoff;
			uint64_t       shoff;
			uint32_t       flags;
			uint16_t       ehsize;
			uint16_t       phentsize;
			uint16_t       phnum;
			uint16_t       shentsize;
			uint16_t       shnum;
			uint16_t       shstrndx;
		};

		enum class segment_id_t : uint32_t
		{
			null = 0,
			load = 1,
			dynamic = 2,
			interp = 3,
			note = 4,
			shlib = 5,
			phdr = 6,
			tls = 7,
			loos = 0x60000000,
			hios = 0x6fffffff,
			loproc = 0x70000000,
			hiproc = 0x7fffffff,
			gnu_eh_frame = 0x6474e550,
			sunw_eh_frame = 0x6474e550,
			sunw_unwind = 0x6464e550,
			gnu_stack = 0x6474e551,
			gnu_relro = 0x6474e552,
			gnu_property = 0x6474e553,
			pax_flags = 0x65041580
		};

		struct segment_flags_t
		{
			uint32_t execute  : 1;
			uint32_t write    : 1;
			uint32_t read     : 1;
			uint32_t reserved : 29;
		};

		struct segment_32_t
		{
			segment_id_t     type;
			uint32_t         offset;
			uint32_t         vaddr;
			uint32_t         paddr;
			uint32_t         filesz;
			uint32_t         memsz;
			segment_flags_t  flags;
			uint32_t         align;
		};

		struct segment_64_t
		{
			segment_id_t     type;
			segment_flags_t  flags;
			uint64_t         offset;
			uint64_t         vaddr;
			uint64_t         paddr;
			uint64_t         filesz;
			uint64_t         memsz;
			uint64_t         align;
		};

		enum dynamic_id_t : uint32_t
		{
			null         = 0,
			needed       = 1,
			pltrelsz     = 2,
			pltgot       = 3,
			hash         = 4,
			strtab       = 5,
			symtab       = 6,
			rela         = 7,
			relasz       = 8,
			relaent      = 9,
			strsz        = 10,
			syment       = 11,
			init         = 12,
			fini         = 13,
			soname       = 14,
			rpath        = 15,
			symbolic     = 16,
			rel          = 17,
			relsz        = 18,
			relent       = 19,
			pltrel       = 20,
			debug        = 21,
			textrel      = 22,
			jmprel       = 23,
			bind_now     = 24,
			init_array   = 25,
			fini_array   = 26,
			init_arraysz = 27,
			fini_arraysz = 28,
			runpath      = 29,
			flags        = 30,
			encoding     = 32,
			preinit_array = 32,
			preinit_arraysz = 33,

			loos         = 0x60000000,
			hios         = 0x6fffffff,
			loproc       = 0x70000000,
			hiproc       = 0x7fffffff,
			gnu_hash     = 0x6ffffef5,
			relacount    = 0x6ffffff9,
			relcount     = 0x6ffffffa,
			flags_1      = 0x6ffffffb,
			versym       = 0x6ffffff0,
			verdef       = 0x6ffffffc,
			verdefnum    = 0x6ffffffd,
			verneed      = 0x6ffffffe,
			verneednum   = 0x6fffffff,
		};

		struct dynamic_32_t
		{
			dynamic_id_t tag;
			union
			{
				uint32_t val;
				uint32_t ptr;
			};
		};

		struct dynamic_64_t
		{
			dynamic_id_t tag;
			uint32_t pad;
			union
			{
				uint64_t val;
				uint64_t ptr;
			};
		};

		enum class section_id_t : uint32_t
		{
			null                = 0,
			progbits            = 1,
			symtab              = 2,
			strtab              = 3,
			rela                = 4,
			hash                = 5,
			dynamic             = 6,
			note                = 7,
			nobits              = 8,
			rel                 = 9,
			shlib               = 10,
			dynsym              = 11,
			init_array          = 14,
			fini_array          = 15,
			preinit_array       = 16,
			group               = 17,
			symtab_shndx        = 18,
			loos                = 0x60000000,
			gnu_attributes      = 0x6ffffff5,
			gnu_hash            = 0x6ffffff6,
			gnu_verdef          = 0x6ffffffd,
			gnu_verneed         = 0x6ffffffe,
			gnu_versym          = 0x6fffffff,
			hios                = 0x6fffffff,
			loproc              = 0x70000000,
			arm_exidx           = 0x70000001u,
			arm_preemptmap      = 0x70000002u,
			arm_attributes      = 0x70000003u,
			arm_debugoverlay    = 0x70000004u,
			arm_overlaysection  = 0x70000005u,
			hex_ordered         = 0x70000000,
			x86_64_unwind       = 0x70000001,
			mips_reginfo        = 0x70000006,
			mips_options        = 0x7000000d,
			mips_abiflags       = 0x7000002a,
			hiproc              = 0x7fffffff,
			louser              = 0x80000000,
			hiuser              = 0xffffffff
		};

		struct section_32_t
		{
			uint32_t      name;
			section_id_t  type;
			uint32_t      flags;
			uint32_t      addr;
			uint32_t      offset;
			uint32_t      size;
			uint32_t      link;
			uint32_t      info;
			uint32_t      addralign;
			uint32_t      entsize;
		};

		struct section_64_t
		{
			uint32_t      name;
			section_id_t  type;
			uint64_t      flags;
			uint64_t      addr;
			uint64_t      offset;
			uint64_t      size;
			uint32_t      link;
			uint32_t      info;
			uint64_t      addralign;
			uint64_t      entsize;
		};

		enum class symbol_type_id_t : uint8_t
		{
			notype    = 0,
			object    = 1,
			func      = 2,
			section   = 3,
			file      = 4,
			common    = 5,
			tls       = 6,
			loos      = 7,
			hios      = 8,
			gnu_ifunc = 10,
			loproc    = 13,
			hiproc    = 15
		};

		enum class symbol_bind_id_t : uint8_t
		{
			local      = 0,
			global     = 1,
			weak       = 2,
			gnu_unique = 10,
			loos       = 10,
			hios       = 12,
			loproc     = 13,
			hiproc     = 15
		};

		struct symbol_info_t
		{
			symbol_type_id_t  type : 4;
			symbol_bind_id_t  bind : 4;
		};

		struct symbol_32_t
		{
			uint32_t  name;
			uint32_t  value;
			uint32_t  size;
			symbol_info_t   info;
			uint8_t   other;
			uint16_t  shndx;
		};

		struct symbol_64_t
		{
			uint32_t  name;
			symbol_info_t   info;
			uint8_t   other;
			uint16_t  shndx;
			uint64_t  value;
			uint64_t  size;
		};

		enum class reloc_id_t : uint8_t
		{
			none = 0,
			r32 = 1,
			pc32 = 2,
			got32 = 3,
			plt32 = 4,
			copy = 5,
			glob_dat = 6,
			jmp_slot = 7,
			relative = 8,
			gotoff = 9,
			gotpc = 10,
			irelative_64 = 37,
			irelative = 42
		};

		struct reloc_32_t
		{
			uint32_t offset;
			uint32_t info;
		};

		struct reloc_64_t
		{
			uint64_t offset;
			uint32_t type;
			uint32_t ssym;
		};

		struct verneed_32_t
		{
			uint16_t	version;
			uint16_t	cnt;
			uint32_t	file;
			uint32_t	aux;
			uint32_t	next;
		};

		struct verneed_64_t
		{
			uint16_t	version;
			uint16_t	cnt;
			uint32_t	file;
			uint32_t	aux;
			uint32_t	next;
		};

		struct vernaux_32_t
		{
			uint32_t	hash;
			uint16_t	flags;
			uint16_t	other;
			uint32_t	name;
			uint32_t	next;
		};

		struct vernaux_64_t
		{
			uint32_t	hash;
			uint16_t	flags;
			uint16_t	other;
			uint32_t	name;
			uint32_t	next;
		};

		virtual bool check(base::stream &stream) const;
		virtual std::unique_ptr<base::file> instance() const;
	};

	class file;
	class architecture;
	class segment_list;
	class string_table;
	class import_list;
	class import;
	class symbol;
	class export_list;
	class dynamic_command_list;

	class segment : public base::segment
	{
	public:
		using base::segment::segment;
		segment(segment_list *owner, const segment &src);
		std::unique_ptr<segment> clone(segment_list *owner) const;
		void load(architecture &file);
		format::segment_id_t type() const { return type_; }
		virtual uint64_t address() const { return address_; }
		virtual uint64_t size() const { return size_; }
		virtual uint32_t physical_offset() const { return physical_offset_; }
		virtual uint32_t physical_size() const { return physical_size_; }
		virtual std::string name() const;
		virtual base::memory_type_t memory_type() const;
	private:
		uint64_t address_;
		uint64_t size_;
		uint32_t physical_offset_;
		uint32_t physical_size_;
		format::segment_id_t type_;
		format::segment_flags_t flags_;
	};

	class segment_list : public base::segment_list_t<segment>
	{
	public:
		using base::segment_list_t<segment>::segment_list_t;
		segment_list(architecture *owner, const segment_list &src);
		std::unique_ptr<segment_list> clone(architecture *owner) const;
		void load(architecture &file, size_t count);
		segment *find_type(format::segment_id_t type) const;
	};

	class dynamic_command : public base::load_command
	{
	public:
		using base::load_command::load_command;
		dynamic_command(dynamic_command_list *owner, const dynamic_command &src);
		std::unique_ptr<dynamic_command> clone(dynamic_command_list *owner) const;
		void load(architecture &file);
		void load(const string_table &table);
		virtual uint64_t address() const { return value_; }
		virtual uint32_t size() const { return 0; }
		virtual size_t type() const { return (size_t)type_; }
		virtual std::string name() const;
		uint64_t value() const { return value_; }
		std::string string() const { return string_; }
	private:
		format::dynamic_id_t type_;
		uint64_t value_;
		std::string string_;
	};

	class dynamic_command_list : public base::load_command_list_t<dynamic_command>
	{
	public:
		using base::load_command_list_t<dynamic_command>::load_command_list_t;
		dynamic_command_list(architecture *owner, const dynamic_command_list &src);
		std::unique_ptr<dynamic_command_list> clone(architecture *owner) const;
		void load(architecture &file);
	};

	class string_table : public std::vector<char>
	{
	public:
		void load(architecture &file, size_t size);
		std::string resolve(uint32_t offset) const;
	};

	class section : public base::section
	{
	public:
		void load(architecture &file, const string_table &table);
		virtual uint64_t address() const { return address_; }
		virtual uint64_t size() const { return size_; }
		virtual uint32_t physical_offset() const { return physical_offset_; }
		virtual uint32_t physical_size() const { return size_; }
		virtual std::string name() const { return name_; }
		virtual segment *parent() const { return parent_; }
		format::section_id_t type() const { return type_; }
		uint32_t entsize() const { return entsize_; }
		uint32_t link() const { return link_; }
	private:
		uint64_t address_;
		uint32_t size_;
		uint32_t physical_offset_;
		format::section_id_t type_;
		uint32_t entsize_;
		uint32_t link_;
		std::string name_;
		segment *parent_;

	};

	class section_list : public base::section_list_t<section>
	{
	public:
		void load(architecture &file, size_t count, const string_table &table);
		section *find_type(format::section_id_t type) const;
	};

	class symbol
	{
	public:
		void load(architecture &file, const string_table &table);
		std::string name() const { return name_; }
		uint16_t version() const { return version_; }
		void set_version(uint16_t version) { version_ = version; }
		format::symbol_type_id_t type() const { return info_.type; }
		format::symbol_bind_id_t bind() const { return info_.bind; }
		uint64_t value() const { return value_; }
		uint16_t shndx() const { return shndx_; }
	private:
		std::string name_;
		format::symbol_info_t info_;
		uint16_t version_;
		uint16_t shndx_;
		uint64_t value_;
	};

	class symbol_list : public base::list<symbol>
	{
	public:
		symbol_list();
		void load(architecture &file);
		string_table &table() const { return *table_; }
	protected:
		std::unique_ptr<string_table> table_;
	};

	class dynamic_symbol_list : public symbol_list
	{
	public:
		void load(architecture &file);
	};

	class import_function : public base::import_function
	{
	public:
		import_function(import *owner, uint64_t address, symbol *symbol, std::string &version);
		virtual uint64_t address() const { return address_; }
		virtual std::string name() const { return name_; }
		virtual std::string version() const { return version_; }
	private:
		uint64_t address_;
		std::string name_;
		symbol *symbol_;
		std::string version_;
	};

	class import : public base::import
	{
	public:
		import(import_list *owner, const std::string &name);
		virtual std::string name() const { return name_; }
	private:
		std::string name_;
	};

	class import_list : public base::import_list_t<import>
	{
	public:
		using base::import_list_t<import>::import_list_t;
		template <typename... Args>
		import &add(Args&&... params) { return base::import_list::add<import>(this, std::forward<Args>(params)...); }
		void load(architecture &file);
	};

	class export_symbol : public base::export_symbol
	{
	public:
		export_symbol(symbol *symbol);
		virtual uint64_t address() const { return address_; }
		virtual std::string name() const { return name_; }
	private:
		symbol *symbol_;
		uint64_t address_;
		std::string name_;
	};

	class export_list : public base::export_list
	{
	public:
		using base::export_list::export_list;
		void load(architecture &file);
	};

	class reloc : public base::reloc
	{
	public:
		void load(architecture &file, bool is_rela);
		virtual uint64_t address() const { return address_; }
		format::reloc_id_t type() const { return type_; }
		symbol *symbol() const { return symbol_; }
	private:
		uint64_t address_;
		format::reloc_id_t type_;
		elf::symbol *symbol_;
		uint64_t addend_;
	};

	class reloc_list : public base::reloc_list_t<reloc>
	{
	public:
		void load(architecture &file);
	};

	class vernaux
	{
	public:
		uint64_t load(architecture &file);
		std::string name() const { return name_; }
		uint16_t version() const { return version_; }
	private:
		uint32_t hash_;
		uint16_t flags_;
		uint16_t version_;
		std::string name_;
	};

	class verneed : public base::list<vernaux>
	{
	public:
		uint64_t load(architecture &file);
		uint16_t version() const { return version_; }
		std::string file() const { return file_; }
	private:
		uint16_t version_;
		std::string file_;
	};

	class verneed_list : public base::list<verneed>
	{
	public:
		void load(architecture &file);
	};

	class resource_list : public base::resource_list
	{
	};

	class architecture : public base::architecture
	{
	public:
		architecture(file *owner, uint64_t offset, uint64_t size);
		base::status load();
		dynamic_symbol_list &dynsymbols() const { return *dynamic_symbol_list_; }
		verneed_list &verneeds() const { return *verneed_list_; }
		virtual std::string name() const;
		virtual base::operand_size address_size() const { return address_size_; }
		virtual dynamic_command_list &commands() const { return *dynamic_command_list_; }
		virtual segment_list &segments() const { return *segment_list_; }
		virtual import_list &imports() const { return *import_list_; }
		virtual base::map_symbol_list *symbols() const { return nullptr; }
		virtual export_list &exports() const { return *export_list_; }
		virtual section_list &sections() const { return *section_list_; }
		virtual reloc_list &relocs() const { return *reloc_list_; }
		virtual resource_list &resources() const { return *resource_list_; }
	private:
		uint64_t entry_point_;
		format::machine_id_t machine_;
		base::operand_size address_size_;
		std::unique_ptr<dynamic_command_list> dynamic_command_list_;
		std::unique_ptr<segment_list> segment_list_;
		std::unique_ptr<section_list> section_list_;
		std::unique_ptr<symbol_list> symbol_list_;
		std::unique_ptr<dynamic_symbol_list> dynamic_symbol_list_;
		std::unique_ptr<import_list> import_list_;
		std::unique_ptr<export_list> export_list_;
		std::unique_ptr<reloc_list> reloc_list_;
		std::unique_ptr<verneed_list> verneed_list_;
		std::unique_ptr<resource_list> resource_list_;
	};

	class file : public base::file
	{
	public:
		virtual std::string format() const { return "ELF"; }
		virtual base::status load();
	};
}