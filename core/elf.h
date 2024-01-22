#pragma once

namespace elf
{
	class format : public base::format
	{
	public:
		static constexpr uint32_t elf_signature = 0x464c457f;

		enum class class_type_id : uint8_t
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
			class_type_id  eclass;
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

		struct file_header_32_t
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

		struct file_header_64_t
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

		enum class segment_type_id_t : uint32_t
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

		struct segment_header_32_t
		{
			segment_type_id_t  type;
			uint32_t  offset;
			uint32_t  vaddr;
			uint32_t  paddr;
			uint32_t  filesz;
			uint32_t  memsz;
			uint32_t  flags;
			uint32_t  align;
		};

		struct segment_header_64_t
		{
			segment_type_id_t  type;
			uint32_t  flags;
			uint64_t  offset;
			uint64_t  vaddr;
			uint64_t  paddr;
			uint64_t  filesz;
			uint64_t  memsz;
			uint64_t  align;
		};

		enum directory_type_id_t : uint32_t
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

		struct dyn_header_32_t
		{
			directory_type_id_t tag;
			union
			{
				uint32_t val;
				uint32_t ptr;
			};
		};

		struct dyn_header_64_t
		{
			directory_type_id_t tag;
			uint32_t pad;
			union
			{
				uint64_t val;
				uint64_t ptr;
			};
		};

		virtual bool check(base::stream &stream) const;
		virtual std::unique_ptr<base::file> instance() const;
	};

	class file;
	class architecture;

	class segment : public base::segment
	{
	public:
		using base::segment::segment;
		void load(architecture &file);
		format::segment_type_id_t type() const { return type_; }
		virtual uint64_t address() const { return address_; }
		virtual uint64_t size() const { return size_; }
		virtual uint32_t physical_offset() const { return physical_offset_; }
		virtual uint32_t physical_size() const { return physical_size_; }
		virtual std::string name() const;
		virtual base::memory_type_t memory_type() const { return {}; }
	private:
		uint64_t address_;
		uint64_t size_;
		uint32_t physical_offset_;
		uint32_t physical_size_;
		format::segment_type_id_t type_;
		uint32_t flags_;
	};

	class segment_list : public base::segment_list_t<segment>
	{
	public:
		using base::segment_list_t<segment>::segment_list_t;
		void load(architecture &file, size_t count);
		segment *find_type(format::segment_type_id_t type) const;
	};

	class load_command : public base::load_command
	{
	public:
		using base::load_command::load_command;
		void load(architecture &file);
		virtual uint64_t address() const { return value_; }
		virtual uint32_t size() const { return 0; }
		virtual size_t type() const { return type_; }
		virtual std::string name() const;
	private:
		uint32_t type_;
		uint64_t value_;
	};

	class load_command_list : public base::load_command_list
	{
	public:
		using base::load_command_list::load_command_list;
		void load(architecture &file);
	};

	class architecture : public base::architecture
	{
	public:
		architecture(file *owner, uint64_t offset, uint64_t size);
		base::status load();
		virtual std::string name() const;
		virtual load_command_list *commands() const { return load_command_list_.get(); }
		virtual segment_list *segments() const { return segment_list_.get(); }
		virtual base::import_list *imports() const { return nullptr; }
		virtual base::symbol_list *symbols() const { return nullptr; }
		virtual base::export_list *exports() const { return nullptr; }
		virtual base::operand_size address_size() const { return address_size_; }
	private:
		uint64_t entry_point_;
		format::machine_id_t machine_;
		base::operand_size address_size_;
		std::unique_ptr<load_command_list> load_command_list_;
		std::unique_ptr<segment_list> segment_list_;
	};

	class file : public base::file
	{
	public:
		virtual std::string format() const { return "ELF"; }
		virtual base::status load();
	};
}