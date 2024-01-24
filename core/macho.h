#pragma once

namespace macho
{
	class format : public base::format
	{
	public:
		virtual bool check(base::stream &stream) const;
		virtual std::unique_ptr<base::file> instance() const;

		static constexpr uint32_t fat_magic = 0xcafebabe;
		static constexpr uint32_t fat_cigam = 0xbebafeca;
		static constexpr uint32_t signature = 0xfeedface;
		static constexpr uint32_t signature_64 = 0xfeedfacf;

		enum class cpu_type_id : uint32_t
		{
			any = (uint32_t)-1,
			vax = 1,
			romp = 2,
			ns32032 = 4,
			ns32332 = 5,
			mc680x0 = 6,
			i386 = 7,
			x86_64 = (i386 | 0x01000000),
			mips = 8,
			ns32532 = 9,
			hppa = 11,
			arm = 12,
			mc88000 = 13,
			sparc = 14,
			i860 = 15,
			i860_little = 16,
			rs6000 = 17,
			mc98000 = 18,
			powerpc = 18,
			powerpc64 = (powerpc | 0x01000000),
			arm64 = (arm | 0x01000000)
		};

		enum class cpu_subtype_id : uint32_t
		{
			multiple	= (uint32_t)-1,
			little_endian = 0,
			big_endian = 1,
			vax_all	= 0, 
			vax780	= 1,
			vax785	= 2,
			vax750	= 3,
			vax730	= 4,
			uvaxi	= 5,
			uvaxii	= 6,
			vax8200	= 7,
			vax8500	= 8,
			vax8600	= 9,
			vax8650	= 10,
			vax8800	= 11,
			uvaxiii	= 12,
			rt_all	= 0,
			rt_pc	= 1,
			rt_apc	= 2,
			rt_135	= 3,
			mmax_all	    = 0,
			mmax_dpc	    = 1,
			sqt		    = 2,
			mmax_apc_fpu    = 3,
			mmax_apc_fpa    = 4,
			mmax_xpc	    = 5,
			mc680x0_all		= 1,
			mc68030		= 1,
			mc68040		= 2, 
			mc68030_only	= 3,
			hppa_all		= 0,
			hppa_7100		= 0, /* compat */
			hppa_7100lc		= 1,
			arm_all		= 0,
			arm_a500_arch	= 1,
			arm_a500		= 2,
			arm_a440		= 3,
			arm_m4		= 4,
			arm_v4t		= 5,
			arm_v6		= 6,
			arm_v5tej		= 7,
			arm_xscale		= 8,
			arm_v7		= 9,
			arm_v7f		= 10,
			arm_v7s = 11,
			arm_v7k		= 12,
			arm_v8 = 13,
			arm_v6m = 14, /* not meant to be run under xnu */
			arm_v7m = 15,
			arm_v7em = 16,
			mmax_jpc	= 1,
			mc98000_all	= 0,
			mc98601	= 1,
			i860_all	= 0,
			i860_860	= 1,
			i860_little_all	= 0,
			i860_little	= 1,
			rs6000_all	= 0,
			rs6000	= 1,
			sun4_all		= 0,
			sun4_260		= 1,
			sun4_110		= 2,
			sparc_all		= 0,
			powerpc_all		= 0,
			powerpc_601		= 1,
			powerpc_602		= 2,
			powerpc_603		= 3,
			powerpc_603e	= 4,
			powerpc_603ev	= 5,
			powerpc_604		= 6,
			powerpc_604e	= 7,
			powerpc_620		= 8,
			powerpc_750		= 9,
			powerpc_7400	= 10,
			powerpc_7450	= 11,
			powerpc_970		= 100,
			veo_1	= 1,
			veo_2	= 2,
			veo_3	= 3,
			veo_4	= 4,
			i386_all = 3,
			i386 = 3 + (0 << 4),
			i486 = 4 + (0 << 4),
			i486sx = 4 + (8 << 4),
			i586 = 5 + (0 << 4),
			pent = 5 + (0 << 4),
			pentpro	= 6 + (1 << 4),
			pentii_m3	= 6 + (3 << 4),
			pentii_m5	= 6 + (5 << 4),
			celeron				= 7 + (6 << 4),
			celeron_mobile		= 7 + (7 << 4),
			pentium_3			= 8 + (0 << 4),
			pentium_3_m			= 8 + (1 << 4),
			pentium_3_xeon		= 8 + (2 << 4),
			pentium_m			= 9 + (0 << 4),
			pentium_4			= 10 + (0 << 4),
			pentium_4_m			= 10 + (1 << 4),
			itanium				= 11 + (0 << 4),
			itanium_2			= 11 + (1 << 4),
			xeon				= 12 + (0 << 4),
			xeon_mp				= 12 + (1 << 4),
			x86_all		= 3,
			x86_64_all		= 3,
			x86_arch1		= 4,
			mips_all	= 0,
			mips_r2300	= 1,
			mips_r2600	= 2,
			mips_r2800	= 3,
			mips_r2000a	= 4,
			mips_r2000	= 5,
			mips_r3000a	= 6,
			mips_r3000	= 7,
			mc88000_all	= 0,
			mc88100	= 1,
			mc88110	= 2,
			arm64_all = 0,
			arm64_v8 = 1,
		};

		struct fat_header_t
		{
			uint32_t    magic;
			uint32_t    nfat_arch;
		};

		struct fat_arch_t
		{
			cpu_type_id	cputype;
			uint32_t	cpusubtype;
			uint32_t	offset;
			uint32_t	size;
			uint32_t	align;
		};

		struct mach_header_t
		{
			uint32_t	magic;
			cpu_type_id	cputype;
			cpu_subtype_id	cpusubtype;
			uint32_t	filetype;
			uint32_t	ncmds;
			uint32_t	sizeofcmds;
			uint32_t	flags;
		};

		enum class command_type_id : uint32_t
		{
			segment	= 0x1,
			symtab = 0x2,
			symseg = 0x3,
			thread = 0x4,
			unixthread = 0x5,
			loadfvmlib = 0x6,
			idfvmlib = 0x7,
			ident = 0x8,
			fvmfile = 0x9,
			prepage = 0xa,
			dysymtab = 0xb,
			load_dylib = 0xc,
			id_dylib = 0xd,
			load_dylinker = 0xe,
			id_dylinker = 0xf,
			prebound_dylib = 0x10,
			routines = 0x11,
			sub_framework = 0x12,
			sub_umbrella = 0x13,
			sub_client = 0x14,
			sub_library = 0x15,
			twolevel_hints = 0x16,
			prebind_cksum = 0x17,
			req_dyld = 0x80000000,
			load_weak_dylib = (0x18 | req_dyld),
			segment_64 = 0x19,
			routines_64	= 0x1a,
			uuid = 0x1b,
			rpath = (0x1c | req_dyld),
			code_signature = 0x1d,
			segment_split_info = 0x1e,
			reexport_dylib = (0x1f | req_dyld),
			lazy_load_dylib = 0x20,
			encryption_info = 0x21,
			dyld_info = 0x22,
			dyld_info_only = (0x22 | req_dyld),
			load_upward_dylib = (0x23 | req_dyld),
			version_min_macosx = 0x24,
			version_min_iphoneos = 0x25,
			function_starts = 0x26,
			dyld_environment = 0x27,
			main  = (0x28 | req_dyld),
			data_in_code = 0x29,
			source_version = 0x2a,
			dylib_code_sign_drs = 0x2b,
			encryption_info_64 = 0x2c,
			linker_option = 0x2d,
			linker_optimization_hint = 0x2e,
			version_min_tvos = 0x2f,
			version_min_watchos = 0x30,
			note = 0x31,
			build_version = 0x32,
			dyld_exports_trie = (0x33 | req_dyld),
			dyld_chained_fixups = (0x34 | req_dyld),
		};

		struct load_command_t
		{
			command_type_id cmd;
			uint32_t cmdsize;
		};
	};

	using cpu_type_id = format::cpu_type_id;
	using cpu_subtype_id = format::cpu_subtype_id;
	using command_type_id = format::command_type_id;

	class file;
	class architecture;

	class load_command : public base::load_command
	{
	public:
		using base::load_command::load_command;
		void load(architecture &file);
		virtual uint64_t address() const { return address_; }
		virtual uint32_t size() const { return size_; }
		virtual size_t type() const { return static_cast<size_t>(type_); }
		virtual std::string name() const;
	private:
		uint64_t address_;
		uint32_t size_;
		command_type_id type_;
	};

	class load_command_list : public base::load_command_list
	{
	public:
		using base::load_command_list::load_command_list;
		void load(architecture &file, size_t count);
	};

	class segment_list : public base::segment_list
	{
	public:
		using base::segment_list::segment_list;
	};

	class section_list : public base::section_list
	{
	};

	class symbol_list
	{
	};

	class import_list : public base::import_list
	{
	public:
		using base::import_list::import_list;
	};

	class export_list : public base::export_list
	{

	};

	class reloc_list : public base::reloc_list
	{
	};

	class resource_list : public base::resource_list
	{
	};

	class architecture : public base::architecture
	{
	public:
		architecture(file *owner, uint64_t offset, uint64_t size);
		base::status load();
		virtual std::string name() const;
		virtual base::operand_size address_size() const { return address_size_; }
		virtual load_command_list &commands() const { return *load_command_list_; }
		virtual segment_list &segments() const { return *segment_list_; }
		virtual import_list &imports() const { return *import_list_; }
		virtual export_list &exports() const { return *export_list_; }
		virtual section_list &sections() const { return *section_list_; }
		virtual reloc_list &relocs() const { return *reloc_list_; }
		virtual resource_list &resources() const { return *resource_list_; }
	private:
		uint64_t entry_point_;
		cpu_type_id cpu_type_;
		cpu_subtype_id cpu_subtype_;
		base::operand_size address_size_;
		std::unique_ptr<load_command_list> load_command_list_;
		std::unique_ptr<segment_list> segment_list_;
		std::unique_ptr<section_list> section_list_;
		std::unique_ptr<symbol_list> symbol_list_;
		std::unique_ptr<import_list> import_list_;
		std::unique_ptr<export_list> export_list_;
		std::unique_ptr<reloc_list> reloc_list_;
		std::unique_ptr<resource_list> resource_list_;
	};

	class file : public base::file
	{
	public:
		virtual std::string format() const { return "Mach-O"; }
		base::status load();
	};
}
