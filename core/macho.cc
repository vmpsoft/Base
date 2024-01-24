#include "file.h"
#include "macho.h"
#include "utils.h"

namespace macho
{
	// format

	bool format::check(base::stream &stream) const
	{
		stream.seek(0);

		uint32_t signature = stream.read<uint32_t>();
		return (signature == fat_magic || signature == fat_cigam || signature == signature || signature == signature_64);
	}

	std::unique_ptr<base::file> format::instance() const
	{
		return std::make_unique<file>();
	}

	// file

	base::status file::load()
	{
		auto fat = read<format::fat_header_t>();
		if (fat.magic == format::fat_magic || fat.magic == format::fat_cigam) {
			return base::status::invalid_format;
		}
		else {
			return add<architecture>(this, 0, size()).load();
		}
	}

	// architecture

	architecture::architecture(file *owner, uint64_t offset, uint64_t size)
		: base::architecture(owner, offset, size)
	{
		load_command_list_ = std::make_unique<load_command_list>(this);
		segment_list_ = std::make_unique<segment_list>(this);
		section_list_ = std::make_unique<section_list>();
		symbol_list_ = std::make_unique<symbol_list>();
		import_list_ = std::make_unique<import_list>(this);
		export_list_ = std::make_unique<export_list>();
		reloc_list_ = std::make_unique<reloc_list>();
		export_list_ = std::make_unique<export_list>();
		resource_list_ = std::make_unique<resource_list>();
	}

	std::string architecture::name() const
	{
		struct cpu_info_t
		{
			const char *name;
			cpu_type_id cputype;
			cpu_subtype_id cpusubtype;
		};

		constexpr std::array<cpu_info_t, 53> infos{ {
			{ "any",        cpu_type_id::any, cpu_subtype_id::multiple },
			{ "little",	    cpu_type_id::any, cpu_subtype_id::little_endian },
			{ "big",        cpu_type_id::any, cpu_subtype_id::big_endian },
			{ "ppc64",      cpu_type_id::powerpc64, cpu_subtype_id::powerpc_all },
			{ "x86_64",     cpu_type_id::x86_64, cpu_subtype_id::x86_64_all },
			{ "arm64",      cpu_type_id::arm64, cpu_subtype_id::arm64_all },
			{ "arm64v8",    cpu_type_id::arm64, cpu_subtype_id::arm64_v8 },
			{ "ppc970-64",  cpu_type_id::powerpc64, cpu_subtype_id::powerpc_970 },
			{ "ppc",        cpu_type_id::powerpc, cpu_subtype_id::powerpc_all },
			{ "m68k",       cpu_type_id::mc680x0, cpu_subtype_id::mc680x0_all },
			{ "hppa",       cpu_type_id::hppa, cpu_subtype_id::hppa_all },
			{ "sparc",      cpu_type_id::sparc, cpu_subtype_id::sparc_all },
			{ "m88k",       cpu_type_id::mc88000, cpu_subtype_id::mc88000_all },
			{ "i860",       cpu_type_id::i860, cpu_subtype_id::i860_all },
			{ "arm",        cpu_type_id::arm, cpu_subtype_id::arm_all },
			{ "armv7",      cpu_type_id::arm, cpu_subtype_id::arm_v7 },
			{ "armv7f",     cpu_type_id::arm, cpu_subtype_id::arm_v7f },
			{ "armv7s",     cpu_type_id::arm, cpu_subtype_id::arm_v7s },
			{ "armv7k",     cpu_type_id::arm, cpu_subtype_id::arm_v7k },
			{ "armv7m",     cpu_type_id::arm, cpu_subtype_id::arm_v7m },
			{ "armv7em",    cpu_type_id::arm, cpu_subtype_id::arm_v7em },
			{ "ppc601",     cpu_type_id::powerpc, cpu_subtype_id::powerpc_601 },
			{ "ppc603",     cpu_type_id::powerpc, cpu_subtype_id::powerpc_603 },
			{ "ppc603e",    cpu_type_id::powerpc, cpu_subtype_id::powerpc_603e },
			{ "ppc603ev",   cpu_type_id::powerpc, cpu_subtype_id::powerpc_603ev },
			{ "ppc604",     cpu_type_id::powerpc, cpu_subtype_id::powerpc_604 },
			{ "ppc604e",    cpu_type_id::powerpc, cpu_subtype_id::powerpc_604e },
			{ "ppc750",     cpu_type_id::powerpc, cpu_subtype_id::powerpc_750 },
			{ "ppc7400",    cpu_type_id::powerpc, cpu_subtype_id::powerpc_7400 },
			{ "ppc7450",    cpu_type_id::powerpc, cpu_subtype_id::powerpc_7450 },
			{ "ppc970",     cpu_type_id::powerpc, cpu_subtype_id::powerpc_970 },
			{ "i386",       cpu_type_id::i386, cpu_subtype_id::i386_all },
			{ "i486",       cpu_type_id::i386, cpu_subtype_id::i486 },
			{ "i486sx",     cpu_type_id::i386, cpu_subtype_id::i486sx },
			{ "pentium",    cpu_type_id::i386, cpu_subtype_id::pent },
			{ "i586",       cpu_type_id::i386, cpu_subtype_id::i586 },
			{ "pentpro",    cpu_type_id::i386, cpu_subtype_id::pentpro },
			{ "i686",       cpu_type_id::i386, cpu_subtype_id::pentpro },
			{ "pentiim3",   cpu_type_id::i386, cpu_subtype_id::pentii_m3 },
			{ "pentiim5",   cpu_type_id::i386, cpu_subtype_id::pentii_m5 },
			{ "pentium4",   cpu_type_id::i386, cpu_subtype_id::pentium_4 },
			{ "pentium4m",  cpu_type_id::i386, cpu_subtype_id::pentium_4_m },
			{ "itanium",    cpu_type_id::i386, cpu_subtype_id::itanium },
			{ "itanium2",   cpu_type_id::i386, cpu_subtype_id::itanium_2 },
			{ "xeon",       cpu_type_id::i386, cpu_subtype_id::xeon },
			{ "xeonmp",     cpu_type_id::i386, cpu_subtype_id::xeon_mp },
			{ "m68030",     cpu_type_id::mc680x0, cpu_subtype_id::mc68030_only },
			{ "m68040",     cpu_type_id::mc680x0, cpu_subtype_id::mc68040 },
			{ "hppa7100lc", cpu_type_id::hppa, cpu_subtype_id::hppa_7100lc },
			{ "armv4t",     cpu_type_id::arm, cpu_subtype_id::arm_v4t },
			{ "armv5",      cpu_type_id::arm, cpu_subtype_id::arm_v5tej },
			{ "xscale",     cpu_type_id::arm, cpu_subtype_id::arm_xscale },
			{ "armv6",      cpu_type_id::arm, cpu_subtype_id::arm_v6 },
		} };

		for (auto &info : infos) {
			if (info.cputype == cpu_type_ && info.cpusubtype == cpu_subtype_)
				return { info.name };
		}

		return utils::format("unknown 0x%X", cpu_type_);
	}

	base::status architecture::load()
	{
		seek(0);

		auto header = read<format::mach_header_t>();
		if (header.magic != format::signature && header.magic != format::signature_64)
			return base::status::unknown_format;

		cpu_type_ = header.cputype;
		cpu_subtype_ = header.cpusubtype;
		if (header.magic == format::signature_64) {
			read<uint32_t>();
			address_size_ = base::operand_size::qword;
		}
		else {
			address_size_ = base::operand_size::dword;
		}

		load_command_list_->load(*this, header.ncmds);


		return base::status::success;
	}

	// load_command

	void load_command::load(architecture &file)
	{
		address_ = file.tell();
		auto header = file.read<format::load_command_t>();
		if (header.cmdsize < sizeof(header))
			throw std::runtime_error("Invalid format");
		type_ = header.cmd;
		size_ = header.cmdsize;
		file.seek(address_ + size_);
	}

	std::string load_command::name() const
	{
		switch (type_) {
		case command_type_id::segment: return "LC_SEGMENT";
		case command_type_id::symtab: return "LC_SYMTAB";
		case command_type_id::symseg: return "LC_SYMSEG";
		case command_type_id::thread: return "LC_THREAD";
		case command_type_id::unixthread: return "LC_UNIXTHREAD";
		case command_type_id::loadfvmlib: return "LC_LOADFVMLIB";
		case command_type_id::idfvmlib: return "LC_IDFVMLIB";
		case command_type_id::ident: return "LC_IDENT";
		case command_type_id::fvmfile: return "LC_FVMFILE";
		case command_type_id::prepage: return "LC_PREPAGE";
		case command_type_id::dysymtab: return "LC_DYSYMTAB";
		case command_type_id::load_dylib: return "LC_LOAD_DYLIB";
		case command_type_id::id_dylib: return "LC_ID_DYLIB";
		case command_type_id::load_dylinker: return "LC_LOAD_DYLINKER";
		case command_type_id::id_dylinker: return "LC_ID_DYLINKER";
		case command_type_id::prebound_dylib: return "LC_PREBOUND_DYLIB";
		case command_type_id::routines: return "LC_ROUTINES";
		case command_type_id::sub_framework: return "LC_SUB_FRAMEWORK";
		case command_type_id::sub_umbrella: return "LC_SUB_UMBRELLA";
		case command_type_id::sub_client: return "LC_SUB_CLIENT";
		case command_type_id::sub_library: return "LC_SUB_LIBRARY";
		case command_type_id::twolevel_hints: return "LC_TWOLEVEL_HINTS";
		case command_type_id::prebind_cksum: return "LC_PREBIND_CKSUM";
		case command_type_id::load_weak_dylib: return "LC_LOAD_WEAK_DYLIB";
		case command_type_id::segment_64: return "LC_SEGMENT_64";
		case command_type_id::routines_64: return "LC_ROUTINES_64";
		case command_type_id::uuid: return "LC_UUID";
		case command_type_id::rpath: return "LC_RPATH";
		case command_type_id::code_signature: return "LC_CODE_SIGNATURE";
		case command_type_id::segment_split_info: return "LC_SEGMENT_SPLIT_INFO";
		case command_type_id::dyld_info: return "LC_DYLD_INFO";
		case command_type_id::dyld_info_only: return "LC_DYLD_INFO_ONLY";
		case command_type_id::version_min_macosx: return "LC_VERSION_MIN_MACOSX";
		case command_type_id::function_starts: return "LC_FUNCTION_STARTS";
		case command_type_id::dyld_environment: return "LC_DYLD_ENVIRONMENT";
		case command_type_id::main: return "LC_MAIN";
		case command_type_id::data_in_code: return "LC_DATA_IN_CODE";
		case command_type_id::source_version: return "LC_SOURCE_VERSION";
		case command_type_id::dylib_code_sign_drs: return "LC_DYLIB_CODE_SIGN_DRS";
		case command_type_id::encryption_info_64: return "LC_ENCRYPTION_INFO_64";
		case command_type_id::linker_option: return "LC_LINKER_OPTION";
		case command_type_id::linker_optimization_hint: return "LC_LINKER_OPTIMIZATION_HINT";
		case command_type_id::version_min_tvos: return "LC_VERSION_MIN_TVOS";
		case command_type_id::version_min_watchos: return "LC_VERSION_MIN_WATCHOS";
		case command_type_id::note: return "LC_NOTE";
		case command_type_id::build_version: return "LC_BUILD_VERSION";
		case command_type_id::dyld_exports_trie: return "LC_DYLD_EXPORTS_TRIE";
		case command_type_id::dyld_chained_fixups: return "LC_DYLD_CHAINED_FIXUPS";
		}

		return base::load_command::name();
	}

	// load_command_list

	void load_command_list::load(architecture &file, size_t count)
	{
		uint64_t pos = file.tell();
		for (size_t i = 0; i < count; i++) {
			add<load_command>(this).load(file);
		}
	}

}