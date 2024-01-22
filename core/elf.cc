#include "file.h"
#include "elf.h"
#include "utils.h"

namespace elf
{
	// format

	bool format::check(base::stream &stream) const
	{
		stream.seek(0);

		auto ident = stream.read<ident_t>();
		return (ident.signature == elf_signature);
	}

	std::unique_ptr<base::file> format::instance() const
	{
		return std::make_unique<file>();
	}

	// file

	base::status file::load()
	{
		return add<architecture>(this, 0, size()).load();
	}

	// architecture

	architecture::architecture(file *owner, uint64_t offset, uint64_t size)
		: base::architecture(owner, offset, size)
	{
		load_command_list_ = std::make_unique<load_command_list>(this);
		segment_list_ = std::make_unique<segment_list>(this);
	}

	std::string architecture::name() const
	{
		switch (machine_) {
		case format::machine_id_t::m32:
		case format::machine_id_t::sparc32plus: return "sparc";
		case format::machine_id_t::i386: return "i386";
		case format::machine_id_t::m68k: return "m68k";
		case format::machine_id_t::m88k: return "m88k";
		case format::machine_id_t::i486: return "i486";
		case format::machine_id_t::i860: return "i860";
		case format::machine_id_t::mips:
		case format::machine_id_t::mips_rs3_le: return "mips";
		case format::machine_id_t::s370: return "s370";
		case format::machine_id_t::parisc: return "parisc";
		case format::machine_id_t::vpp500: return "vpp500";
		case format::machine_id_t::i960: return "i960";
		case format::machine_id_t::ppc: return "ppc";
		case format::machine_id_t::ppc64: return "ppc64";
		case format::machine_id_t::s390: return "s390";
		case format::machine_id_t::spu: return "spu";
		case format::machine_id_t::v800: return "v800";
		case format::machine_id_t::fr20: return "fr20";
		case format::machine_id_t::rh32: return "rh32";
		case format::machine_id_t::rce: return "rce";
		case format::machine_id_t::arm: return "arm";
		case format::machine_id_t::alpha: return "alpha";
		case format::machine_id_t::sh: return "sh";
		case format::machine_id_t::sparcv9: return "sparc9";
		case format::machine_id_t::tricore: return "tricore";
		case format::machine_id_t::arc: return "arc";
		case format::machine_id_t::h8_300: return "h8/300";
		case format::machine_id_t::h8_300h: return "h8/300h";
		case format::machine_id_t::h8s: return "h8s";
		case format::machine_id_t::h8_500: return "h8/500";
		case format::machine_id_t::ia_64: return "ia64";
		case format::machine_id_t::mips_x: return "mipsx";
		case format::machine_id_t::coldfire: return "coldfire";
		case format::machine_id_t::m68hc12: return "68hc12";
		case format::machine_id_t::mma: return "mma";
		case format::machine_id_t::pcp: return "pcp";
		case format::machine_id_t::ncpu: return "ncpu";
		case format::machine_id_t::ndr1: return "ndr1";
		case format::machine_id_t::starcore: return "starcore";
		case format::machine_id_t::me16: return "me16";
		case format::machine_id_t::st100: return "st100";
		case format::machine_id_t::tinyj: return "tinyj";
		case format::machine_id_t::x86_64: return "amd64";
		case format::machine_id_t::pdsp: return "pdsp";
		case format::machine_id_t::pdp10: return "pdp10";
		case format::machine_id_t::pdp11: return "pdp11";
		case format::machine_id_t::fx66: return "fx66";
		case format::machine_id_t::st9plus: return "st9+";
		case format::machine_id_t::st7: return "st7";
		case format::machine_id_t::aarch64: return "arm64";
		}
		return utils::format("unknown 0x%x", machine_);
	}

	base::status architecture::load()
	{
		seek(0);

		auto ident = read<format::ident_t>();
		if (ident.signature != format::elf_signature)
			return base::status::unknown_format;

		seek(0);

		uint64_t phoff;
		uint16_t phnum;
		switch (ident.eclass) {
		case format::class_type_id::x32:
			{
				auto header = read<format::file_header_32_t>();
				if (header.version != 1)
					return base::status::invalid_format;

				entry_point_ = header.entry;
				machine_ = header.machine;
				phoff = header.phoff;
				phnum = header.phnum;
				address_size_ = base::operand_size::dword;
			}
			break;
		case format::class_type_id::x64:
			{
				auto header = read<format::file_header_64_t>();
				if (header.version != 1)
					return base::status::invalid_format;

				entry_point_ = header.entry;
				machine_ = header.machine;
				phoff = header.phoff;
				phnum = header.phnum;
				address_size_ = base::operand_size::qword;
			}
			break;
		}

		switch (ident.os_abi) {
		case format::osabi_id_t::none:
		case format::osabi_id_t::gnu:
			// supported type
			break;
		default:
			return base::status::unsupported_subsystem;
		}

		seek(phoff);
		segment_list_->load(*this, phnum);
		load_command_list_->load(*this);

		return base::status::success;
	}

	// segment_list

	void segment_list::load(architecture &file, size_t count)
	{
		for (size_t i = 0; i < count; i++) {
			add().load(file);
		}
	}

	segment *segment_list::find_type(format::segment_type_id_t type) const
	{
		for (auto &item : *this) {
			if (item.type() == type)
				return &item;
		}
		return nullptr;
	}

	// segment

	std::string segment::name() const
	{
		switch (type_) {
		case format::segment_type_id_t::null: return "PT_NULL";
		case format::segment_type_id_t::load: return "PT_LOAD";
		case format::segment_type_id_t::dynamic: return "PT_DYNAMIC";
		case format::segment_type_id_t::interp: return "PT_INTERP";
		case format::segment_type_id_t::note: return "PT_NOTE";
		case format::segment_type_id_t::shlib: return "PT_SHLIB";
		case format::segment_type_id_t::phdr: return "PT_PHDR";
		case format::segment_type_id_t::tls: return "PT_TLS";
		case format::segment_type_id_t::gnu_eh_frame: return "PT_GNU_EH_FRAME";
		case format::segment_type_id_t::gnu_stack: return "PT_GNU_STACK";
		case format::segment_type_id_t::gnu_relro: return "PT_GNU_RELRO";
		case format::segment_type_id_t::gnu_property: return "PT_GNU_PROPERTY";
		case format::segment_type_id_t::pax_flags: return "PT_PAX_FLAGS";
		}
		return utils::format("unknown 0x%X", type_);
	}

	void segment::load(architecture &file)
	{
		if (file.address_size() == base::operand_size::dword) {
			auto header = file.read<format::segment_header_32_t>();
			type_ = header.type;
			address_ = header.paddr;
			size_ = header.memsz;
			physical_offset_ = header.offset;
			physical_size_ = header.filesz;
			flags_ = header.flags;
		}
		else {
			auto header = file.read<format::segment_header_64_t>();
			type_ = header.type;
			address_ = header.paddr;
			if (header.offset >> 32)
				throw std::runtime_error("Segment size is too large");
			if (header.filesz >> 32)
				throw std::runtime_error("Segment offset is too large");
			size_ = header.memsz;
			physical_offset_ = static_cast<uint32_t>(header.offset);
			physical_size_ = static_cast<uint32_t>(header.filesz);
			flags_ = header.flags;
		}
	}

	// load_command_list

	void load_command_list::load(architecture &file)
	{
		auto segment = file.segments()->find_type(format::segment_type_id_t::dynamic);
		if (!segment)
			return;

		file.seek(segment->physical_offset());
		size_t entry_size = (file.address_size() == base::operand_size::dword) ? sizeof(format::dyn_header_32_t) : sizeof(format::dyn_header_64_t);
		for (uint64_t i = 0; i < segment->size(); i += entry_size) {
			auto &item = add<load_command>(this);
			item.load(file);
			if (item.type() == format::directory_type_id_t::null) {
				pop();
				break;
			}
		}
	}

	// load_command

	std::string load_command::name() const
	{
		switch (type_) {
		case format::directory_type_id_t::null: return "DT_NULL";
		case format::directory_type_id_t::needed: return "DT_NEEDED";
		case format::directory_type_id_t::pltrelsz: return "DT_PLTRELSZ";
		case format::directory_type_id_t::pltgot: return "DT_PLTGOT";
		case format::directory_type_id_t::hash: return "DT_HASH";
		case format::directory_type_id_t::strtab: return "DT_STRTAB";
		case format::directory_type_id_t::symtab: return "DT_SYMTAB";
		case format::directory_type_id_t::rela: return "DT_RELA";
		case format::directory_type_id_t::relasz: return "DT_RELASZ";
		case format::directory_type_id_t::relaent: return "DT_RELAENT";
		case format::directory_type_id_t::strsz: return "DT_STRSZ";
		case format::directory_type_id_t::syment: return "DT_SYMENT";
		case format::directory_type_id_t::init: return "DT_INIT";
		case format::directory_type_id_t::fini: return "DT_FINI";
		case format::directory_type_id_t::soname: return "DT_SONAME";
		case format::directory_type_id_t::rpath: return "DT_RPATH";
		case format::directory_type_id_t::symbolic: return "DT_SYMBOLIC";
		case format::directory_type_id_t::rel: return "DT_REL";
		case format::directory_type_id_t::relsz: return "DT_RELSZ";
		case format::directory_type_id_t::relent: return "DT_RELENT";
		case format::directory_type_id_t::pltrel: return "DT_PLTREL";
		case format::directory_type_id_t::debug: return "DT_DEBUG";
		case format::directory_type_id_t::textrel: return "DT_TEXTREL";
		case format::directory_type_id_t::jmprel: return "DT_JMPREL";
		case format::directory_type_id_t::bind_now: return "DT_BIND_NOW";
		case format::directory_type_id_t::init_array: return "DT_INIT_ARRAY";
		case format::directory_type_id_t::fini_array: return "DT_FINI_ARRAY";
		case format::directory_type_id_t::init_arraysz: return "DT_INIT_ARRAYSZ";
		case format::directory_type_id_t::fini_arraysz: return "DT_FINI_ARRAYSZ";
		case format::directory_type_id_t::runpath: return "DT_RUNPATH";
		case format::directory_type_id_t::flags: return "DT_FLAGS";
		case format::directory_type_id_t::preinit_array: return "DT_PREINIT_ARRAY";
		case format::directory_type_id_t::preinit_arraysz: return "DT_PREINIT_ARRAYSZ";
		case format::directory_type_id_t::gnu_hash: return "DT_GNU_HASH";
		case format::directory_type_id_t::relacount: return "DT_RELACOUNT";
		case format::directory_type_id_t::relcount: return "DT_RELCOUNT";
		case format::directory_type_id_t::flags_1: return "DT_FLAGS_1";
		case format::directory_type_id_t::versym: return "DT_VERSYM";
		case format::directory_type_id_t::verdef: return "DT_VERDEF";
		case format::directory_type_id_t::verdefnum: return "DT_VERDEFNUM";
		case format::directory_type_id_t::verneed: return "DT_VERNEED";
		case format::directory_type_id_t::verneednum: return "DT_VERNEEDNUM";
		}
		return base::load_command::name();
	}

	void load_command::load(architecture &file)
	{
		if (file.address_size() == base::operand_size::dword) {
			auto header = file.read<format::dyn_header_32_t>();
			type_ = header.tag;
			value_ = header.val;
		}
		else {
			auto header = file.read<format::dyn_header_64_t>();
			type_ = header.tag;
			value_ = header.val;
		}
	}
}