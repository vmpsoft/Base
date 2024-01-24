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
		dynamic_command_list_ = std::make_unique<dynamic_command_list>(this);
		segment_list_ = std::make_unique<segment_list>(this);
		section_list_ = std::make_unique<section_list>();
		symbol_list_ = std::make_unique<symbol_list>();
		dynamic_symbol_list_ = std::make_unique<dynamic_symbol_list>();
		import_list_ = std::make_unique<import_list>(this);
		export_list_ = std::make_unique<export_list>();
		reloc_list_ = std::make_unique<reloc_list>();
		verneed_list_ = std::make_unique<verneed_list>();
		export_list_ = std::make_unique<export_list>();
		resource_list_ = std::make_unique<resource_list>();
	}

	std::string architecture::name() const
	{
		switch (machine_) {
		case machine_id::m32:
		case machine_id::sparc32plus: return "sparc";
		case machine_id::i386: return "i386";
		case machine_id::m68k: return "m68k";
		case machine_id::m88k: return "m88k";
		case machine_id::i486: return "i486";
		case machine_id::i860: return "i860";
		case machine_id::mips:
		case machine_id::mips_rs3_le: return "mips";
		case machine_id::s370: return "s370";
		case machine_id::parisc: return "parisc";
		case machine_id::vpp500: return "vpp500";
		case machine_id::i960: return "i960";
		case machine_id::ppc: return "ppc";
		case machine_id::ppc64: return "ppc64";
		case machine_id::s390: return "s390";
		case machine_id::spu: return "spu";
		case machine_id::v800: return "v800";
		case machine_id::fr20: return "fr20";
		case machine_id::rh32: return "rh32";
		case machine_id::rce: return "rce";
		case machine_id::arm: return "arm";
		case machine_id::alpha: return "alpha";
		case machine_id::sh: return "sh";
		case machine_id::sparcv9: return "sparc9";
		case machine_id::tricore: return "tricore";
		case machine_id::arc: return "arc";
		case machine_id::h8_300: return "h8/300";
		case machine_id::h8_300h: return "h8/300h";
		case machine_id::h8s: return "h8s";
		case machine_id::h8_500: return "h8/500";
		case machine_id::ia_64: return "ia64";
		case machine_id::mips_x: return "mipsx";
		case machine_id::coldfire: return "coldfire";
		case machine_id::m68hc12: return "68hc12";
		case machine_id::mma: return "mma";
		case machine_id::pcp: return "pcp";
		case machine_id::ncpu: return "ncpu";
		case machine_id::ndr1: return "ndr1";
		case machine_id::starcore: return "starcore";
		case machine_id::me16: return "me16";
		case machine_id::st100: return "st100";
		case machine_id::tinyj: return "tinyj";
		case machine_id::x86_64: return "amd64";
		case machine_id::pdsp: return "pdsp";
		case machine_id::pdp10: return "pdp10";
		case machine_id::pdp11: return "pdp11";
		case machine_id::fx66: return "fx66";
		case machine_id::st9plus: return "st9+";
		case machine_id::st7: return "st7";
		case machine_id::aarch64: return "arm64";
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

		uint64_t phoff, shoff;
		uint16_t phnum, shnum, shstrndx;
		switch (ident.eclass) {
		case format::class_id_t::x32:
			{
				auto header = read<format::header_32_t>();
				if (header.version != 1)
					return base::status::invalid_format;

				entry_point_ = header.entry;
				machine_ = header.machine;
				phoff = header.phoff;
				phnum = header.phnum;
				shoff = header.shoff;
				shnum = header.shnum;
				shstrndx = header.shstrndx;
				address_size_ = operand_size::dword;
			}
			break;
		case format::class_id_t::x64:
			{
				auto header = read<format::header_64_t>();
				if (header.version != 1)
					return base::status::invalid_format;

				entry_point_ = header.entry;
				machine_ = header.machine;
				phoff = header.phoff;
				phnum = header.phnum;
				shoff = header.shoff;
				shnum = header.shnum;
				shstrndx = header.shstrndx;
				address_size_ = operand_size::qword;
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
		dynamic_command_list_->load(*this);
		dynamic_symbol_list_->load(*this);
		reloc_list_->load(*this);
		verneed_list_->load(*this);
		import_list_->load(*this);
		export_list_->load(*this);

		if (shnum) {
			string_table table;
			if (shstrndx) {
				uint64_t offset;
				uint32_t size;
				if (address_size_ == operand_size::dword) {
					seek(shoff + shstrndx * sizeof(format::section_32_t));
					auto header = read<format::section_32_t>();
					offset = header.offset;
					size = header.size;
				}
				else {
					seek(shoff + shstrndx * sizeof(format::section_64_t));
					auto header = read<format::section_64_t>();
					offset = header.offset;
					size = (uint32_t)header.size;
				}
				seek(offset);
				table.load(*this, size);
			}
			seek(shoff);
			section_list_->load(*this, shnum, table);
			symbol_list_->load(*this);
		}

		return base::status::success;
	}

	// segment_list

	segment_list::segment_list(architecture *owner, const segment_list &src)
		: base::segment_list_t<segment>(owner)
	{
		for (auto &item : src) {
			push(item.clone(this));
		}
	}

	std::unique_ptr<segment_list> segment_list::clone(architecture *owner) const
	{
		return std::make_unique<segment_list>(owner, *this);
	}

	void segment_list::load(architecture &file, size_t count)
	{
		for (size_t i = 0; i < count; i++) {
			add().load(file);
		}
	}

	segment *segment_list::find_type(format::segment_id_t type) const
	{
		for (auto &item : *this) {
			if (item.type() == type)
				return &item;
		}
		return nullptr;
	}

	// segment

	segment::segment(segment_list *owner, const segment &src)
		: base::segment(owner)
	{
		*this = src;
	}

	std::unique_ptr<segment> segment::clone(segment_list *owner) const
	{
		return std::make_unique<segment>(owner, *this);
	}

	std::string segment::name() const
	{
		switch (type_) {
		case format::segment_id_t::null: return "PT_NULL";
		case format::segment_id_t::load: return "PT_LOAD";
		case format::segment_id_t::dynamic: return "PT_DYNAMIC";
		case format::segment_id_t::interp: return "PT_INTERP";
		case format::segment_id_t::note: return "PT_NOTE";
		case format::segment_id_t::shlib: return "PT_SHLIB";
		case format::segment_id_t::phdr: return "PT_PHDR";
		case format::segment_id_t::tls: return "PT_TLS";
		case format::segment_id_t::gnu_eh_frame: return "PT_GNU_EH_FRAME";
		case format::segment_id_t::gnu_stack: return "PT_GNU_STACK";
		case format::segment_id_t::gnu_relro: return "PT_GNU_RELRO";
		case format::segment_id_t::gnu_property: return "PT_GNU_PROPERTY";
		case format::segment_id_t::pax_flags: return "PT_PAX_FLAGS";
		}
		return utils::format("unknown 0x%X", type_);
	}

	base::memory_type_t segment::memory_type() const
	{
		base::memory_type_t res{};
		res.read = flags_.read;
		res.write = flags_.write;
		res.execute = flags_.execute;
		res.mapped = (type_ == format::segment_id_t::load);
		return res;
	}

	void segment::load(architecture &file)
	{
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::segment_32_t>();
			type_ = header.type;
			address_ = header.paddr;
			size_ = header.memsz;
			physical_offset_ = header.offset;
			physical_size_ = header.filesz;
			flags_ = header.flags;
		}
		else {
			auto header = file.read<format::segment_64_t>();
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

	dynamic_command_list::dynamic_command_list(architecture *owner, const dynamic_command_list &src)
		: load_command_list_t<dynamic_command>(owner)
	{
		for (auto &item : src) {
			push(item.clone(this));
		}
	}

	std::unique_ptr<dynamic_command_list> dynamic_command_list::clone(architecture *owner) const
	{
		return std::make_unique<dynamic_command_list>(owner, *this);
	}

	void dynamic_command_list::load(architecture &file)
	{
		if (auto *dynamic = file.segments().find_type(format::segment_id_t::dynamic)) {
			file.seek(dynamic->physical_offset());
			size_t entry_size = (file.address_size() == operand_size::dword) ? sizeof(format::dynamic_32_t) : sizeof(format::dynamic_64_t);
			for (uint64_t i = 0; i < dynamic->size(); i += entry_size) {
				auto &item = add<dynamic_command>(this);
				item.load(file);
				if (item.type() == dynamic_id::null) {
					pop();
					break;
				}
			}
		}
	}

	// dynamic_command

	dynamic_command::dynamic_command(dynamic_command_list *owner, const dynamic_command &src)
		: base::load_command(owner)
	{
		*this = src;
	}

	std::unique_ptr<dynamic_command> dynamic_command::clone(dynamic_command_list *owner) const
	{
		return std::make_unique<dynamic_command>(owner, *this);
	}

	std::string dynamic_command::name() const
	{
		switch (type_) {
		case dynamic_id::null: return "DT_NULL";
		case dynamic_id::needed: return "DT_NEEDED";
		case dynamic_id::pltrelsz: return "DT_PLTRELSZ";
		case dynamic_id::pltgot: return "DT_PLTGOT";
		case dynamic_id::hash: return "DT_HASH";
		case dynamic_id::strtab: return "DT_STRTAB";
		case dynamic_id::symtab: return "DT_SYMTAB";
		case dynamic_id::rela: return "DT_RELA";
		case dynamic_id::relasz: return "DT_RELASZ";
		case dynamic_id::relaent: return "DT_RELAENT";
		case dynamic_id::strsz: return "DT_STRSZ";
		case dynamic_id::syment: return "DT_SYMENT";
		case dynamic_id::init: return "DT_INIT";
		case dynamic_id::fini: return "DT_FINI";
		case dynamic_id::soname: return "DT_SONAME";
		case dynamic_id::rpath: return "DT_RPATH";
		case dynamic_id::symbolic: return "DT_SYMBOLIC";
		case dynamic_id::rel: return "DT_REL";
		case dynamic_id::relsz: return "DT_RELSZ";
		case dynamic_id::relent: return "DT_RELENT";
		case dynamic_id::pltrel: return "DT_PLTREL";
		case dynamic_id::debug: return "DT_DEBUG";
		case dynamic_id::textrel: return "DT_TEXTREL";
		case dynamic_id::jmprel: return "DT_JMPREL";
		case dynamic_id::bind_now: return "DT_BIND_NOW";
		case dynamic_id::init_array: return "DT_INIT_ARRAY";
		case dynamic_id::fini_array: return "DT_FINI_ARRAY";
		case dynamic_id::init_arraysz: return "DT_INIT_ARRAYSZ";
		case dynamic_id::fini_arraysz: return "DT_FINI_ARRAYSZ";
		case dynamic_id::runpath: return "DT_RUNPATH";
		case dynamic_id::flags: return "DT_FLAGS";
		case dynamic_id::preinit_array: return "DT_PREINIT_ARRAY";
		case dynamic_id::preinit_arraysz: return "DT_PREINIT_ARRAYSZ";
		case dynamic_id::gnu_hash: return "DT_GNU_HASH";
		case dynamic_id::relacount: return "DT_RELACOUNT";
		case dynamic_id::relcount: return "DT_RELCOUNT";
		case dynamic_id::flags_1: return "DT_FLAGS_1";
		case dynamic_id::versym: return "DT_VERSYM";
		case dynamic_id::verdef: return "DT_VERDEF";
		case dynamic_id::verdefnum: return "DT_VERDEFNUM";
		case dynamic_id::verneed: return "DT_VERNEED";
		case dynamic_id::verneednum: return "DT_VERNEEDNUM";
		}
		return base::load_command::name();
	}

	void dynamic_command::load(architecture &file)
	{
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::dynamic_32_t>();
			type_ = header.tag;
			value_ = header.val;
		}
		else {
			auto header = file.read<format::dynamic_64_t>();
			type_ = header.tag;
			value_ = header.val;
		}
	}

	void dynamic_command::load(const string_table &table)
	{
		switch (type_) {
		case dynamic_id::needed:
		case dynamic_id::rpath:
		case dynamic_id::runpath:
		case dynamic_id::soname:
			if (value_ >> 32)
				throw std::runtime_error("Invalid format");
			string_ = table.resolve((uint32_t)value_);
			break;
		}
	}

	// string_table

	void string_table::load(architecture &file, size_t size)
	{
		resize(size);
		file.read(data(), size);
	}

	std::string string_table::resolve(uint32_t offset) const
	{
		if (offset >= size())
			throw std::runtime_error("Invalid index for string table");
		auto begin = data() + offset;
		auto end = data() + size();
		for (auto it = begin; it < end; it++) {
			if (*it == 0)
				return { begin, (size_t)(it - begin) };
		}
		throw std::runtime_error("Invalid format");
	}

	// section_list

	void section_list::load(architecture &file, size_t count, const string_table &table)
	{
		for (size_t  i = 0; i < count; i++) {
			add<section>().load(file, table);
		}
	}

	section *section_list::find_type(format::section_id_t type) const
	{
		for (auto &item : *this) {
			if (item.type() == type)
				return &item;
		}
		return nullptr;
	}

	// section

	void section::load(architecture &file, const string_table &table)
	{
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::section_32_t>();
			address_ = header.addr;
			size_ = header.size;
			physical_offset_ = header.offset;
			name_ = table.resolve(header.name);
			type_ = header.type;
			entsize_ = header.entsize;
			link_ = header.link;
		}
		else {
			auto header = file.read<format::section_64_t>();
			if (header.size >> 32)
				throw std::runtime_error("Section size is too large");
			if (header.offset >> 32)
				throw std::runtime_error("Section offset is too large");
			address_ = header.addr;
			size_ = (uint32_t)header.size;
			physical_offset_ = (uint32_t)header.offset;
			name_ = table.resolve(header.name);
			type_ = header.type;
			entsize_ = (uint32_t)header.entsize;
			link_ = header.link;
		}

		if (address_)
			parent_ = file.segments().find_address(address_);
	}

	// symbol_list

	symbol_list::symbol_list()
	{
		table_ = std::make_unique<string_table>();
	}
	
	void symbol_list::load(architecture &file)
	{
		if (auto *symtab = file.sections().find_type(format::section_id_t::symtab)) {
			if (symtab->link() >= file.sections().size())
				throw std::runtime_error("Invalid section index");
			auto &strtab = file.sections().item(symtab->link());
			file.seek(strtab.physical_offset());
			table_->load(file, (uint32_t)strtab.size());

			file.seek(symtab->physical_offset());
			for (uint64_t i = 0; i < symtab->size(); i += symtab->entsize()) {
				add().load(file, *table_);
			}
		}
	};

	// dynamic_symbol_list

	void dynamic_symbol_list::load(architecture &file)
	{
		if (auto *strtab = file.commands().find_type(dynamic_id::strtab)) {
			auto *strsz = file.commands().find_type(dynamic_id::strsz);
			if (!strsz || !file.seek_address(strtab->value()))
				throw std::runtime_error("Invalid format");
			table_->load(file, (uint32_t)strtab->value());
			for (auto &item : file.commands()) {
				item.load(*table_);
			}
		}

		if (auto *symtab = file.commands().find_type(dynamic_id::symtab)) {
			uint64_t size = 0;
			size_t entry_size = (file.address_size() == operand_size::dword) ? sizeof(format::symbol_32_t) : sizeof(format::symbol_64_t);
			if (auto *hash = file.commands().find_type(dynamic_id::hash)) {
				if (!file.seek_address(hash->value() + sizeof(uint32_t)))
					throw std::runtime_error("Invalid format");
				size = entry_size * file.read<uint32_t>();
			}
			else if (auto *gnu_hash = file.commands().find_type(dynamic_id::gnu_hash)) {
				if (!file.seek_address(gnu_hash->value()))
					throw std::runtime_error("Invalid format");

				uint32_t last_sym = 0;
				uint32_t bucket_count = file.read<uint32_t>();
				uint32_t symbol_base = file.read<uint32_t>();
				uint32_t maskwords = file.read<uint32_t>();
				uint32_t shift2 = file.read<uint32_t>();
				uint64_t bucket_pos = file.tell() + maskwords * ((file.address_size() == operand_size::dword) ? sizeof(uint32_t) : sizeof(uint64_t));
				uint64_t chains_pos = bucket_pos + bucket_count * sizeof(uint32_t);
				file.seek(bucket_pos);
				for (size_t index = 0; index < bucket_count; index++) {
					last_sym = std::max(last_sym, file.read<uint32_t>());
				}
				if (last_sym) {
					if (last_sym < symbol_base)
						throw std::runtime_error("Invalid format");

					file.seek(chains_pos + (last_sym - symbol_base) * sizeof(uint32_t));
					while (true) {
						if (file.read<uint32_t>() & 1)
							break;
						last_sym++;
					}
					size = (last_sym + 1) * entry_size;
				}
			}
			if (!size) {
				auto *strtab = file.commands().find_type(dynamic_id::strtab);
				if (!strtab)
					throw std::runtime_error("Invalid format");
				size = (strtab->value() - symtab->value());
			}
			if (!file.seek_address(symtab->value()))
				throw std::runtime_error("Invalid format");

			for (uint64_t i = 0; i < size; i += entry_size) {
				add().load(file, *table_);
			}

			if (auto *versym = file.commands().find_type(dynamic_id::versym)) {
				if (!file.seek_address(versym->value()))
					throw std::runtime_error("Invalid format");
				for (auto &symbol : *this) {
					symbol.set_version(file.read<uint16_t>());
				}
			}
		}
	}

	// symbol

	void symbol::load(architecture &file, const string_table &table)
	{
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::symbol_32_t>();
			name_ = table.resolve(header.name);
			value_ = header.value;
			info_ = header.info;
			shndx_ = header.shndx;
		}
		else {
			auto header = file.read<format::symbol_64_t>();
			name_ = table.resolve(header.name);
			value_ = header.value;
			info_ = header.info;
			shndx_ = header.shndx;
		}
	}

	// import_function

	import_function::import_function(import *owner, uint64_t address, symbol *symbol, std::string &version)
		: base::import_function(owner), address_(address), symbol_(symbol), version_(version)
	{
		if (symbol_)
			name_ = symbol_->name();
	}

	// import

	import::import(import_list *owner, const std::string &name)
		: base::import(owner), name_(name)
	{

	}

	// import_list

	void import_list::load(architecture &file)
	{
		for (auto &dynamic : file.commands()) {
			if (dynamic.type() == dynamic_id::needed) {
				add(dynamic.string());
				break;
			}
		}

		std::map<symbol *, std::vector<uint64_t>> symbol_map;
		for (auto &reloc : file.relocs()) {
			if (!reloc.symbol())
				continue;

			auto it = symbol_map.find(reloc.symbol());
			if (it != symbol_map.end())
				it->second.push_back(reloc.address());
			else
				symbol_map[reloc.symbol()].push_back(reloc.address());
		}

		std::map<uint16_t, std::pair<std::string, import *>> version_map;
		for (auto &verneed : file.verneeds()) {
			if (auto *item = find_name(verneed.file())) {
				for (auto &vernaux : verneed) {
					version_map[vernaux.version()] = { vernaux.name(), item };
				}
			}
		}

		import *empty = nullptr;
		for (auto &symbol : file.dynsymbols()) {
			if (symbol.bind() == format::symbol_bind_id_t::local)
				continue;

			auto it = symbol_map.find(&symbol);
			if (it == symbol_map.end())
				continue;

			import *item = nullptr;
			std::string version;
			if (symbol.version() > 1) {
				auto it = version_map.find(symbol.version());
				if (it != version_map.end()) {
					item = it->second.second;
					version = it->second.first;
				}
			}
			if (!item) {
				if (!empty)
					empty = &add("");
				item = empty;
			}

			for (auto address : it->second) {
				item->add<import_function>(item, address, &symbol, version);
			}
		}
	}

	// reloc

	void reloc::load(architecture &file, bool is_rela)
	{
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::reloc_32_t>();
			address_ = header.offset;
			type_ = (format::reloc_id_t)header.info;
			if (type_ == format::reloc_id_t::irelative)
				symbol_ = nullptr;
			else {
				size_t ssym = header.info >> 8;
				if (ssym >= file.dynsymbols().size())
					throw std::runtime_error("Invalid symbol index");
				symbol_ = &file.dynsymbols().item(ssym);
			}
			if (is_rela)
				addend_ = file.read<uint32_t>();
		}
		else {
			auto header = file.read<format::reloc_64_t>();
			address_ = header.offset;
			type_ = (format::reloc_id_t)header.type;
			if (type_ == format::reloc_id_t::irelative_64)
				symbol_ = nullptr;
			else {
				if (header.ssym >= file.dynsymbols().size())
					throw std::runtime_error("Invalid symbol index");
				symbol_ = &file.dynsymbols().item(header.ssym);
			}
			if (is_rela)
				addend_ = file.read<uint64_t>();
		}
	}

	// reloc_list

	void reloc_list::load(architecture &file)
	{
		constexpr std::array<std::pair<dynamic_id, dynamic_id>, 3> pairs{ {
			{ dynamic_id::rel, dynamic_id::relsz },
			{ dynamic_id::rela, dynamic_id::relasz },
			{ dynamic_id::jmprel, dynamic_id::pltrelsz }
		} };

		for (auto &pair : pairs) {
			if (auto *first = file.commands().find_type(pair.first)) {
				auto *second = file.commands().find_type(pair.second);
				if (!second || !file.seek_address(first->value()))
					throw std::runtime_error("Invalid format");

				bool is_rela;
				switch (pair.first) {
				case dynamic_id::jmprel:
					{
						auto *pltrel = file.commands().find_type(dynamic_id::pltrel);
						if (!pltrel)
							throw std::runtime_error("Invalid format");
						is_rela = (pltrel->value() == dynamic_id::rela);
					}
					break;
				case dynamic_id::rela:
					is_rela = true;
					break;
				default:
					is_rela = false;
					break;
				}

				size_t entry_size = (file.address_size() == operand_size::dword) ? sizeof(format::reloc_32_t) : sizeof(format::reloc_64_t);
				if (is_rela)
					entry_size += (file.address_size() == operand_size::dword) ? sizeof(uint32_t) : sizeof(uint64_t);

				for (uint64_t i = 0; i < second->value(); i += entry_size) {
					add<reloc>().load(file, is_rela);
				}
			}
		}
	}

	// vernaux

	uint64_t vernaux::load(architecture &file)
	{
		uint64_t next;
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::vernaux_32_t>();
			hash_ = header.hash;
			flags_ = header.flags;
			version_ = header.other;
			name_ = file.dynsymbols().table().resolve(header.name);
			next = header.next;
		}
		else {
			auto header = file.read<format::vernaux_64_t>();
			hash_ = header.hash;
			flags_ = header.flags;
			version_ = header.other;
			name_ = file.dynsymbols().table().resolve(header.name);
			next = header.next;
		}
		return next;
	}

	// verneed

	uint64_t verneed::load(architecture &file)
	{
		uint64_t pos = file.tell();
		size_t count;
		uint64_t offset;
		uint64_t next;
		if (file.address_size() == operand_size::dword) {
			auto header = file.read<format::verneed_32_t>();
			version_ = header.version;
			file_ = file.dynsymbols().table().resolve(header.file);
			count = header.cnt;
			offset = header.aux;
			next = header.next;
		}
		else {
			auto header = file.read<format::verneed_64_t>();
			version_ = header.version;
			file_ = file.dynsymbols().table().resolve(header.file);
			count = header.cnt;
			offset = header.aux;
			next = header.next;
		}

		for (size_t i = 0; i < count; i++) {
			file.seek(pos + offset);
			auto &item = add();
			auto item_next = item.load(file);
			if (!item_next)
				break;

			offset += item_next;
		}

		return next;
	}

	// verneed_list

	void verneed_list::load(architecture &file)
	{
		if (auto *verneed = file.commands().find_type(dynamic_id::verneed)) {
			auto *verneednum = file.commands().find_type(dynamic_id::verneednum);
			if (!verneednum || !file.seek_address(verneed->value()))
				throw std::runtime_error("Invalid format");

			uint64_t pos = file.tell();
			uint64_t offset = 0;
			for (uint64_t i = 0; i < verneednum->value(); i++) {
				file.seek(pos + offset);

				auto &item = add();
				uint64_t next = item.load(file);
				if (!next)
					break;

				offset += next;
			}
		}
	}

	// export_symbol

	export_symbol::export_symbol(symbol *symbol)
		: symbol_(symbol)
	{
		if (symbol_) {
			address_ = symbol_->value();
			name_ = symbol_->name();
		}
	}

	// export_list

	void export_list::load(architecture &file)
	{
		for (auto &symbol : file.dynsymbols()) {
			if (symbol.shndx() 
				&& symbol.bind() == format::symbol_bind_id_t::global 
				&& (symbol.type() == format::symbol_type_id_t::func || symbol.type() == format::symbol_type_id_t::object)) {
				add<export_symbol>(&symbol);
			}
		}
	}
}