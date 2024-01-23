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
		load_command_list_ = std::make_unique<dynamic_command_list>(this);
		segment_list_ = std::make_unique<segment_list>(this);
		section_list_ = std::make_unique<section_list>();
		symbol_list_ = std::make_unique<symbol_list>();
		dynamic_symbol_list_ = std::make_unique<dynamic_symbol_list>();
		import_list_ = std::make_unique<import_list>(this);
		export_list_ = std::make_unique<export_list>();
		reloc_list_ = std::make_unique<reloc_list>();
		verneed_list_ = std::make_unique<verneed_list>();
		export_list_ = std::make_unique<export_list>();
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
				address_size_ = base::operand_size::dword;
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
				if (address_size_ == base::operand_size::dword) {
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
		if (file.address_size() == base::operand_size::dword) {
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

	void dynamic_command_list::load(architecture &file)
	{
		if (auto *dynamic = file.segments().find_type(format::segment_id_t::dynamic)) {
			file.seek(dynamic->physical_offset());
			size_t entry_size = (file.address_size() == base::operand_size::dword) ? sizeof(format::dynamic_32_t) : sizeof(format::dynamic_64_t);
			for (uint64_t i = 0; i < dynamic->size(); i += entry_size) {
				auto &item = add<dynamic_command>(this);
				item.load(file);
				if (item.type() == format::dynamic_id_t::null) {
					pop();
					break;
				}
			}
		}
	}

	// load_command

	std::string dynamic_command::name() const
	{
		switch (type_) {
		case format::dynamic_id_t::null: return "DT_NULL";
		case format::dynamic_id_t::needed: return "DT_NEEDED";
		case format::dynamic_id_t::pltrelsz: return "DT_PLTRELSZ";
		case format::dynamic_id_t::pltgot: return "DT_PLTGOT";
		case format::dynamic_id_t::hash: return "DT_HASH";
		case format::dynamic_id_t::strtab: return "DT_STRTAB";
		case format::dynamic_id_t::symtab: return "DT_SYMTAB";
		case format::dynamic_id_t::rela: return "DT_RELA";
		case format::dynamic_id_t::relasz: return "DT_RELASZ";
		case format::dynamic_id_t::relaent: return "DT_RELAENT";
		case format::dynamic_id_t::strsz: return "DT_STRSZ";
		case format::dynamic_id_t::syment: return "DT_SYMENT";
		case format::dynamic_id_t::init: return "DT_INIT";
		case format::dynamic_id_t::fini: return "DT_FINI";
		case format::dynamic_id_t::soname: return "DT_SONAME";
		case format::dynamic_id_t::rpath: return "DT_RPATH";
		case format::dynamic_id_t::symbolic: return "DT_SYMBOLIC";
		case format::dynamic_id_t::rel: return "DT_REL";
		case format::dynamic_id_t::relsz: return "DT_RELSZ";
		case format::dynamic_id_t::relent: return "DT_RELENT";
		case format::dynamic_id_t::pltrel: return "DT_PLTREL";
		case format::dynamic_id_t::debug: return "DT_DEBUG";
		case format::dynamic_id_t::textrel: return "DT_TEXTREL";
		case format::dynamic_id_t::jmprel: return "DT_JMPREL";
		case format::dynamic_id_t::bind_now: return "DT_BIND_NOW";
		case format::dynamic_id_t::init_array: return "DT_INIT_ARRAY";
		case format::dynamic_id_t::fini_array: return "DT_FINI_ARRAY";
		case format::dynamic_id_t::init_arraysz: return "DT_INIT_ARRAYSZ";
		case format::dynamic_id_t::fini_arraysz: return "DT_FINI_ARRAYSZ";
		case format::dynamic_id_t::runpath: return "DT_RUNPATH";
		case format::dynamic_id_t::flags: return "DT_FLAGS";
		case format::dynamic_id_t::preinit_array: return "DT_PREINIT_ARRAY";
		case format::dynamic_id_t::preinit_arraysz: return "DT_PREINIT_ARRAYSZ";
		case format::dynamic_id_t::gnu_hash: return "DT_GNU_HASH";
		case format::dynamic_id_t::relacount: return "DT_RELACOUNT";
		case format::dynamic_id_t::relcount: return "DT_RELCOUNT";
		case format::dynamic_id_t::flags_1: return "DT_FLAGS_1";
		case format::dynamic_id_t::versym: return "DT_VERSYM";
		case format::dynamic_id_t::verdef: return "DT_VERDEF";
		case format::dynamic_id_t::verdefnum: return "DT_VERDEFNUM";
		case format::dynamic_id_t::verneed: return "DT_VERNEED";
		case format::dynamic_id_t::verneednum: return "DT_VERNEEDNUM";
		}
		return base::load_command::name();
	}

	void dynamic_command::load(architecture &file)
	{
		if (file.address_size() == base::operand_size::dword) {
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
		case format::dynamic_id_t::needed:
		case format::dynamic_id_t::rpath:
		case format::dynamic_id_t::runpath:
		case format::dynamic_id_t::soname:
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
		if (file.address_size() == base::operand_size::dword) {
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
		if (auto *strtab = file.commands().find_type(format::dynamic_id_t::strtab)) {
			auto *strsz = file.commands().find_type(format::dynamic_id_t::strsz);
			if (!strsz || !file.seek_address(strtab->value()))
				throw std::runtime_error("Invalid format");
			table_->load(file, (uint32_t)strtab->value());
			for (auto &item : file.commands()) {
				item.load(*table_);
			}
		}

		if (auto *symtab = file.commands().find_type(format::dynamic_id_t::symtab)) {
			uint64_t size = 0;
			size_t entry_size = (file.address_size() == base::operand_size::dword) ? sizeof(format::symbol_32_t) : sizeof(format::symbol_64_t);
			if (auto *hash = file.commands().find_type(format::dynamic_id_t::hash)) {
				if (!file.seek_address(hash->value() + sizeof(uint32_t)))
					throw std::runtime_error("Invalid format");
				size = entry_size * file.read<uint32_t>();
			}
			else if (auto *gnu_hash = file.commands().find_type(format::dynamic_id_t::gnu_hash)) {
				if (!file.seek_address(gnu_hash->value()))
					throw std::runtime_error("Invalid format");

				uint32_t last_sym = 0;
				uint32_t bucket_count = file.read<uint32_t>();
				uint32_t symbol_base = file.read<uint32_t>();
				uint32_t maskwords = file.read<uint32_t>();
				uint32_t shift2 = file.read<uint32_t>();
				uint64_t bucket_pos = file.tell() + maskwords * ((file.address_size() == base::operand_size::dword) ? sizeof(uint32_t) : sizeof(uint64_t));
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
				auto *strtab = file.commands().find_type(format::dynamic_id_t::strtab);
				if (!strtab)
					throw std::runtime_error("Invalid format");
				size = (strtab->value() - symtab->value());
			}
			if (!file.seek_address(symtab->value()))
				throw std::runtime_error("Invalid format");

			for (uint64_t i = 0; i < size; i += entry_size) {
				add().load(file, *table_);
			}

			if (auto *versym = file.commands().find_type(format::dynamic_id_t::versym)) {
				if (!file.seek_address(versym->value()))
					throw std::runtime_error("Invalid format");
				for (auto &item : *this) {
					item.set_version(file.read<uint16_t>());
				}
			}
		}
	}

	// symbol

	void symbol::load(architecture &file, const string_table &table)
	{
		if (file.address_size() == base::operand_size::dword) {
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
			switch (dynamic.type()) {
			case format::dynamic_id_t::needed:
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
		if (file.address_size() == base::operand_size::dword) {
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
		const std::array<std::pair<format::dynamic_id_t, format::dynamic_id_t>, 3> pairs{ {
			{ format::dynamic_id_t::rel, format::dynamic_id_t::relsz },
			{ format::dynamic_id_t::rela, format::dynamic_id_t::relasz },
			{ format::dynamic_id_t::jmprel, format::dynamic_id_t::pltrelsz }
		} };

		for (auto &pair : pairs) {
			if (auto *first = file.commands().find_type(pair.first)) {
				auto *second = file.commands().find_type(pair.second);
				if (!second || !file.seek_address(first->value()))
					throw std::runtime_error("Invalid format");

				bool is_rela;
				switch (pair.first) {
				case format::dynamic_id_t::jmprel:
					{
						auto *pltrel = file.commands().find_type(format::dynamic_id_t::pltrel);
						if (!pltrel)
							throw std::runtime_error("Invalid format");
						is_rela = (pltrel->value() == format::dynamic_id_t::rela);
					}
					break;
				case format::dynamic_id_t::rela:
					is_rela = true;
					break;
				default:
					is_rela = false;
					break;
				}

				size_t entry_size = (file.address_size() == base::operand_size::dword) ? sizeof(format::reloc_32_t) : sizeof(format::reloc_64_t);
				if (is_rela)
					entry_size += (file.address_size() == base::operand_size::dword) ? sizeof(uint32_t) : sizeof(uint64_t);

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
		if (file.address_size() == base::operand_size::dword) {
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
		if (file.address_size() == base::operand_size::dword) {
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
		if (auto *verneed = file.commands().find_type(format::dynamic_id_t::verneed)) {
			auto *verneednum = file.commands().find_type(format::dynamic_id_t::verneednum);
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