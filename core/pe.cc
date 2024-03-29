#include "file.h"
#include "pe.h"
#include "dotnet.h"
#include "utils.h"

namespace pe
{
	// format

	bool format::check(base::stream &stream) const
	{
		stream.seek(0);
		return (stream.read<uint16_t>() == dos_signature);
	}

	std::unique_ptr<base::file> format::instance() const
	{
		return std::make_unique<file>();
	}

	// string_table

	void string_table::load(base::architecture &file)
	{
		uint32_t size = file.read<uint32_t>();
		if (size < sizeof(uint32_t))
			throw std::runtime_error("Invalid offset");
		resize(size);
		file.read(data() + sizeof(uint32_t), this->size() - sizeof(uint32_t));
	}

	std::string string_table::resolve(size_t offset) const
	{
		if (offset < sizeof(uint32_t))
			throw std::runtime_error("Invalid offset");
		auto begin = data() + offset;
		auto end = data() + size();
		for (auto it = begin; it < end; it++) {
			if (*it == 0)
				return { begin, (size_t)(it - begin) };
		}
		return { };
	}

	// file

	base::status file::load()
	{
		auto &pe = add<architecture>(this, 0, size());
		base::status status = pe.load();
		if (status == base::status::success) {
			auto *dir = pe.commands().find_type(directory_id::com_descriptor);
			if (dir && dir->address()) {
				auto &net = add<net::architecture>(pe);
				status = net.load();
			}
		}
		return status;
	}

	// directory

	directory::directory(directory_list *owner, directory_id type)
		: base::load_command(owner), type_(type)
	{

	}

	directory::directory(directory_list *owner, const directory &src)
		: base::load_command(owner)
	{
		*this = src;
	}

	std::unique_ptr<directory> directory::clone(directory_list *owner) const
	{
		return std::make_unique<directory>(owner, *this);
	}

	std::string directory::name() const
	{
		switch (type_) {
		case directory_id::exports: return "Export";
		case directory_id::import: return "Import";
		case directory_id::resource: return "Resource";
		case directory_id::exception: return "Exception";
		case directory_id::security: return "Security";
		case directory_id::basereloc: return "Relocation";
		case directory_id::debug: return "Debug";
		case directory_id::architecture: return "Architecture";
		case directory_id::globalptr: return "GlobalPtr";
		case directory_id::tls: return "Thread Local Storage";
		case directory_id::load_config: return "Load Config";
		case directory_id::bound_import: return "Bound Import";
		case directory_id::iat: return "Import Address Table";
		case directory_id::delay_import: return "Delay Import";
		case directory_id::com_descriptor: return ".NET MetaData";
		}
		return base::load_command::name();
	}

	void directory::load(architecture &file)
	{
		auto data = file.read<format::data_directory_t>();
		address_ = data.rva ? data.rva + file.image_base() : 0;
		size_ = data.size;
	}

	// directory_list

	directory_list::directory_list(architecture *owner, const directory_list &src)
		: base::load_command_list_t<directory>(owner)
	{
		for (auto &item : src) {
			push(item.clone(this));
		}
	}

	std::unique_ptr<directory_list> directory_list::clone(architecture *owner) const
	{
		return std::make_unique<directory_list>(owner, *this);
	}

	void directory_list::load(architecture &file, size_t count)
	{
		for (size_t type = 0; type < count; type++) {
			auto &item = add(static_cast<directory_id>(type));
			item.load(file);
			if (!item.address() && !item.size())
				pop();
		}
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

	void segment::load(architecture &file, string_table *table)
	{
		auto header = file.read<section_header_t>();
		address_ = header.virtual_address + file.image_base();
		size_ = header.virtual_size;
		physical_offset_ = header.ptr_raw_data;
		physical_size_ = header.size_raw_data;
		characteristics_ = header.characteristics;
		name_ = header.name.to_string(table);
	}

	memory_type_t segment::memory_type() const
	{
		memory_type_t res{};
		res.read = characteristics_.mem_read;
		res.write = characteristics_.mem_write;
		res.execute = characteristics_.mem_execute;
		res.discardable = characteristics_.mem_discardable;
		res.not_cached = characteristics_.mem_not_cached;
		res.not_paged = characteristics_.mem_not_paged;
		res.shared = characteristics_.mem_shared;
		res.mapped = true;
		return res;
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

	void segment_list::load(architecture &file, size_t count, string_table *table)
	{
		for (size_t index = 0; index < count; ++index) {
			add().load(file, table);
		}
	}

	// import_function

	import_function::import_function(import *owner, uint64_t address)
		: base::import_function(owner), address_(address)
	{

	}

	bool import_function::load(architecture &file)
	{
		uint64_t value = 0;
		if (file.address_size() == base::operand_size::dword) {
			auto header = file.read<format::image_thunk_data_32_t>();
			if (!header.address)
				return false;

			is_ordinal_ = header.is_ordinal;
			value = is_ordinal_ ? header.ordinal : header.address;
		}
		else {
			auto header = file.read<format::image_thunk_data_64_t>();
			if (!header.address)
				return false;

			is_ordinal_ = header.is_ordinal;
			value = is_ordinal_ ? header.ordinal : header.address;
		}

		if (is_ordinal_) {
			ordinal_ = (uint32_t)value;
			name_ = utils::format("Ordinal: %.4X", ordinal_);
		} else {
			auto position = file.tell();
			if (!file.seek_address(value + file.image_base() + sizeof(uint16_t)))
				throw std::runtime_error("Format error");
			name_ = file.read_string();
			file.seek(position);
		}

		return true;
	}

	// import

	bool import::load(architecture &file)
	{
		auto header = file.read<format::import_directory_t>();
		if (!header.rva_first_thunk)
			return false;

		auto position = file.tell();
		if (!file.seek_address(header.rva_name + file.image_base()))
			throw std::runtime_error("Format error");

		name_ = file.read_string();

		if (!file.seek_address((header.rva_original_first_thunk ? header.rva_original_first_thunk : header.rva_first_thunk) + file.image_base()))
			throw std::runtime_error("Format error");

		uint64_t address = header.rva_first_thunk + file.image_base();
		while (true) {
			if (!add(address).load(file)) {
				pop();
				break;
			}
			address += (file.address_size() == base::operand_size::dword) ? sizeof(uint32_t) : sizeof(uint64_t);
		}

		file.seek(position);
		return true;
	}

	// import_list

	void import_list::load(architecture &file)
	{
		if (auto * dir = file.commands().find_type(directory_id::import)) {
			if (!file.seek_address(dir->address()))
				throw std::runtime_error("Format error");

			while (true) {
				if (!add().load(file)) {
					pop();
					return;
				}
			}
		}
	}

	// export_symbol

	void export_symbol::load(architecture &file, uint64_t name_address, bool is_forwarded)
	{
		if (name_address) {
			if (!file.seek_address(name_address))
				throw std::runtime_error("Format error");
			name_ = file.read_string();
		}

		if (is_forwarded) {
			if (!file.seek_address(address_))
				throw std::runtime_error("Format error");
			forwarded_ = file.read_string();
		}
	}

	// export_list

	void export_list::load(architecture &file)
	{
		if (auto *dir = file.commands().find_type(directory_id::exports)) {
			if (!file.seek_address(dir->address()))
				throw std::runtime_error("Format error");

			auto header = file.read<format::export_directory_t>();
			if (!header.num_functions)
				return;

			std::map<uint32_t, uint32_t> name_map;
			if (header.num_names) {
				if (!file.seek_address(header.rva_names + file.image_base()))
					throw std::runtime_error("Format error");

				std::vector<uint32_t> rva_names;
				rva_names.resize(header.num_names);
				for (size_t i = 0; i < header.num_names; i++) {
					rva_names[i] = file.read<uint32_t>();
				}

				if (!file.seek_address(header.rva_name_ordinals + file.image_base()))
					throw std::runtime_error("Format error");

				for (size_t i = 0; i < header.num_names; i++) {
					name_map[header.base + file.read<uint16_t>()] = rva_names[i];
				}
			}

			if (!file.seek_address(header.rva_functions + file.image_base()))
				throw std::runtime_error("Format error");

			for (uint32_t index = 0; index < header.num_functions; index++) {
				if (uint32_t rva = file.read<uint32_t>()) {
					add(rva + file.image_base(), header.base + index);
				}
			}

			for (auto &item : *this) {
				auto it = name_map.find(item.ordinal());
				item.load(file, (it != name_map.end()) ? it->second + file.image_base() : 0, (item.address() >= dir->address() && item.address() < dir->address() + dir->size()));
			}
		}
	}

	// reloc_list

	void reloc_list::load(architecture &file)
	{
		if (auto *dir = file.commands().find_type(directory_id::basereloc)) {
			if (!file.seek_address(dir->address()))
				throw std::runtime_error("Format error");

			for (uint32_t i = 0; i < dir->size();) {
				auto header = file.read<format::reloc_directory_t>();
				if (!header.size)
					break;

				if (header.size < sizeof(format::reloc_directory_t) || (header.size & 1))
					throw std::runtime_error("Invalid size of the base relocation block");

				size_t count = (header.size - sizeof(format::reloc_directory_t)) / sizeof(format::reloc_value_t);
				for (size_t block = 0; block < count; block++) {
					auto value = file.read<format::reloc_value_t>();
					auto type = value.type;
					if (type != reloc_id::absolute)
						add<reloc>(header.rva + file.image_base() + value.offset, type);
				}
			}
		}
	}
	
	// architecture

	architecture::architecture(file *owner, uint64_t offset, uint64_t size)
		: base::architecture(owner, offset, size)
	{
		machine_ = machine_id::unknown;
		address_size_ = base::operand_size::dword;
		subsystem_ = format::subsystem_id::unknown;
		directory_list_ = std::make_unique<directory_list>(this);
		segment_list_ = std::make_unique<segment_list>(this);
		import_list_ = std::make_unique<import_list>(this);
		export_list_ = std::make_unique<export_list>();
		section_list_ = std::make_unique<section_list>();
		reloc_list_ = std::make_unique<reloc_list>();
		resource_list_ = std::make_unique<resource_list>();
	}

	architecture::architecture(file *owner, const architecture &src)
		: base::architecture(owner, src)
	{
		machine_ = src.machine_;
		address_size_ = src.address_size_;
		subsystem_ = src.subsystem_;
		directory_list_ = std::move(directory_list_->clone(this));
		segment_list_ = std::move(segment_list_->clone(this));
	}

	std::unique_ptr<base::architecture> architecture::clone(file *owner) const
	{
		return std::make_unique<architecture>(owner, *this);
	}

	std::string architecture::name() const
	{
		switch (machine_) {
		case machine_id::i386: return "i386";
		case machine_id::r3000:
		case machine_id::r4000:
		case machine_id::r10000:
		case machine_id::mips16:
		case machine_id::mipsfpu:
		case machine_id::mipsfpu16: return "mips";
		case machine_id::wcemipsv2: return "mips_wce_v2";
		case machine_id::alpha: return "alpha_axp";
		case machine_id::sh3: return "sh3";
		case machine_id::sh3dsp: return "sh3dsp";
		case machine_id::sh3e: return "sh3e";
		case machine_id::sh4: return "sh4";
		case machine_id::sh5: return "sh5";
		case machine_id::arm: return "arm";
		case machine_id::thumb: return "thumb";
		case machine_id::am33: return "am33";
		case machine_id::powerpc:
		case machine_id::powerpcfp: return "ppc";
		case machine_id::ia64: return "ia64";
		case machine_id::alpha64: return "alpha64";
		case machine_id::tricore: return "infineon";
		case machine_id::cef: return "cef";
		case machine_id::ebc: return "ebc";
		case machine_id::amd64: return "amd64";
		case machine_id::m32r: return "m32r";
		case machine_id::cee: return "cee";
		case machine_id::arm64: return "arm64";
		}
		return utils::format("unknown 0x%X", machine_);
	}

	base::status architecture::load()
	{
		seek(0);

		auto dos_header = read<format::dos_header_t>();
		if (dos_header.e_magic != format::dos_signature)
			return base::status::unknown_format;

		seek(dos_header.e_lfanew);
		if (read<uint32_t>() != format::nt_signature)
			return base::status::unknown_format;

		size_t num_data_directories;
		auto file_header = read<format::file_header_t>();
		switch (file_header.machine) {
		case machine_id::i386:
			{
				auto optional = read<format::optional_header_32_t>();
				if (optional.magic != format::hdr32_magic)
					throw std::runtime_error("Format error");
				image_base_ = optional.image_base;
				entry_point_ = optional.entry_point ? optional.entry_point + image_base_ : 0;
				subsystem_ = optional.subsystem;
				address_size_ = base::operand_size::dword;
				num_data_directories = optional.num_data_directories;
			}
			break;
		case machine_id::amd64:
			{
				auto optional = read<format::optional_header_64_t>();
				if (optional.magic != format::hdr64_magic)
					throw std::runtime_error("Format error");
				image_base_ = optional.image_base;
				entry_point_ = optional.entry_point ? optional.entry_point + image_base_ : 0;
				subsystem_ = optional.subsystem;
				address_size_ = base::operand_size::qword;
				num_data_directories = optional.num_data_directories;
			}
			break;
		default:
			return base::status::unsupported_cpu;
		}

		switch (subsystem_) {
		case format::subsystem_id::native:
		case format::subsystem_id::windows_gui:
		case format::subsystem_id::windows_cui:
			break;
		default:
			return base::status::unsupported_subsystem;
		}

		directory_list_->load(*this, num_data_directories);

		machine_ = file_header.machine;

		string_table string_table;
		if (file_header.ptr_symbols) {
			seek(file_header.ptr_symbols + file_header.num_symbols * sizeof(format::symbol_t));
			string_table.load(*this);
		}
		seek(dos_header.e_lfanew + sizeof(uint32_t) + sizeof(format::file_header_t) + file_header.size_optional_header);
		segment_list_->load(*this, file_header.num_sections, &string_table);

		export_list_->load(*this);
		import_list_->load(*this);
		resource_list_->load(*this);
		reloc_list_->load(*this);

		if (file_header.ptr_symbols) {
			seek(file_header.ptr_symbols);
			for (size_t i = 0; i < file_header.num_symbols; i++) {
				auto symbol = read<format::symbol_t>();
				switch (symbol.storage_class) {
				case format::storage_class_id::public_symbol:
				case format::storage_class_id::private_symbol:
					if (symbol.section_index == 0 || symbol.section_index >= segment_list_->size())
						continue;

					map_symbols().add(segment_list_->item(symbol.section_index - 1).address() + symbol.value, symbol.name.to_string(&string_table),
						(symbol.derived_type == format::derived_type_id::function) ? base::symbol_type_id::function : base::symbol_type_id::data);
					break;
				}
			}
		}

		return base::status::success;
	}

	// resource

	void resource::load(architecture &file, uint64_t address, bool is_root)
	{
		auto header = file.read<format::rsrc_generic_t>();
		auto position = file.tell();
		if (header.is_named) {
			if (!file.seek_address(address + header.offset_name))
				throw std::runtime_error("Format error");

			if (auto size = file.read<uint16_t>()) {
				std::vector<char16_t> unicode_name;
				unicode_name.resize(size);
				file.read(unicode_name.data(), size * sizeof(unicode_name[0]));
				name_ = utils::to_utf8(unicode_name.data(), unicode_name.size());
			}
		}
		else {
			if (is_root) {
				type_ = (resource_id)header.identifier;
				switch (type_) {
				case resource_id::cursor: name_ = "Cursor"; break;
				case resource_id::bitmap: name_ = "Bitmap"; break;
				case resource_id::icon: name_ = "Icon"; break;
				case resource_id::menu: name_ = "Menu"; break;
				case resource_id::dialog: name_ = "Dialog"; break;
				case resource_id::string: name_ = "String Table"; break;
				case resource_id::font_dir: name_ = "Font Directory"; break;
				case resource_id::font: name_ = "Font"; break;
				case resource_id::accelerator: name_ = "Accelerators"; break;
				case resource_id::rcdata: name_ = "RCData"; break;
				case resource_id::message_table: name_ = "Message Table"; break;
				case resource_id::group_cursor: name_ = "Cursor Group"; break;
				case resource_id::group_icon: name_ = "Icon Group"; break;
				case resource_id::version: name_ = "Version Info"; break;
				case resource_id::dlg_include: name_ = "DlgInclude"; break;
				case resource_id::plug_play: name_ = "Plug Play"; break;
				case resource_id::vxd: name_ = "VXD"; break;
				case resource_id::ani_cursor: name_ = "Animated Cursor"; break;
				case resource_id::ani_icon: name_ = "Animated Icon"; break;
				case resource_id::html: name_ = "HTML"; break;
				case resource_id::manifest: name_ = "Manifest"; break;
				case resource_id::dialog_init: name_ = "Dialog Init"; break;
				case resource_id::toolbar: name_ = "Toolbar"; break;
				default:
					name_ = utils::format("%d", header.identifier);
					break;
				}
			}
			else {
				name_ = utils::format("%d", header.identifier);
			}
		}

		if (!file.seek_address(address + header.offset))
			throw std::runtime_error("Format error");

		if (header.is_directory) {
			auto header = file.read<format::rsrc_directory_t>();
			for (size_t i = 0; i < header.num_id_entries + header.num_named_entries; i++) {
				add<resource>();
			}
			for (auto &item : *this) {
				item.load(file, address);
			}
		}
		else {
			auto header = file.read<format::rsrc_data_t>();
			address_ = header.rva_data + file.image_base();
			size_ = header.size_data;
		}
		file.seek(position);
	}

	// resource_list

	void resource_list::load(architecture &file)
	{
		if (auto *rsrc = file.commands().find_type(directory_id::resource)) {
			if (!file.seek_address(rsrc->address()))
				throw std::runtime_error("Format error");
			auto header = file.read<format::rsrc_directory_t>();
			for (size_t i = 0; i < header.num_id_entries + header.num_named_entries; i++) {
				add<resource>();
			}
			for (auto &item : *this) {
				item.load(file, rsrc->address(), true);
			}
		}
	}
};