#include "dotnet.h"
#include "utils.h"

namespace net
{
	std::string symbol_name(const std::string &ret, const std::string &type, const std::string &method, const std::string &signature)
	{
		std::string res;
		if (!ret.empty())
			res += ret + ' ';
		if (!type.empty())
			res += type + "::";
		return res + method + signature;
	}

	// storage

	storage::storage(const uint8_t *data, size_t size)
	{ 
		push(data, size); 
	}

	// storage_view

	storage_view::storage_view(const storage &storage, size_t position)
		: data_(storage.data()), size_(storage.size()), position_(position)
	{

	}

	void storage_view::read(void *buffer, size_t size)
	{
		if (position_ + size > size_)
			throw std::runtime_error("Invalid offset");
		memcpy(buffer, data_ + position_, size);
		position_ += size;
	}

	uint32_t storage_view::read_encoded()
	{
		uint8_t byte = read<uint8_t>();
		if ((byte & 0x80) == 0)
			return byte & 0x7f;
		if ((byte & 0x40) == 0)
			return ((byte & 0x3f) << 8) | read<uint8_t>();
		return ((byte & 0x1f) << 24) | (read<uint8_t>() << 16) | (read<uint8_t>() << 8) | read<uint8_t>();
	}

	std::string storage_view::read_string()
	{
		if (size_t size = read_encoded()) {
			if (position_ + size > size_)
				throw std::runtime_error("Invalid string size");
			return { (const char *)data_ + position_, size };
		}
		return { };
	}

	// architecture

	architecture::architecture(pe::architecture &file)
		: base::architecture(file.owner(), file.offset(), file.size()), file_(file)
	{
		meta_data_ = std::make_unique<meta_data>(this);
		import_list_ = std::make_unique<import_list>(this);
		export_list_ = std::make_unique<export_list>();
		reloc_list_ = std::make_unique<reloc_list>();
		resource_list_ = std::make_unique<resource_list>();
	}

	base::status architecture::load() 
	{
		auto dir = file_.commands().find_type(pe::directory_id::com_descriptor);
		if (!dir || !seek_address(dir->address()))
			return base::status::invalid_format;

		auto header = read<format::cor20_header_t>();
		if (!header.meta_data.rva)
			return base::status::invalid_format;

		meta_data_->load(*this, header.meta_data.rva + image_base());
		import_list_->load(*this);
		resource_list_->load(*this);

		if (header.vtable_fixups.rva) {
			if (!seek_address(header.vtable_fixups.rva + image_base()))
				throw std::runtime_error("Format error");
			reloc_list_->load(*this, header.vtable_fixups.size / sizeof(format::vtable_fixup_t));
		}

		{
			auto *table = commands().table(token_type_id::method_def);
			for (auto &token : *table) {
				auto &method = static_cast<method_def &>(token);
				if (method.declaring_type())
				map_symbols().add(method.address(), method.full_name(), base::symbol_type_id::function);
			}
		}

		return base::status::success;
	}

	// import_function

	import_function::import_function(import *owner, uint32_t token, const std::string &name)
		: base::import_function(owner), token_(token), name_(name)
	{

	}

	// import

	import::import(import_list *owner, const std::string &name)
		: base::import(owner), name_(name)
	{

	}

	// import_list

	void import_list::load(architecture &file)
	{
		std::map<token *, import *> import_map;
		std::map<token *, import *> type_map;

		auto table = file.commands().table(token_type_id::assembly_ref);
		for (auto &token : *table) {
			auto &ref = static_cast<assembly_ref &>(token);
			import *item = find_name(ref.name());
			if (!item)
				item = &add(ref.name());
			import_map[&token] = item;
		}

		table = file.commands().table(token_type_id::module_ref);
		for (auto &token : *table) {
			auto &ref = static_cast<module_ref &>(token);
			import *item = find_name(ref.name());
			if (!item)
				item = &add(ref.name());
			import_map[&token] = item;
		}

		table = file.commands().table(token_type_id::type_ref);
		for (auto &token : *table) {
			auto &ref = static_cast<type_ref &>(token);
			auto it = import_map.find(ref.resolution_scope());
			if (it != import_map.end()) {
				import *item = it->second;
				type_map[&ref] = item;
				item->add(ref.id(), ref.full_name());
			}
		}

		table = file.commands().table(token_type_id::type_spec);
		for (auto &token : *table) {
			auto &ref = static_cast<type_spec &>(token);

			net::token *type = nullptr;
			switch (ref.signature().type()) {
			case element_type_id::genericinst:
				type = ref.signature().next()->token();
				break;
			case element_type_id::valuetype:
			case element_type_id::_class:
				type = ref.signature().token();
				break;
			}

			if (!type || (type->type() != token_type_id::type_ref))
				continue;

			auto it = import_map.find(static_cast<type_ref *>(type)->resolution_scope());
			if (it != import_map.end()) {
				import *item = it->second;
				type_map[&ref] = item;
				item->add(ref.id(), ref.name());
			}
		}

		table = file.commands().table(token_type_id::member_ref);
		for (auto &token : *table) {
			auto &ref = static_cast<member_ref &>(token);
			auto it = type_map.find(ref.declaring_type());
			if (it != type_map.end())
				it->second->add(ref.id(), ref.full_name());
		}

		table = file.commands().table(token_type_id::impl_map);
		for (auto &token : *table) {
			auto &ref = static_cast<impl_map &>(token);
			auto it = import_map.find(ref.import_scope());
			if (it != import_map.end())
				it->second->add(ref.id(), ref.import_name());
		}
	}

	// reloc_list

	void reloc_list::load(architecture &file, size_t count)
	{
		for (size_t i = 0; i < count; i++) {
			auto header = file.read<format::vtable_fixup_t>();
			uint64_t pos = file.tell();
			uint64_t address = header.rva + file.image_base();
			if (!file.seek_address(address))
				throw std::runtime_error("Format error");

			for (size_t j = 0; j < header.count; j++) {
				auto *token = file.commands().find(file.read<uint32_t>());
				if (!token)
					throw std::runtime_error("Format error");
				add<reloc>(address, token);

				address += sizeof(uint32_t);
				if (header.type.x64) {
					file.read<uint32_t>();
					address += sizeof(uint32_t);
				}
			}
			file.seek(pos);
		}
	}

	// resource

	resource::resource(uint32_t id, uint64_t address, uint32_t size, const std::string &name)
		: id_(id), address_(address), size_(size), name_(name)
	{

	}

	// resource_list

	resource *resource_list::find_id(uint32_t id) const
	{
		for (auto &item : *this) {
			if (item.id() == id)
				return &item;
		}
		return nullptr;
	}

	void resource_list::load(architecture &file)
	{
		auto *table = file.commands().table(token_type_id::manifest_resource);
		for (auto &token : *table) {
			auto &item = static_cast<manifest_resource &>(token);
			if (auto *implementation = item.implementation()) {
				auto *folder = find_id(implementation->id());
				if (!folder) {
					switch (implementation->type()) {
					case token_type_id::file:
						folder = &add<resource>(implementation->id(), 0, 0, static_cast<tfile *>(implementation)->name());
						break;
					case token_type_id::assembly_ref:
						folder = &add<resource>(implementation->id(), 0, 0, static_cast<assembly_ref *>(implementation)->name());
						break;
					default:
						continue;
					}
				}
				folder->add<resource>(item.id(), item.offset(), 0, item.name());
			}
			else {
				// TODO
			}
		}
	}

	// meta_data

	void meta_data::load(architecture &file, uint64_t address)
	{
		if (!file.seek_address(address))
			throw std::runtime_error("Invalid meta data address");

		auto header = file.read<format::meta_data_header_t>();
		if (header.signature != format::meta_data_signature)
			throw std::runtime_error("Invalid meta data signature");

		version_.resize(header.version_size);
		file.read((char *)version_.data(), version_.size());
		file.read<uint16_t>();
		size_t stream_count = file.read<uint16_t>();
		for (size_t index = 0; index < stream_count; index++) {
			auto stream_header = file.read<format::stream_header_t>();
			std::string stream_name = file.read_string();
			if (stream_name == "#~" && !heap_)
				heap_ = &add<heap_stream>(address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#Strings" && !strings_)
				strings_ = &add<strings_stream>(address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#US" && !user_strings_)
				user_strings_ = &add<user_strings_stream>(address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#Blob" && !blob_)
				blob_ = &add<blob_stream>(address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#GUID" && !guid_)
				guid_ = &add<guid_stream>(address + stream_header.offset, stream_header.size, stream_name);
			else
				add<stream>(address + stream_header.offset, stream_header.size, stream_name);

			size_t pad = stream_name.size() + 1;
			while (pad & 3) {
				file.read<uint8_t>();
				pad++;
			}
		}

		if (!heap_)
			throw std::runtime_error("Invalid .NET format");

		for (auto &item : *this) {
			if (&item != heap_)
				item.load(file);
		}
		heap_->load(file);

		auto table = this->table(token_type_id::type_def);
		for (auto &item : *table) {
			auto &type = static_cast<type_def &>(item);
			type_def *next = type.next();
			method_def *method_end = next ? next->method_list() : nullptr;
			for (method_def *method = type.method_list(); method && method != method_end; method = method->next())
				method->set_declaring_type(&type);
		}
	}

	table *meta_data::table(token_type_id type) const
	{
		size_t index = (size_t)type;
		return (index < heap_->table_list().size()) ? &heap_->table_list().item(index) : nullptr;
	}

	std::string meta_data::user_string(uint32_t offset) const
	{
		if (!user_strings_)
			throw std::runtime_error("Invalid .NET format");
		return user_strings_->resolve(offset);
	}

	std::string meta_data::string(uint32_t offset) const
	{
		if (!strings_)
			throw std::runtime_error("Invalid .NET format");
		return strings_->resolve(offset);
	}

	storage meta_data::guid(uint32_t offset) const
	{
		if (!offset)
			return storage{ };

		if (!guid_)
			throw std::runtime_error("Invalid .NET format");
		return guid_->resolve(offset - 1);
	}

	storage meta_data::blob(uint32_t offset) const
	{
		if (!offset)
			return storage{ };

		if (!blob_)
			throw std::runtime_error("Invalid .NET format");
		return blob_->resolve(offset);
	}

	token *meta_data::find(token_value_t id) const
	{
		auto table = this->table(id.type);
		if (!table)
			throw std::runtime_error("Invalid token");
		return (id.value >= 1 && id.value <= table->size()) ? &table->item(id.value - 1) : nullptr;
	}

	bool meta_data::field_size(const token_encoding_t &encoding) const
	{
		size_t count = 0;
		for (size_t index = 0; index < encoding.size; index++) {
			token_type_id type = encoding.types[index];
			if (type == token_type_id::invalid)
				continue;

			auto table = this->table(type);
			if (!table)
				throw std::runtime_error("Invalid encoding");
			count = std::max(count, table->size());
		}
		return count >= ((size_t)1 << (16 - encoding.bits));
	}

	bool meta_data::field_size(token_type_id type) const
	{
		auto table = this->table(type);
		if (!table)
			throw std::runtime_error("Invalid table type");
		return table->size() > std::numeric_limits<uint16_t>::max();
	}

	// stream

	stream::stream(meta_data *owner, uint64_t address, uint32_t size, const std::string &name)
		: base::load_command(owner), address_(address), size_(size), name_(name)
	{

	}

	meta_data *stream::owner() const
	{
		return static_cast<meta_data *>(base::load_command::owner());
	}

	// heap_stream

	void heap_stream::load(architecture &file)
	{
		if (!file.seek_address(address()))
			throw std::runtime_error("Invalid stream address");

		auto header = file.read<format::heap_header_t>();
		uint64_t mask = header.mask_valid;
		for (size_t type = 0; type < 64; mask >>= 1, type++) {
			uint32_t token_count = (mask & 1) ? file.read<uint32_t>() : 0;
			table_list_.add<table>(owner(), (token_type_id)type, token_count);
		}

		offset_sizes_ = header.heap_offset_sizes;

		for (auto &table : table_list_) {
			table.load(file);
		}
	}

	// strings_stream

	void strings_stream::load(architecture &file)
	{
		if (!file.seek_address(address()))
			throw std::runtime_error("Invalid stream address");
		data_.resize(stream::size());
		file.read(data_.data(), data_.size());
	}

	std::string strings_stream::resolve(uint32_t offset) const
	{
		auto begin = data_.data() + offset;
		auto end = data_.data() + data_.size();
		for (auto it = begin; it < end; it++) {
			if (*it == 0)
				return { (const char *)begin, (size_t)(it - begin) };
		}
		throw std::runtime_error("Invalid offset");
	}

	// user_strings_stream

	void user_strings_stream::load(architecture &file)
	{
		if (!file.seek_address(address()))
			throw std::runtime_error("Invalid stream address");
		data_.resize(stream::size());
		file.read(data_.data(), data_.size());
	}

	std::string user_strings_stream::resolve(uint32_t offset) const
	{
		storage_view stream(data_, offset);

		size_t size = stream.read_encoded();
		size_t position = stream.tell();
		if (position + size > data_.size())
			throw std::runtime_error("Invalid offset");

		size >>= 1;
		if (!size)
			return { };

		return utils::to_utf8((const char16_t *)data_.data() + offset, size);
	}

	// guid_stream

	void guid_stream::load(architecture &file)
	{
		if (!file.seek_address(address()))
			throw std::runtime_error("Invalid stream address");
		data_.resize(stream::size());
		file.read(data_.data(), data_.size());
	}

	storage guid_stream::resolve(uint32_t offset)
	{
		uint32_t size = 16;
		if (offset + size > data_.size())
			throw std::runtime_error("Invalid offset");

		return storage{ data_.data() + offset, size };
	}

	// blob_stream

	blob_stream::blob_stream(meta_data *owner, uint64_t address, uint32_t size, const std::string &name)
		: stream(owner, address, size, name)
	{

	}

	void blob_stream::load(architecture &file)
	{
		if (!file.seek_address(address()))
			throw std::runtime_error("Invalid stream address");
		data_.resize(stream::size());
		file.read(data_.data(), data_.size());
	}

	storage blob_stream::resolve(uint32_t offset) const
	{
		storage_view stream(data_, offset);
		uint32_t size = stream.read_encoded();
		size_t pos = stream.tell();
		if (pos + size > data_.size())
			throw std::runtime_error("Invalid blob size");
		return storage{ data_.data() + pos, size };
	}

	// table

	table::table(meta_data *owner, token_type_id type, uint32_t token_count)
		: owner_(owner), type_(type)
	{
		token_value_t token_value{};
		token_value.type = type_;
		for (token_value.value = 1; token_value.value <= token_count; token_value.value++) {
			switch (type_) {
			case token_type_id::module: add<module>(owner, token_value); break;
			case token_type_id::type_ref: add<type_ref>(owner, token_value); break;
			case token_type_id::type_def: add<type_def>(owner, token_value); break;
			case token_type_id::field: add<field>(owner, token_value); break;
			case token_type_id::method_def: add<method_def>(owner, token_value); break;
			case token_type_id::param: add<param>(owner, token_value); break;
			case token_type_id::interface_impl: add<interface_impl>(owner, token_value); break;
			case token_type_id::member_ref: add<member_ref>(owner, token_value); break;
			case token_type_id::constant: add<constant>(owner, token_value); break;
			case token_type_id::custom_attribute: add<custom_attribute>(owner, token_value); break;
			case token_type_id::field_marshal: add<field_marshal>(owner, token_value); break;
			case token_type_id::decl_security: add<decl_security>(owner, token_value); break;
			case token_type_id::class_layout: add<class_layout>(owner, token_value); break;
			case token_type_id::field_layout: add<field_layout>(owner, token_value); break;
			case token_type_id::stand_alone_sig: add<stand_alone_sig>(owner, token_value); break;
			case token_type_id::event_map: add<event_map>(owner, token_value); break;
			case token_type_id::event: add<event>(owner, token_value); break;
			case token_type_id::property_map: add<property_map>(owner, token_value); break;
			case token_type_id::property: add<property>(owner, token_value); break;
			case token_type_id::method_semantics: add<method_semantics>(owner, token_value); break;
			case token_type_id::method_impl: add<method_impl>(owner, token_value); break;
			case token_type_id::module_ref: add<module_ref>(owner, token_value); break;
			case token_type_id::type_spec: add<type_spec>(owner, token_value); break;
			case token_type_id::impl_map: add<impl_map>(owner, token_value); break;
			case token_type_id::field_rva: add<field_rva>(owner, token_value); break;
			case token_type_id::enc_log: add<enc_log>(owner, token_value); break;
			case token_type_id::enc_map: add<enc_map>(owner, token_value); break;
			case token_type_id::assembly: add<assembly>(owner, token_value); break;
			case token_type_id::assembly_processor: add<assembly_processor>(owner, token_value); break;
			case token_type_id::assembly_os: add<assembly_os>(owner, token_value); break;
			case token_type_id::assembly_ref: add<assembly_ref>(owner, token_value); break;
			case token_type_id::assembly_ref_processor: add<assembly_ref_processor>(owner, token_value); break;
			case token_type_id::assembly_ref_os: add<assembly_ref_os>(owner, token_value); break;
			case token_type_id::file: add<tfile>(owner, token_value); break;
			case token_type_id::exported_type: add<exported_type>(owner, token_value); break;
			case token_type_id::manifest_resource: add<manifest_resource>(owner, token_value); break;
			case token_type_id::nested_class: add<nested_class>(owner, token_value); break;
			case token_type_id::generic_param: add<generic_param>(owner, token_value); break;
			case token_type_id::method_spec: add<method_spec>(owner, token_value); break;
			case token_type_id::generic_param_constraint: add<generic_param_constraint>(owner, token_value); break;
			default:
				throw std::runtime_error("Unknown token type");
			}
		}
	}

	void table::load(architecture &file)
	{
		for (auto &item : *this) {
			item.load(file);
		}
	}

	// token

	token::token(meta_data *owner, token_value_t value)
		: meta_(owner), value_(value)
	{
	
	}

	std::string token::read_string(architecture &file) const
	{
		return meta_->string(meta_->string_field_size() ? file.read<uint32_t>() : file.read<uint16_t>());
	}

	std::string token::read_user_string(uint32_t offset) const
	{
		return meta_->user_string(offset);
	}

	storage token::read_blob(architecture &file) const
	{
		return meta_->blob(meta_->blob_field_size() ? file.read<uint32_t>() : file.read<uint16_t>());
	}

	storage token::read_guid(architecture &file) const
	{
		return meta_->guid(meta_->guid_field_size() ? file.read<uint32_t>() : file.read<uint16_t>());
	}

	token *token::read_token(architecture &file, const token_encoding_t &encoding) const
	{
		uint32_t value = meta_->field_size(encoding) ? file.read<uint32_t>() : file.read<uint16_t>();
		size_t type_index = (value & ((1ul << encoding.bits) - 1));
		if (type_index >= encoding.size)
			throw std::runtime_error("Unknown ref type");
		return meta_->find({ encoding.types[type_index], value >> encoding.bits });
	}

	token *token::read_token(architecture &file, token_type_id type) const
	{
		uint32_t value = meta_->field_size(type) ? file.read<uint32_t>() : file.read<uint16_t>();
		return meta_->find({ type, value });
	}

	token *token::next() const
	{
		return meta_->find(id() + 1);
	}

	// module

	void module::load(architecture &file)
	{
		generation_ = file.read<uint16_t>();
		name_ = read_string(file);
		mv_id_ = read_guid(file);
		enc_id_ = read_guid(file);
		enc_base_id_ = read_guid(file);
	}

	// type_ref

	void type_ref::load(architecture &file)
	{
		resolution_scope_ = read_token(file, resolution_scope_encoding);
		name_ = read_string(file);
		namespace_ = read_string(file);
	}

	type_ref *type_ref::declaring_type() const
	{
		if (resolution_scope_ && resolution_scope_->type() == token_type_id::type_ref)
			return static_cast<type_ref *>(resolution_scope_);
		return nullptr;
	}

	std::string type_ref::full_name() const
	{
		std::string res;
		if (type_ref *declaring_type = this->declaring_type())
			res = declaring_type->full_name() + '/';
		else {
			res = namespace_;
			if (!res.empty())
				res += '.';
		}
		res += name_;

		return res;
	}

	// type_def

	void type_def::load(architecture &file)
	{
		flags_ = file.read<format::type_attributes_t>();
		name_ = read_string(file);
		namespace_ = read_string(file);
		base_type_ = read_token(file, type_def_ref_encoding);
		field_list_ = static_cast<field *>(read_token(file, token_type_id::field));
		method_list_ = static_cast<method_def *>(read_token(file, token_type_id::method_def));
	}

	std::string type_def::full_name() const
	{
		std::string res;
		if (declaring_type_)
			res = declaring_type_->full_name() + '/';
		else {
			res = namespace_;
			if (!res.empty())
				res += '.';
		}
		res += name_;

		return res;
	}

	// field

	field::field(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<signature>(owner);
	}

	void field::load(architecture &file)
	{
		flags_ = file.read<format::field_attributes_t>();
		name_ = read_string(file);
		signature_->load(read_blob(file));
	}

	// method_def

	method_def::method_def(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<signature>(owner);
	}

	void method_def::load(architecture &file)
	{
		address_ = file.read<uint32_t>();
		if (address_)
			address_ += file.image_base();
		impl_ = file.read<format::method_impl_t>();
		flags_ = file.read<format::method_attributes_t>();
		name_ = read_string(file);
		signature_->load(read_blob(file));
		param_list_ = static_cast<param *>(read_token(file, token_type_id::param));
	}

	std::string method_def::full_name(generic_arguments *args) const
	{
		return symbol_name(signature_->ret_name(args), declaring_type_ ? declaring_type_->full_name() : "<nullptr>", name_, signature_->name(args));
	}

	// param

	void param::load(architecture &file)
	{
		flags_ = file.read<uint16_t>();
		sequence_ = file.read<uint16_t>();
		name_ = read_string(file);
	}

	// interface_impl

	void interface_impl::load(architecture &file)
	{
		class_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
		interface_ = read_token(file, type_def_ref_encoding);
	}

	// member_ref

	member_ref::member_ref(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<signature>(owner);
	}

	void member_ref::load(architecture &file)
	{
		declaring_type_ = read_token(file, member_ref_parent_encoding);
		name_ = read_string(file);
		signature_->load(read_blob(file));
	}

	std::string member_ref::full_name(generic_arguments *in_args) const
	{
		generic_arguments args(in_args);

		std::string type_name;
		if (declaring_type_) {
			switch (declaring_type_->type()) {
			case token_type_id::type_def:
				type_name = static_cast<type_def *>(declaring_type_)->name();
				break;
			case token_type_id::type_ref:
				type_name = static_cast<type_ref *>(declaring_type_)->full_name();
				break;
			case token_type_id::type_spec:
				{
					type_spec *type = static_cast<type_spec *>(declaring_type_);
					type_name = type->name();
					if (type->signature().type() == element_type_id::genericinst) {
						type->signature().push_args(args, true);
						if (type_name.substr(0, 9) == "valuetype")
							type_name = type_name.substr(10);
						else if (type_name.substr(0, 5) == "class")
							type_name = type_name.substr(6);
					}
				}
				break;
			case token_type_id::method_def:
				type_name = static_cast<method_def *>(declaring_type_)->declaring_type()->full_name();
				break;
			}
		}
		else
			type_name = "<nullptr>";

		return symbol_name(signature_->ret_name(&args), type_name, name_, signature_->type().is_method() ? signature_->name(&args) : "");
	}

	// constant

	void constant::load(architecture &file)
	{
		type_ = file.read<uint8_t>();
		padding_zero_ = file.read<uint8_t>();
		parent_ = read_token(file, has_constant_encoding);
		value_ = read_blob(file);
	}

	// custom_attribute

	void custom_attribute::load(architecture &file)
	{
		parent_ = read_token(file, has_custom_attribute_encoding);
		type_ = read_token(file, custom_attribute_encoding);
		value_ = read_blob(file);
	}

	// field_marshal

	void field_marshal::load(architecture &file)
	{
		parent_ = read_token(file, has_field_marshal_encoding);
		native_type_ = read_blob(file);
	}

	// decl_security

	void decl_security::load(architecture &file)
	{
		action_ = file.read<uint16_t>();
		parent_ = read_token(file, has_decl_security_encoding);
		permission_set_ = read_blob(file);
	}

	// class_layout

	void class_layout::load(architecture &file)
	{
		packing_size_ = file.read<uint16_t>();
		class_size_ = file.read<uint32_t>();
		parent_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
	}

	// field_layout

	void field_layout::load(architecture &file)
	{
		offset_ = file.read<uint32_t>();
		field_ = static_cast<field *>(read_token(file, token_type_id::field));
	}

	// standalone_sig

	stand_alone_sig::stand_alone_sig(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<signature>(owner);
	}

	void stand_alone_sig::load(architecture &file)
	{
		signature_->load(read_blob(file));
	}

	// event_map

	void event_map::load(architecture &file)
	{
		parent_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
		event_list_ = static_cast<event *>(read_token(file, token_type_id::event));
	}

	// event

	void event::load(architecture &file)
	{
		flags_ = file.read<uint16_t>();
		name_ = read_string(file);
		parent_ = read_token(file, type_def_ref_encoding);
	}

	// property_map

	void property_map::load(architecture &file)
	{
		parent_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
		property_list_ = static_cast<property *>(read_token(file, token_type_id::property));
	}

	// property

	property::property(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<signature>(owner);
	}

	void property::load(architecture &file)
	{
		flags_ = file.read<uint16_t>();
		name_ = read_string(file);
		signature_->load(read_blob(file));
	}

	// method_semantics

	void method_semantics::load(architecture &file)
	{
		flags_ = file.read<uint16_t>();
		method_ = static_cast<method_def *>(read_token(file, token_type_id::method_def));
		association_ = read_token(file, has_semantics_encoding);
	}

	// method_impl

	void method_impl::load(architecture &file)
	{
		class_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
		body_ = read_token(file, method_def_ref_encoding);
		declaration_ = read_token(file, method_def_ref_encoding);
	}

	// module_ref

	void module_ref::load(architecture &file)
	{
		name_ = read_string(file);
	}

	// type_spec

	type_spec::type_spec(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<element>(owner);
	}

	void type_spec::load(architecture &file)
	{
		signature_->load(read_blob(file));
	}

	// impl_map

	void impl_map::load(architecture &file)
	{
		mapping_flags_ = file.read<uint16_t>();
		member_forwarded_ = read_token(file, member_forwarded_encoding);
		import_name_ = read_string(file);
		import_scope_ = static_cast<module_ref *>(read_token(file, token_type_id::module_ref));
	}

	// field_rva

	void field_rva::load(architecture &file)
	{
		address_ = file.read<uint32_t>() + file.image_base();
		field_ = static_cast<field *>(read_token(file, token_type_id::field));
	}

	// enc_log

	void enc_log::load(architecture &file)
	{
		token_ = file.read<uint32_t>();
		func_code_ = file.read<uint32_t>();
	}

	// enc_map

	void enc_map::load(architecture &file)
	{
		token_ = file.read<uint32_t>();
	}

	// assembly

	void assembly::load(architecture &file)
	{
		hash_id_ = file.read<uint32_t>();
		version_ = file.read<format::ex_version_t>();
		build_number_ = file.read<uint16_t>();
		revision_number_ = file.read<uint16_t>();
		flags_ = file.read<uint32_t>();
		public_key_ = read_blob(file);
		name_ = read_string(file);
		culture_ = read_string(file);
	}

	// assembly_processor

	void assembly_processor::load(architecture &file)
	{
		processor_ = file.read<uint32_t>();
	}

	// assembly_os

	void assembly_os::load(architecture &file)
	{
		os_platform_id_ = file.read<uint32_t>();
		os_major_version_ = file.read<uint32_t>();
		os_minor_version_ = file.read<uint32_t>();
	}

	// assembly_ref

	void assembly_ref::load(architecture &file)
	{
		version_ = file.read<format::ex_version_t>();
		build_number_ = file.read<uint16_t>();
		revision_number_ = file.read<uint16_t>();
		flags_ = file.read<uint32_t>();
		public_key_or_token_ = read_blob(file);
		name_ = read_string(file);
		culture_ = read_string(file);
		hash_value_ = read_blob(file);
	}

	// assembly_ref_os

	void assembly_ref_os::load(architecture &file)
	{
		os_platform_id_ = file.read<uint32_t>();
		os_major_version_ = file.read<uint32_t>();
		os_minor_version_ = file.read<uint32_t>();
		assembly_ref_ = static_cast<assembly_ref *>(read_token(file, token_type_id::assembly_ref));
	};

	// assembly_ref_processor

	void assembly_ref_processor::load(architecture &file)
	{
		processor_ = file.read<uint32_t>();
		assembly_ref_ = static_cast<assembly_ref *>(read_token(file, token_type_id::assembly_ref));
	}

	// file

	void tfile::load(architecture &file)
	{
		flags_ = file.read<uint32_t>();
		name_ = read_string(file);
		value_ = read_blob(file);
	}

	// exported_type

	void exported_type::load(architecture &file)
	{
		flags_ = file.read<uint32_t>();
		type_def_id_ = file.read<uint32_t>();
		name_ = read_string(file);
		namespace_ = read_string(file);
		implementation_ = read_token(file, implementation_encoding);
	}

	// manifest_resource

	void manifest_resource::load(architecture &file)
	{
		offset_ = file.read<uint32_t>();
		flags_ = file.read<uint32_t>();
		name_ = read_string(file);
		implementation_ = read_token(file, implementation_encoding);
	}

	// nested_class

	void nested_class::load(architecture &file)
	{
		nested_type_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
		declaring_type_ = static_cast<type_def *>(read_token(file, token_type_id::type_def));
	}

	// generic_param

	void generic_param::load(architecture &file)
	{
		number_ = file.read<uint16_t>();
		flags_ = file.read<uint16_t>();
		parent_ = read_token(file, type_or_methoddef_encoding);
		name_ = read_string(file);
	}

	// method_spec

	method_spec::method_spec(meta_data *owner, token_value_t value)
		: token(owner, value)
	{
		signature_ = std::make_unique<signature>(owner);
	}

	void method_spec::load(architecture &file)
	{
		parent_ = read_token(file, method_def_ref_encoding);
		signature_->load(read_blob(file));
	}

	std::string method_spec::full_name() const
	{
		if (parent_) {
			generic_arguments args;
			signature_->push_args(args, false);

			switch (parent_->type()) {
			case token_type_id::method_def:
				return static_cast<method_def *>(parent_)->full_name(&args);
			case token_type_id::member_ref:
				return static_cast<member_ref *>(parent_)->full_name(&args);
			}
		}

		return "<nullptr>";
	}

	// generic_param_constraint

	void generic_param_constraint::load(architecture &file)
	{
		parent_ = static_cast<generic_param *>(read_token(file, token_type_id::generic_param));
		constraint_ = read_token(file, type_def_ref_encoding);
	}

	// array_shape

	void array_shape::load(storage_view &data)
	{
		rank_ = data.read_encoded();
		size_t count = data.read_encoded();
		for (size_t i = 0; i < count; i++) {
			sizes_.push_back(data.read_encoded());
		}
		count = data.read_encoded();
		for (size_t i = 0; i < count; i++) {
			lo_bounds_.push_back(data.read_encoded());
		}
	}

	std::string array_shape::name() const
	{
		std::string res;

		res += '[';
		for (size_t i = 0; i < rank_; i++) {
			if (i > 0)
				res += ',';
			if (i < lo_bounds_.size()) {
				uint32_t lo_bound = lo_bounds_[i];
				res += utils::format("%d..", lo_bound);
				if (i < sizes_.size())
					res += utils::format("%d", lo_bound + sizes_[rank_] - 1);
				else
					res += '.';
			}
		}
		res += ']';
		return res;
	}

	// element

	void element::load(const storage &data)
	{
		storage_view stream(data);
		load(stream);
	}

	void element::load(storage_view &data)
	{
		for (bool mod_found = true; mod_found;) {
			size_t id = data.tell();
			auto mod_type = data.read<element_type_id>();
			switch (mod_type) {
			case element_type_id::byref:
				byref_ = true;
				break;
			case element_type_id::pinned:
				pinned_ = true;
				break;
			case element_type_id::sentinel:
				sentinel_ = true;
				break;
			case element_type_id::cmod_reqd:
			case element_type_id::cmod_opt:
				data.seek(id);
				mod_list_.add(owner_).read_type(data);
				break;
			default:
				data.seek(id);
				mod_found = false;
				break;
			}
		}
		read_type(data);
	}

	void element::read_type(storage_view &data)
	{
		size_t pos = data.tell();
		type_ = static_cast<element_type_id>(data.read_encoded());
		switch (type_) {
		case element_type_id::_void:
		case element_type_id::boolean:
		case element_type_id::_char:
		case element_type_id::i1:
		case element_type_id::u1:
		case element_type_id::i2:
		case element_type_id::u2:
		case element_type_id::i4:
		case element_type_id::u4:
		case element_type_id::i8:
		case element_type_id::u8:
		case element_type_id::r4:
		case element_type_id::r8:
		case element_type_id::i:
		case element_type_id::u:
		case element_type_id::string:
		case element_type_id::object:
		case element_type_id::typedbyref:
		case element_type_id::sentinel:
		case element_type_id::pinned:
			break;
		case element_type_id::valuetype:
		case element_type_id::_class:
		case element_type_id::cmod_reqd:
		case element_type_id::cmod_opt:
			{
				pos = data.tell();
				uint32_t ref_value = data.read_encoded();
				token_type_id ref_type;
				switch (ref_value & 3) {
				case 0:
					ref_type = token_type_id::type_def;
					break;
				case 1:
					ref_type = token_type_id::type_ref;
					break;
				case 2:
					ref_type = token_type_id::type_spec;
					break;
				default:
					throw std::runtime_error(utils::format("Invalid token type at signature offset %d", pos));
				}
				token_value_t value = { ref_type, ref_value >> 2 };
				token_ = owner_->find(value);
				if (!token_)
					throw std::runtime_error(utils::format("Invalid token 0x%x at signature offset %d", value.id, pos));
			}
			break;
		case element_type_id::szarray:
			next_ = std::make_unique<element>(owner_);
			next_->load(data);
			break;
		case element_type_id::ptr:
			next_ = std::make_unique<element>(owner_);
			next_->load(data);
			break;
		case element_type_id::fnptr:
			pos = data.tell();
			method_ = std::make_unique<signature>(owner_);
			method_->load(data);
			if (!method_->type().is_method())
				throw std::runtime_error(utils::format("Invalid signature type 0x%x for ELEMENT_TYPE_FNPTR at signature offset %d", method_->type(), pos));
			break;
		case element_type_id::array:
			next_ = std::make_unique<element>(owner_);
			next_->load(data);
			array_shape_ = std::make_unique<array_shape>();
			array_shape_->load(data);
			break;
		case element_type_id::mvar:
		case element_type_id::var:
			generic_param_ = data.read_encoded();
			break;
		case element_type_id::genericinst:
			next_ = std::make_unique<element>(owner_);
			next_->load(data);
			{
				size_t count = data.read_encoded();
				for (size_t i = 0; i < count; i++) {
					child_list_.add(owner_).load(data);
				}
			}
			break;
		default:
			throw std::runtime_error(utils::format("Invalid element type 0x%x at signature offset %d", type_, pos));
		}
	}

	std::string element::name(generic_arguments *args) const
	{
		std::string res;

		if (sentinel_) {
			res += "...";
			if (type_ != element_type_id::end)
				res += ", ";
		}

		switch (type_) {
		case element_type_id::end:
			return res;
		case element_type_id::_void:
			res += "void";
			break;
		case element_type_id::boolean:
			res += "bool";
			break;
		case element_type_id::_char:
			res += "char";
			break;
		case element_type_id::i1:
			res += "int8";
			break;
		case element_type_id::u1:
			res += "unsigned int8";
			break;
		case element_type_id::i2:
			res += "int16";
			break;
		case element_type_id::u2:
			res += "unsigned int16";
			break;
		case element_type_id::i4:
			res += "int32";
			break;
		case element_type_id::u4:
			res += "unsigned int32";
			break;
		case element_type_id::i8:
			res += "int64";
			break;
		case element_type_id::u8:
			res += "unsigned int64";
			break;
		case element_type_id::r4:
			res += "float32";
			break;
		case element_type_id::r8:
			res += "float64";
			break;
		case element_type_id::i:
			res += "native int";
			break;
		case element_type_id::u:
			res += "native unsigned int";
			break;
		case element_type_id::object:
			res += "object";
			break;
		case element_type_id::string:
			res += "string";
			break;
		case element_type_id::szarray:
			res += next_->name(args);
			res += "[]";
			break;
		case element_type_id::ptr:
			res += next_->name(args);
			res += '*';
			break;
		case element_type_id::typedbyref:
			res += "typedref";
			break;
		case element_type_id::fnptr:
			{
				res += "method ";
				switch (method_->type().type) {
				case signature_type_id::std_call:
					res += "stdcall ";
					break;
				case signature_type_id::this_call:
					res += "thiscall ";
					break;
				case signature_type_id::fast_call:
					res += "fastcall ";
					break;
				}
				res += method_->ret_name();
				res += method_->name();
			}
			break;
		case element_type_id::array:
			res += next_->name(args);
			res += array_shape_->name();
			break;
		case element_type_id::valuetype:
		case element_type_id::_class:
			res += (type_ == element_type_id::valuetype) ? "valuetype " : "class ";
			switch (token_->type()) {
			case token_type_id::type_ref:
				res += static_cast<type_ref *>(token_)->full_name();
				break;
			case token_type_id::type_def:
				res += static_cast<type_def *>(token_)->full_name();
				break;
			}
			break;
		case element_type_id::genericinst:
			res += next_->name();
			res += '<';
			{
				bool need_comma = false;
				for (auto &child : child_list_) {
					if (need_comma)
						res += ", ";
					res += child.name(args);
					need_comma = true;
				}
			}
			res += '>';
			break;
		case element_type_id::mvar:
		case element_type_id::var:
			if (element *gen_type = args ? args->resolve(*this) : nullptr)
				res += gen_type->name();
			else
				res += utils::format("%s%d", (type_ == element_type_id::mvar) ? "!!" : "!", generic_param_);
			break;
		case element_type_id::cmod_reqd:
		case element_type_id::cmod_opt:
			res += (type_ == element_type_id::cmod_reqd) ? "modreq" : "modopt";
			res += '(';
			switch (token_->type()) {
			case token_type_id::type_ref:
				res += static_cast<type_ref *>(token_)->full_name();
				break;
			case token_type_id::type_def:
				res += static_cast<type_def *>(token_)->full_name();
				break;
			}
			res += ')';
			break;
		}

		for (auto it = mod_list_.end(); it != mod_list_.begin();) {
			res += ' ';
			res += (*--it).name(args);
		}

		if (byref_)
			res += '&';

		if (pinned_)
			res += " pinned";

		return res;
	}

	void element::push_args(generic_arguments &args, bool is_type) const
	{
		if (type_ == element_type_id::genericinst) {
			for (auto &child : child_list_) {
				args.push_arg(&child, is_type);
			}
		}
	}

	// generic_arguments

	generic_arguments::generic_arguments(generic_arguments *src)
	{
		if (src) {
			method_args_ = src->method_args_;
			type_args_ = src->type_args_;
		}
	}

	void generic_arguments::clear()
	{
		method_args_.clear();
		type_args_.clear();
	}

	void generic_arguments::push_arg(element *arg, bool is_type)
	{
		if (is_type)
			type_args_.push_back(arg);
		else 
			method_args_.push_back(arg);
	}

	element *generic_arguments::resolve(const element &type) const
	{
		switch (type.type()) {
		case element_type_id::mvar:
			return (type.number() < method_args_.size()) ? method_args_[type.number()] : nullptr;
		case element_type_id::var:
			return (type.number() < type_args_.size()) ? type_args_[type.number()] : nullptr;
		}
		return nullptr;
	}

	// signature

	signature::signature(meta_data *owner)
		: owner_(owner)
	{
		ret_ = std::make_unique<element>(owner);
	}

	void signature::load(const storage &storage)
	{
		storage_view stream(storage);
		load(stream);
	}

	void signature::load(storage_view &data)
	{
		type_ = data.read<signature_type_t>();
		if (type_.generic)
			gen_param_count_ = data.read_encoded();

		switch (type_.type) {
		case signature_type_id::def:
		case signature_type_id::c_call:
		case signature_type_id::std_call:
		case signature_type_id::this_call:
		case signature_type_id::fast_call:
		case signature_type_id::var_arg:
		case signature_type_id::unmanaged:
		case signature_type_id::native_var_arg:
		case signature_type_id::property:
			{
				size_t count = data.read_encoded();
				ret_->load(data);
				for (size_t i = 0; i < count; i++) {
					add(owner_).load(data);
				}
			}
			break;
		case signature_type_id::field:
			ret_->load(data);
			break;
		case signature_type_id::local:
		case signature_type_id::generic_inst:
			{
				size_t count = data.read_encoded();
				for (size_t i = 0; i < count; i++) {
					add(owner_).load(data);
				}
			}
			break;
		default:
			throw std::runtime_error("Unknown signature type");
		}
	}

	std::string signature::ret_name(generic_arguments *args) const
	{
		std::string res;

		if (type_.has_this)
			res = "instance ";

		res += ret_->name(args);
		return res;
	}

	std::string signature::name(generic_arguments *args) const
	{
		std::string res;

		bool is_generic_inst = false;
		switch (type_.type) {
		case signature_type_id::generic_inst:
			is_generic_inst = true;
			// fall through
		case signature_type_id::def:
		case signature_type_id::c_call:
		case signature_type_id::std_call:
		case signature_type_id::this_call:
		case signature_type_id::fast_call:
		case signature_type_id::var_arg:
		case signature_type_id::local:
		case signature_type_id::unmanaged:
		case signature_type_id::native_var_arg:
			if (type_.generic) {
				res += '<';
				for (size_t i = 0; i < gen_param_count_; i++) {
					if (i > 0)
						res += ", ";
					if (element *gen_type = args ? args->method_arg(i) : nullptr)
						res += gen_type->name();
					else
						res += utils::format("%d", i);
				}
				res += '>';
			}

			res += is_generic_inst ? '<' : '(';
			{
				bool need_comma = false;
				for (auto &item : *this) {
					if (need_comma)
						res += ", ";
					res += item.name(args);
					need_comma = true;
				}
			}
			res += is_generic_inst ? '>' : ')';
			break;
		}

		return res;
	}

	void signature::push_args(generic_arguments &args, bool is_type) const
	{
		if (type_.generic) {
			for (auto &item : *this) {
				args.push_arg(&item, is_type);
			}
		}
	}
}