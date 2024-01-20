#include "dotnet.h"
#include "utils.h"

namespace net
{
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
		uint32_t res;
		uint8_t b = read<uint8_t>();
		if ((b & 0x80) == 0)
			res = b & 0x7f;
		else if ((b & 0x40) == 0)
			res = ((b & 0x3f) << 8) | read<uint8_t>();
		else
			res = ((b & 0x1f) << 24) | (read<uint8_t>() << 16) | (read<uint8_t>() << 8) | read<uint8_t>();
		return res;
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
	}

	base::status architecture::load() 
	{
		auto dir = file_.command_list()->find_type(pe::format::directory_id::com_descriptor);
		if (!dir || !seek_address(dir->address()))
			return base::status::invalid_format;

		auto header = read<format::cor20_header_t>();
		if (!header.meta_data.rva)
			return base::status::invalid_format;

		meta_data_->load(*this, header.meta_data.rva + image_base());

		return base::status::success;
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
				heap_ = &add<heap_stream>(this, address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#Strings" && !strings_)
				strings_ = &add<strings_stream>(this, address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#US" && !user_strings_)
				user_strings_ = &add<user_strings_stream>(this, address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#Blob" && !blob_)
				blob_ = &add<blob_stream>(this, address + stream_header.offset, stream_header.size, stream_name);
			else if (stream_name == "#GUID" && !guid_)
				guid_ = &add<guid_stream>(this, address + stream_header.offset, stream_header.size, stream_name);
			else
				add<stream>(this, address + stream_header.offset, stream_header.size, stream_name);

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
	}

	table *meta_data::table(token_type_id type) const
	{
		for (auto &item : heap_->table_list()) {
			if (item.type() == type)
				return &item;
		}
		return nullptr;
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

	token *meta_data::token(token_value_t id) const
	{
		if (!id.value)
			return nullptr;

		auto table = this->table(id.type);
		if (!table)
			throw std::runtime_error("Invalid token");
		return (id.value <= table->size()) ? table->item(id.value - 1) : nullptr;
	}

	uint32_t meta_data::token_count(token_type_id type) const
	{
		auto *table = this->table(type);
		return table ? (uint32_t)table->size() : 0;
	}

	bool meta_data::field_size(const token_encoding_t &encoding) const
	{
		uint32_t count = 0;
		for (size_t index = 0; index < encoding.size; index++) {
			count = std::max<uint32_t>(count, token_count(encoding.types[index]));
		}
		return count >= (1ul << (16 - encoding.bits));
	}

	bool meta_data::field_size(token_type_id type) const
	{
		return token_count(type) > 0xffff;
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
			default:
				add<token>(owner, token_value); break;
				/*
			default:
				throw std::runtime_error("Unknown token type");
				*/
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
		: meta_(owner), id_(value)
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
		return meta_->token({ encoding.types[type_index], value >> encoding.bits });
	}

	token *token::read_token(architecture &file, token_type_id type) const
	{
		uint32_t value = meta_->field_size(type) ? file.read<uint32_t>() : file.read<uint16_t>();
		return meta_->token({ type, value });
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

	// field

	void field::load(architecture &file)
	{
		flags_ = file.read<format::field_attributes_t>();
		name_ = read_string(file);
		signature_->load(read_blob(file));
	}

	// method_def

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
}