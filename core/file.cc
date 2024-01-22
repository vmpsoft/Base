#include "file.h"
#include "utils.h"

namespace base
{
	// file

	void file::close()
	{
		clear();
		stream_.close();
	}

	status file::open(const std::string &file_name)
	{
		close();

		if (!stream_.open(file_name))
			return status::open_error;

		file_name_ = file_name;
		try {
			return load();
		}
		catch (std::runtime_error) {
			return status::invalid_format;
		}
	}

	uint64_t file::seek(uint64_t position)
	{
		uint64_t res = stream_.seek(position);
		if (res == stream::error)
			throw std::runtime_error("Runtime error at Seek");
		return res;
	}

	uint64_t file::tell()
	{
		return stream_.tell();
	}

	uint64_t file::size()
	{
		return stream_.size();
	}

	size_t file::read(void *buffer, size_t size)
	{
		if (stream_.read(buffer, size) != size)
			throw std::runtime_error("Runtime error at Read");
		return size;
	}

	// architecture

	architecture:: architecture(file *owner, uint64_t offset, uint64_t size) 
		: owner_(owner), offset_(offset), size_(size) 
	{
	
	}

	size_t architecture::read(void *buffer, size_t size) const
	{ 
		size_t res = owner_->read(buffer, size);
		if (res != size)
			throw std::runtime_error("Runtime error at Read");
		return res;
	}

	std::string architecture::read_string() const
	{
		std::string res;
		while (char c = read<char>()) res.push_back(c);
		return res;
	}

	uint64_t architecture::seek(uint64_t position) const
	{
		position += offset_;
		if (position < offset_ || position >= offset_ + size_)
			throw std::runtime_error("Runtime error at Seek");
		return owner_->seek(position) - offset_;
	}

	bool architecture::seek_address(uint64_t address) const
	{
		if (auto segment = segments()->find_mapped(address)) {
			if (segment->physical_size() > address - segment->address()) {
				seek(segment->physical_offset() + address - segment->address());
				return true;
			}
		}
		return false;
	}

	uint64_t architecture::tell() const
	{
		uint64_t position = owner_->tell();
		if (position < offset_ || position >= offset_ + size_)
			throw std::runtime_error("Runtime error at Tell");
		return position - offset_;
	}

	// load_command

	std::string load_command::name() const
	{
		return utils::format("%d", type());
	}

	// load_command_list

	load_command *load_command_list::find_type(size_t type) const
	{
		for (auto &item : *this) {
			if (item.type() == type)
				return &item;
		}
		return nullptr;
	}

	// segment_list

	segment *segment_list::find_mapped(uint64_t address) const
	{
		for (auto &item : *this) {
			if (item.memory_type().mapped && address >= item.address() && address < item.address() + item.size())
				return &item;
		}
		return nullptr;
	}

	// import_list

	import *import_list::find_name(const std::string &name) const
	{
		for (auto &item : *this) {
			if (item.name() == name)
				return &item;
		}
		return nullptr;
	}
};