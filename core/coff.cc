#include "file.h"
#include "coff.h"

namespace coff
{
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
}