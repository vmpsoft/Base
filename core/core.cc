#include "file.h"
#include "pe.h"
#include "core.h"

namespace core
{
	// core

	core::core()
	{
		formats_.add<pe::format>();
	}

	void core::close()
	{
		file_.reset();
	}

	base::status core::open(const std::string &file_name)
	{
		close();

		base::stream stream;
		if (!stream.open(file_name))
			return base::status::open_error;

		for (auto &format : formats_) {
			if (format.check(stream)) {
				file_ = format.instance();
				return file_->open(file_name);
			}
		}
		return base::status::unknown_format;
	}
}