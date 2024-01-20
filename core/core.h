#pragma once

#include "file.h"

namespace core
{
	class core
	{
	public:
		core();
		void close();
		base::status open(const std::string &file_name);
		base::file *file() const { return file_.get(); }
	private:
		base::list<base::format> formats_;
		std::unique_ptr<base::file> file_;
	};
}