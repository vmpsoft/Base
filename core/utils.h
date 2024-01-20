#pragma once

namespace utils
{
	std::string to_utf8(const char16_t *data, size_t size)
	{
		auto begin = (const wchar_t *)data;
		auto end = begin + size;
		return { std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(begin, end) };
	}
}