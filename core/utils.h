#pragma once

namespace utils
{
    std::string to_utf8(const char16_t *data, size_t size);

    template<typename ... Args>
    std::string format(const char *format, Args ... args)
    {
        int size_s = std::snprintf(nullptr, 0, format, args ...) + 1;
        if (size_s <= 0) return { };
        auto size = static_cast<size_t>(size_s);
        std::unique_ptr<char[]> buf(new char[size]);
        std::snprintf(buf.get(), size, format, args ...);
        return { buf.get(), size - 1 };
    }
}