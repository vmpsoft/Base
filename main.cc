#include <iostream>
#include "core/core.h"

int main()
{
    core::core core;

    std::string file_name;
    switch (core.open(file_name)) {
    case base::status::success:
        {
            const auto &file = *core.file();
            std::cout << "Format: " << file.format() << "\n";
            for (auto &architecture : file) {
                std::cout << "  Architecture: " << architecture.name() << "\n";
                std::cout << "    Load Commands: (" << std::dec << architecture.commands().size() << ")\n";
                for (auto &load_command : architecture.commands()) {
                    std::cout << "      Name: " << load_command.name() << "  Address: " << std::hex << load_command.address() << "  Size: " << std::hex << load_command.size() << "\n";
                }
                std::cout << "    Segments: (" << std::dec << architecture.segments().size() << ")\n";
                for (auto &segment : architecture.segments()) {
                    std::cout << "      Name: " << segment.name() << "  Address: " << std::hex << segment.address() << "  Size: " << std::hex << segment.size() << "\n";
                }
                std::cout << "    Imports: (" << std::dec << architecture.imports().size() << ")\n";
                for (auto &import : architecture.imports()) {
                    std::cout << "      Name: " << import.name() << " (" << std::dec << import.size() << ")\n";
                    for (auto &func : import) {
                        std::cout << "        Address: " << std::hex << func.address() << "  Name: " << func.name() << "\n";
                    }
                }
                std::cout << "    Exports: (" << std::dec << architecture.exports().size() << ")\n";
                for (auto &symbol : architecture.exports()) {
                    std::cout << "        Address: " << std::hex << symbol.address() << "  Name: " << symbol.name() << "\n";
                }
                std::cout << "    Symbols: (" << std::dec << architecture.map_symbols().size() << ")\n";
                for (auto &symbol : architecture.map_symbols()) {
                    std::cout << "        Address: " << std::hex << symbol.address() << "  Name: " << symbol.name() << "\n";
                }
            }
        }
        break;
    case base::status::open_error:
        std::cout << "Open error" << "\n";
        break;
    case base::status::invalid_format:
        std::cout << "Invald format" << "\n";
        break;
    case base::status::unknown_format:
        std::cout << "Unknown format" << "\n";
        break;
    }
}