#include <iostream>
#include "core/core.h"

int main()
{
    core::core core;

    std::string file_name;
    switch (core.open(file_name)) {
    case base::status::success:
        {
            auto &file = *core.file();
            std::cout << "Format: " << file.format() << "\n";
            for (auto &architecture : file) {
                std::cout << "  Architecture: " << architecture.name() << "\n";
                std::cout << "    Load Commands: (" << architecture.command_list()->size() << ")\n";
                for (auto &load_command : *architecture.command_list()) {
                    std::cout << "      Name: " << load_command.name() << "  Address: " << std::hex << load_command.address() << "  Size: " << std::hex << load_command.size() << "\n";
                }
                std::cout << "    Segments: (" << architecture.segment_list()->size() << ")\n";
                for (auto &segment : *architecture.segment_list()) {
                    std::cout << "      Name: " << segment.name() << "  Address: " << std::hex << segment.address() << "  Size: " << std::hex << segment.size()<< "\n";
                }
                std::cout << "    Imports: (" << architecture.import_list()->size() << ")\n";
                for (auto &import : *architecture.import_list()) {
                    std::cout << "      Name: " << import.name() << " (" << std::dec << import.size() << ")\n";
                    for (auto &func : import) {
                        std::cout << "        Address: " << std::hex << func.address() << "  Name: " << func.name() << "\n";
                    }
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