#include <iostream>
#include <iomanip>
#include <functional>
#include "core/core.h"

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " File\n";
        return 0;
    }

    core::core core;

    switch (core.open(argv[1])) {
    case base::status::success:
    {
            auto &file = *core.file();
            std::cout << "Format: " << file.format() << "\n";
            for (auto &architecture : file) {
                std::cout << "  Architecture: " << architecture.name() << "\n";
                std::cout << "    Load Commands: (" << std::dec << architecture.commands().size() << ")\n";
                for (auto &load_command : architecture.commands()) {
                    std::cout << "      Name: " << load_command.name() << "  Address: " << std::hex << load_command.address() << "  Size: " << std::hex << load_command.size() << "\n";
                }
                std::cout << "    Segments: (" << std::dec << architecture.segments().size() << ")\n";
                for (auto &segment : architecture.segments()) {
                    std::cout << "      Name: " << segment.name() << "  Address: " << segment.address() << "  Size: " << std::hex << segment.size() << "\n";
                    for (auto &section : architecture.sections()) {
                        if (section.parent() == &segment)
                            std::cout << "        Name: " << section.name() << "  Address: " << std::hex << section.address() << "  Size: " << std::hex << section.size() << "\n";
                    }
                }
                for (auto &section : architecture.sections()) {
                    if (!section.parent())
                        std::cout << "      Name: " << section.name() << "  Offset: " << std::hex << section.physical_offset() << "  Size: " << std::hex << section.physical_size() << "\n";
                }
                std::cout << "    Imports: (" << std::dec << architecture.imports().size() << ")\n";
                for (auto &import : architecture.imports()) {
                    std::cout << "      Name: " << import.name() << " (" << std::dec << import.size() << ")\n";
                    for (auto &func : import) {
                        std::cout << "        Address: " << std::hex << func.address() << "  Name: " << func.name();
                        if (!func.version().empty())
                            std::cout << "  (" << func.version() << ')';
                        std::cout << "\n";
                    }
                }
                std::cout << "    Exports: (" << std::dec << architecture.exports().size() << ")\n";
                for (auto &symbol : architecture.exports()) {
                    std::cout << "        Address: " << std::hex << symbol.address() << "  Name: " << symbol.name() << "\n";
                }
                std::cout << "    Resources: (" << std::dec << architecture.resources().size() << ")\n";

                std::size_t indent = 0;
                const auto print_tree = [&](const auto &self, const base::resource &resource) -> void
                {
                        std::cout << std::string(indent * 2, ' ') << "    Name: " << resource.name();
                        if (!resource.address()) {
                            std::cout << " (" << std::dec << resource.size() << ")\n";
                        }
                        else {
                            std::cout << "  Address: " << std::hex << resource.address() << "  Size: " << std::hex << resource.data_size() << "\n";
                        }

                        ++indent;
                        for (auto &child : resource) {
                            self(self, child);
                        }
                        --indent;
                    };
                for (auto &resource : architecture.resources()) {
                    print_tree(print_tree, resource);
                }
                std::cout << "    Relocations: (" << std::dec << architecture.relocs().size() << ")\n";
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
        std::cout << "Invalid format" << "\n";
        break;
    case base::status::unknown_format:
        std::cout << "Unknown format" << "\n";
        break;
    }
}
