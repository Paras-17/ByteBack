#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <zlib.h>

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cerr << "Logs from your program will appear here!\n";

    // Uncomment this block to pass the first stage
    if (argc < 2) {
        std::cerr << "No command provided.\n";
        return EXIT_FAILURE;
    }
    
    std::string command = argv[1];
    
    if (command == "init") {
        try {
            std::filesystem::create_directory(".git");
            std::filesystem::create_directory(".git/objects");
            std::filesystem::create_directory(".git/refs");
    
            std::ofstream headFile(".git/HEAD");
            if (headFile.is_open()) {
                headFile << "ref: refs/heads/main\n";
                headFile.close();
            } else {
                std::cerr << "Failed to create .git/HEAD file.\n";
                return EXIT_FAILURE;
            }
    
            std::cout << "Initialized git directory\n";
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << e.what() << '\n';
            return EXIT_FAILURE;
        }
    }
    else if (command =="cat-file")
    {
        if (argc < 4) {
            std::cerr << "Invalid number of arguments, missing parameters: -p <hash> \n";
            return EXIT_FAILURE;
        }
        const auto blob_hash = std::string_view(argv[3],40);
        const auto blob_dir = blob_hash.substr(0,2);
        const auto blob_name = blob_hash.substr(2);
        const auto blob_path = std::filesystem::path(".git")/"objects"/blob_dir/blob_name;
        auto in = std::ifstream(blob_path);
        if(!in.is_open()){
            std::cerr << "Failed to open"<<blob_path<<"file. \n";
            return EXIT_FAILURE;
        }
        const auto blob_data = std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        auto buf = std::string();
        buf.resize(blob_data.size());
        while (true) {
            auto len = buf.size();
            if (auto res = uncompress((uint8_t*)buf.data(), &len, (const uint8_t*)blob_data.data(), blob_data.size()); res == Z_BUF_ERROR) {
                buf.resize(buf.size() * 2);
            } else if (res != Z_OK) {
                std::cerr << "Failed to uncompress Zlib. (code: " << res << ")\n";
                return EXIT_FAILURE;
            } else {
                buf.resize(len);
                break;
            }
        }
        std::cout << std::string_view(buf).substr(buf.find('\0') + 1);
    }
    else {
        std::cerr << "Unknown command " << command << '\n';
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
