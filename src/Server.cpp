#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <zlib.h>
#include <openssl/sha.h>

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cerr << "Logs from your program will appear here!\n";

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
    }else if (command =="hash-object")
    {
        if (argc < 4) {
            std::cerr << "Invalid number of arguments, missing parameters \n";
            return EXIT_FAILURE;
        }
        std::string flag = argv[2];
        if(flag !="-w"){
            std::cerr <<"Expected -w flag for writing the object. \n";
            return EXIT_FAILURE;
        }
        std::string file_path = argv[3];
        //open file
        std::ifstream file(file_path,std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << file_path << "\n";
            return EXIT_FAILURE;
        }
        std::ostringstream fileStream;
        fileStream<<file.rdbuf();
        std::string content = fileStream.str();
        // blob construct
        std::string header = "blob " + std::to_string(content.size()) + '\0';
        std::string blob_object = header + content;
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(blob_object.data()),
             blob_object.size(), hash);

        std::ostringstream hashStream;
        hashStream << std::hex << std::setfill('0');
        for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
            hashStream << std::setw(2) << static_cast<int>(hash[i]);
        }
        std::string hashString = hashStream.str();
        //print the 40 char sha hash
        std::cout << hashString << "\n";
        uLongf compressedSize = compressBound(blob_object.size());
        std::vector<char> compressedData(compressedSize);
        int res = compress(reinterpret_cast<Bytef*>(compressedData.data()), &compressedSize,
                           reinterpret_cast<const Bytef*>(blob_object.data()),
                           blob_object.size());
        if (res != Z_OK) {
            std::cerr << "Compression failed with error code: " << res << "\n";
            return EXIT_FAILURE;
        }
        // Resize vector to the actual compressed size.
        compressedData.resize(compressedSize);
        // Determine the storage path: first 2 characters form the directory.
        std::string dir = ".git/objects/" + hashString.substr(0, 2);
        std::filesystem::create_directories(dir);
        // The remaining 38 characters form the file name.
        std::string object_path = dir + "/" + hashString.substr(2);

        // Write the compressed blob object to the file.
        std::ofstream out(object_path, std::ios::binary);
        if (!out.is_open()) {
            std::cerr << "Failed to write object file: " << object_path << "\n";
            return EXIT_FAILURE;
        }
        out.write(compressedData.data(), compressedData.size());        
    }
    else if(command=="ls-tree"){
        if (argc < 4) {
            std::cerr << "Invalid number of arguments, missing parameters \n";
            return EXIT_FAILURE;
        }
        std::string flag = argv[2];
        if(flag !="--name-only"){
            std::cerr <<"Expected flag for writing the object. \n";
            return EXIT_FAILURE;
        }
        std::string tree_sha= argv[3];
        if (tree_sha.size() != 40) {
            std::cerr << "Invalid tree SHA. Expected a 40-character SHA-1 hash.\n";
            return EXIT_FAILURE;
        }
        std::string dir = tree_sha.substr(0, 2);
        std::string filename = tree_sha.substr(2);
        std::filesystem::path objectPath = std::filesystem::path(".git") / "objects" / dir / filename;
        std::ifstream infile(objectPath, std::ios::binary);
        if (!infile) {
            std::cerr << "Failed to open object file: " << objectPath << "\n";
            return EXIT_FAILURE;
        }
        
        // Read the entire file content into a string.
        std::ostringstream oss;
        oss << infile.rdbuf();
        std::string compressed_data = oss.str();
        infile.close();

        // --- Decompression using zlib ---
        // Make an initial guess for the decompressed size.
        uLongf decompressed_size = compressed_data.size() * 4;
        std::vector<char> decompressed_data(decompressed_size);
        
        int ret = uncompress(reinterpret_cast<Bytef*>(decompressed_data.data()),
                             &decompressed_size,
                             reinterpret_cast<const Bytef*>(compressed_data.data()),
                             compressed_data.size());
        // If buffer is too small, uncompress returns Z_BUF_ERROR.
        while(ret == Z_BUF_ERROR) {
            decompressed_size *= 2; // Double the buffer size
            decompressed_data.resize(decompressed_size);
            ret = uncompress(reinterpret_cast<Bytef*>(decompressed_data.data()),
                             &decompressed_size,
                             reinterpret_cast<const Bytef*>(compressed_data.data()),
                             compressed_data.size());
        }
        if(ret != Z_OK) {
            std::cerr << "Decompression failed with error code: " << ret << "\n";
            return EXIT_FAILURE;
        }
        // Resize to the actual decompressed size.
        decompressed_data.resize(decompressed_size);
        
        // Convert the decompressed data to a string for easier parsing.
        std::string decompressed_str(decompressed_data.begin(), decompressed_data.end());
            // --- Parsing the Tree Object ---
        // The header is "tree <size>\0". Find the null terminator.
        size_t header_end = decompressed_str.find('\0');
        if(header_end == std::string::npos) {
            std::cerr << "Invalid tree object format: header not found.\n";
            return EXIT_FAILURE;
        }

        // Set the position to start reading entries after the header.
        size_t pos = header_end + 1;
        // Iterate through each tree entry.
        while (pos < decompressed_str.size()) {
            // --- Parse the Mode ---
            // The mode ends at the first space.
            size_t space_pos = decompressed_str.find(' ', pos);
            if (space_pos == std::string::npos) {
                std::cerr << "Invalid tree entry: mode not terminated by space.\n";
                return EXIT_FAILURE;
            }
            std::string mode = decompressed_str.substr(pos, space_pos - pos);
            pos = space_pos + 1;  // Move past the space

            // --- Parse the Name ---
            // The name ends at the null byte.
            size_t null_pos = decompressed_str.find('\0', pos);
            if (null_pos == std::string::npos) {
                std::cerr << "Invalid tree entry: name not terminated by null byte.\n";
                return EXIT_FAILURE;
            }
            std::string name = decompressed_str.substr(pos, null_pos - pos);

            // For --name-only, output the name.
            std::cout << name << "\n";

            // Move the position pointer past the null terminator.
            pos = null_pos + 1;

            // --- Skip the SHA ---
            // The SHA is always 20 bytes (raw binary data).
            pos += 20;
        }

        return EXIT_SUCCESS;
    


    }

    else {
        std::cerr << "Unknown command " << command << '\n';
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
