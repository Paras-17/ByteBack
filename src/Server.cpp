#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <zlib.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;

// ----------------------------------------------------------------
// Helper structure for a tree entry
struct TreeEntry {
    std::string mode;   // "100644" for files, "40000" for directories
    std::string name;   // The filename (or directory name)
    std::string sha;    // The 40-character SHA (in hex) for the object
};

// ----------------------------------------------------------------
// Helper: Convert a 40-character hex string into its raw 20-byte binary form.
std::string hex_to_raw(const std::string &hex) {
    std::string raw;
    raw.resize(20);
    for (size_t i = 0; i < 20; ++i) {
        std::string byteStr = hex.substr(i * 2, 2);
        unsigned int byte;
        std::istringstream(byteStr) >> std::hex >> byte;
        raw[i] = static_cast<char>(byte);
    }
    return raw;
}

// ----------------------------------------------------------------
// Helper: Write an object (blob, tree, etc.) to .git/objects.
//  - object_data: the uncompressed object (header + payload)
//  - Returns the 40-character SHA (hex string)
std::string write_object(const std::string &object_data) {
    // Compute SHA-1 hash over the uncompressed object_data.
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(object_data.data()),
         object_data.size(), hash);
    
    std::ostringstream hashStream;
    hashStream << std::hex << std::setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        hashStream << std::setw(2) << static_cast<int>(hash[i]);
    }
    std::string hashString = hashStream.str();
    
    // Compress the object_data with zlib.
    uLongf compressedSize = compressBound(object_data.size());
    std::vector<char> compressedData(compressedSize);
    int res = compress(reinterpret_cast<Bytef*>(compressedData.data()),
                       &compressedSize,
                       reinterpret_cast<const Bytef*>(object_data.data()),
                       object_data.size());
    if (res != Z_OK) {
        std::cerr << "Compression failed with error code: " << res << "\n";
        exit(EXIT_FAILURE);
    }
    compressedData.resize(compressedSize);
    
    // Compute the storage path: .git/objects/<first 2 chars>/<remaining 38 chars>
    std::string dir = ".git/objects/" + hashString.substr(0, 2);
    fs::create_directories(dir);
    std::string object_path = dir + "/" + hashString.substr(2);
    
    // Write the object only if it doesn't already exist.
    if (!fs::exists(object_path)) {
        std::ofstream out(object_path, std::ios::binary);
        if (!out.is_open()) {
            std::cerr << "Failed to write object file: " << object_path << "\n";
            exit(EXIT_FAILURE);
        }
        out.write(compressedData.data(), compressedData.size());
    }
    return hashString;
}

// ----------------------------------------------------------------
// Recursive function: write_tree()
// Given a directory (as a filesystem path), scan its entries (ignoring .git),
// create blob objects for files and recursively tree objects for subdirectories,
// build a tree object with the format:
//   "tree <payload_size>\0" + for each entry: "<mode> <name>\0<20_byte_sha>"
// then write that tree object to the object store and return its SHA.
std::string write_tree(const fs::path &dir) {
    std::vector<TreeEntry> entries;
    
    // Iterate over entries in this directory.
    for (const auto &entry : fs::directory_iterator(dir)) {
        // Ignore the .git directory
        if (entry.path().filename() == ".git")
            continue;
        
        if (entry.is_regular_file()) {
            // Process file: read its content.
            std::ifstream file(entry.path(), std::ios::binary);
            if (!file.is_open()) {
                std::cerr << "Failed to open file: " << entry.path() << "\n";
                exit(EXIT_FAILURE);
            }
            std::ostringstream ss;
            ss << file.rdbuf();
            std::string content = ss.str();
            // Create the blob object: header "blob <size>\0" + content.
            std::string header = "blob " + std::to_string(content.size()) + "\0";
            std::string blob_object = header + content;
            // Write the blob object and get its SHA.
            std::string blob_sha = write_object(blob_object);
            TreeEntry te;
            te.mode = "100644";  // Regular file mode.
            te.name = entry.path().filename().string();
            te.sha = blob_sha;
            entries.push_back(te);
        } else if (entry.is_directory()) {
            // Process directory: recursively write a tree for it.
            std::string subtree_sha = write_tree(entry.path());
            TreeEntry te;
            te.mode = "40000";  // Directory mode.
            te.name = entry.path().filename().string();
            te.sha = subtree_sha;
            entries.push_back(te);
        }
        // (Symlinks and other types can be added here if desired.)
    }
    
    // Sort tree entries by name (alphabetical order).
    std::sort(entries.begin(), entries.end(), [](const TreeEntry &a, const TreeEntry &b) {
        return a.name < b.name;
    });
    
    // Build the tree payload.
    // For each entry, the format is: "<mode> <name>\0" + raw 20-byte SHA.
    std::string payload;
    for (const auto &te : entries) {
        payload += te.mode + " " + te.name;
        payload.push_back('\0');
        payload += hex_to_raw(te.sha);
    }
    
    // Build the full tree object: header "tree <payload_size>\0" followed by payload.
    std::string header = "tree " + std::to_string(payload.size());
    header.push_back('\0');

    std::string tree_object = header + payload;
    
    // Write the tree object and return its SHA.
    return write_object(tree_object);
}

// ----------------------------------------------------------------
// Main
int main(int argc, char *argv[])
{
    // Flush outputs immediately
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    std::cerr << "Logs from your program will appear here!\n";

    if (argc < 2) {
        std::cerr << "No command provided.\n";
        return EXIT_FAILURE;
    }
    
    std::string command = argv[1];
    
    if (command == "init") {
        try {
            fs::create_directory(".git");
            fs::create_directory(".git/objects");
            fs::create_directory(".git/refs");
    
            std::ofstream headFile(".git/HEAD");
            if (headFile.is_open()) {
                headFile << "ref: refs/heads/main\n";
                headFile.close();
            } else {
                std::cerr << "Failed to create .git/HEAD file.\n";
                return EXIT_FAILURE;
            }
    
            std::cout << "Initialized git directory\n";
        } catch (const fs::filesystem_error &e) {
            std::cerr << e.what() << '\n';
            return EXIT_FAILURE;
        }
    }
    else if (command == "cat-file") {
        if (argc < 4) {
            std::cerr << "Invalid number of arguments, missing parameters: -p <hash> \n";
            return EXIT_FAILURE;
        }
        const auto blob_hash = std::string_view(argv[3], 40);
        const auto blob_dir = blob_hash.substr(0, 2);
        const auto blob_name = blob_hash.substr(2);
        fs::path blob_path = fs::path(".git") / "objects" / blob_dir / blob_name;
        std::ifstream in(blob_path, std::ios::binary);
        if (!in.is_open()) {
            std::cerr << "Failed to open " << blob_path << " file.\n";
            return EXIT_FAILURE;
        }
        std::string blob_data((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        in.close();
        std::string buf;
        buf.resize(blob_data.size());
        while (true) {
            auto len = buf.size();
            int res = uncompress(reinterpret_cast<Bytef*>(buf.data()), &len,
                                 reinterpret_cast<const Bytef*>(blob_data.data()),
                                 blob_data.size());
            if (res == Z_BUF_ERROR) {
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
    else if (command == "hash-object") {
        if (argc < 4) {
            std::cerr << "Invalid number of arguments, missing parameters \n";
            return EXIT_FAILURE;
        }
        std::string flag = argv[2];
        if (flag != "-w") {
            std::cerr << "Expected -w flag for writing the object. \n";
            return EXIT_FAILURE;
        }
        std::string file_path = argv[3];
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << file_path << "\n";
            return EXIT_FAILURE;
        }
        std::ostringstream fileStream;
        fileStream << file.rdbuf();
        std::string content = fileStream.str();
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
        compressedData.resize(compressedSize);
        std::string dir = ".git/objects/" + hashString.substr(0, 2);
        fs::create_directories(dir);
        std::string object_path = dir + "/" + hashString.substr(2);
        std::ofstream out(object_path, std::ios::binary);
        if (!out.is_open()) {
            std::cerr << "Failed to write object file: " << object_path << "\n";
            return EXIT_FAILURE;
        }
        out.write(compressedData.data(), compressedData.size());
    }
    else if (command == "ls-tree") {
        if (argc < 4) {
            std::cerr << "Invalid number of arguments, missing parameters \n";
            return EXIT_FAILURE;
        }
        std::string flag = argv[2];
        if (flag != "--name-only") {
            std::cerr << "Expected flag --name-only.\n";
            return EXIT_FAILURE;
        }
        std::string tree_sha = argv[3];
        if (tree_sha.size() != 40) {
            std::cerr << "Invalid tree SHA. Expected a 40-character SHA-1 hash.\n";
            return EXIT_FAILURE;
        }
        std::string dir = tree_sha.substr(0, 2);
        std::string filename = tree_sha.substr(2);
        fs::path objectPath = fs::path(".git") / "objects" / dir / filename;
        std::ifstream infile(objectPath, std::ios::binary);
        if (!infile) {
            std::cerr << "Failed to open object file: " << objectPath << "\n";
            return EXIT_FAILURE;
        }
        std::ostringstream oss;
        oss << infile.rdbuf();
        std::string compressed_data = oss.str();
        infile.close();
        uLongf decompressed_size = compressed_data.size() * 4;
        std::vector<char> decompressed_data(decompressed_size);
        int ret = uncompress(reinterpret_cast<Bytef*>(decompressed_data.data()),
                             &decompressed_size,
                             reinterpret_cast<const Bytef*>(compressed_data.data()),
                             compressed_data.size());
        while (ret == Z_BUF_ERROR) {
            decompressed_size *= 2;
            decompressed_data.resize(decompressed_size);
            ret = uncompress(reinterpret_cast<Bytef*>(decompressed_data.data()),
                             &decompressed_size,
                             reinterpret_cast<const Bytef*>(compressed_data.data()),
                             compressed_data.size());
        }
        if (ret != Z_OK) {
            std::cerr << "Decompression failed with error code: " << ret << "\n";
            return EXIT_FAILURE;
        }
        decompressed_data.resize(decompressed_size);
        std::string decompressed_str(decompressed_data.begin(), decompressed_data.end());
        size_t header_end = decompressed_str.find('\0');
        if (header_end == std::string::npos) {
            std::cerr << "Invalid tree object format: header not found.\n";
            return EXIT_FAILURE;
        }
        size_t pos = header_end + 1;
        while (pos < decompressed_str.size()) {
            size_t space_pos = decompressed_str.find(' ', pos);
            if (space_pos == std::string::npos) {
                std::cerr << "Invalid tree entry: mode not terminated by space.\n";
                return EXIT_FAILURE;
            }
            std::string mode = decompressed_str.substr(pos, space_pos - pos);
            pos = space_pos + 1;
            size_t null_pos = decompressed_str.find('\0', pos);
            if (null_pos == std::string::npos) {
                std::cerr << "Invalid tree entry: name not terminated by null byte.\n";
                return EXIT_FAILURE;
            }
            std::string name = decompressed_str.substr(pos, null_pos - pos);
            std::cout << name << "\n";
            pos = null_pos + 1;
            pos += 20;
        }
    }
    else if (command == "write-tree") {
        // The "write-tree" command: recursively create tree objects from
        // the current working directory (ignoring .git) and print the SHA.
        // We assume all files are staged.
        std::string tree_sha = write_tree(fs::current_path());
        std::cout << tree_sha << "\n";
    }
    else {
        std::cerr << "Unknown command " << command << '\n';
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
