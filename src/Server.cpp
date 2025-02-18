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
#include <cstring>
#include <optional>
// #include <fmt/format.h>
namespace fs = std::filesystem;

// ----------------------------------------------------------------
// A simple structure to represent a tree entry.
// Each tree entry holds:
//   - mode: "100644" for regular files, "40000" for directories.
//   - name: the filename or directory name.
//   - sha: the 40-character SHA (in hexadecimal) of the corresponding object.
struct TreeEntry {
    std::string mode;
    std::string name;
    std::string sha;
};

// ----------------------------------------------------------------
// Helper function: Convert a 40-character hex string into its raw 20-byte binary form.
// Git stores the SHA in raw binary format within tree objects.
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
// Helper function: Write an object (e.g. blob, tree) to the .git/objects directory.
// The function compresses the provided object_data, writes it into the appropriate
// path based on its SHA-1 hash, and returns the 40-character hash.
//
// object_data should be the uncompressed data (including the header).
std::string write_object(const std::string &object_data) {
    // Compute the SHA-1 hash of the object_data.
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(object_data.data()),
         object_data.size(), hash);
    
    std::ostringstream hashStream;
    hashStream << std::hex << std::setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        hashStream << std::setw(2) << static_cast<int>(hash[i]);
    }
    std::string hashString = hashStream.str();

    // Compress the object_data using zlib.
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

    // Determine the storage path: .git/objects/<first two chars>/<remaining 38 chars>
    std::string dir = ".git/objects/" + hashString.substr(0, 2);
    fs::create_directories(dir);
    std::string object_path = dir + "/" + hashString.substr(2);

    // Write the compressed object only if it does not already exist.
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
// This function recursively scans the directory provided (dir_path),
// creates blob objects for regular files and recursively builds tree objects
// for subdirectories. It then constructs a tree object representing the directory,
// writes it to the object store, and returns its SHA.
//
// The tree object format (before compression) is:
//   "tree <payload_length>\0" followed by a concatenation of entries.
// Each entry has the form: "<mode> <name>\0" + <20-byte raw SHA>
std::string write_tree(const std::string dir_path) {
    fs::path dir(dir_path);
    std::vector<TreeEntry> entries;
    std::string mode;
    std::string sha1;

    // Iterate over each entry in the directory.
    for (const auto &entry : fs::directory_iterator(dir)) {
        std::string name = entry.path().filename().string();
        // Ignore the .git directory.
        if (name == ".git")
            continue;

        if (entry.is_directory()) {
            mode = "40000";  // Mode for directories.
            // Recursively write the subtree.
            sha1 = write_tree(entry.path().string());
        }
        else if (entry.is_regular_file()) {
            mode = "100644"; // Mode for regular files.
            // Create a blob object from the file.
            sha1 = /* a function similar to hash_object */ ""; // Assume you already have hash_object implemented.
            // For demonstration, we'll call a stub here.
            {
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file.is_open()) {
                    std::cerr << "Failed to open file: " << entry.path() << "\n";
                    exit(EXIT_FAILURE);
                }
                std::ostringstream ss;
                ss << file.rdbuf();
                std::string content = ss.str();
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
                sha1 = hashStream.str();
                // Also write the blob object.
                write_object(blob_object);
            }
        }

        // If a SHA was obtained, convert it to its raw 20-byte binary representation.
        if (!sha1.empty()) {
            std::string binary_sha;
            for (size_t i = 0; i < sha1.length(); i += 2) {
                std::string byte_string = sha1.substr(i, 2);
                char byte = static_cast<char>(std::stoi(byte_string, nullptr, 16));
                binary_sha.push_back(byte);
            }
            // Build the entry data: "<mode> <name>\0" + binary SHA.
            std::string entry_data = mode + " " + name + '\0' + binary_sha;
            TreeEntry te;
            te.mode = mode;
            te.name = name;
            te.sha = sha1;
            entries.push_back(te);
        }
    }

    // Sort tree entries by name (alphabetical order).
    std::sort(entries.begin(), entries.end(), [](const TreeEntry &a, const TreeEntry &b) {
        return a.name < b.name;
    });

    // Build the tree content payload.
    std::string tree_content;
    for (auto &it : entries) {
        // For each entry, append: "<mode> <name>\0" + raw SHA.
        std::string binary_sha;
        for (size_t i = 0; i < it.sha.length(); i += 2) {
            std::string byte_string = it.sha.substr(i, 2);
            char byte = static_cast<char>(std::stoi(byte_string, nullptr, 16));
            binary_sha.push_back(byte);
        }
        tree_content += it.mode + " " + it.name;
        tree_content.push_back('\0');
        tree_content += binary_sha;
    }

    // Build the full tree object.
    // IMPORTANT: Build the header by appending a null byte explicitly.
    std::string header = "tree " + std::to_string(tree_content.size());
    header.push_back('\0');
    std::string tree_store = header + tree_content;

    // Compute the SHA1 hash of the uncompressed tree object.
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast< const unsigned char *>(tree_store.c_str()), tree_store.size(), hash);
    std::string tree_sha;
    for (int i = 0; i < 20; i++) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
        tree_sha += ss.str();
    }

    // Write the tree object (compress it) to the object store.
    std::string tree_dir = ".git/objects/" + tree_sha.substr(0, 2);
    fs::create_directories(tree_dir);
    std::string tree_filepath = tree_dir + "/" + tree_sha.substr(2);

    // Compress the tree object using zlib.
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK) {
        throw(std::runtime_error("deflateInit failed while compressing."));
    }
    zs.next_in = (Bytef *)tree_store.c_str();
    zs.avail_in = tree_store.size();
    int ret;
    char outBuffer[32768];
    std::string outstring;
    do {
        zs.next_out = reinterpret_cast<Bytef *>(outBuffer);
        zs.avail_out = sizeof(outBuffer);
        ret = deflate(&zs, Z_FINISH);
        if (outstring.size() < zs.total_out) {
            outstring.insert(outstring.end(), outBuffer, outBuffer + zs.total_out - outstring.size());
        }
    } while (ret == Z_OK);
    deflateEnd(&zs);
    if (ret != Z_STREAM_END) {
        throw(std::runtime_error("Exception during zlib compression: " + std::to_string(ret)));
    }
    std::ofstream outfile(tree_filepath, std::ios::binary);
    outfile.write(outstring.c_str(), outstring.size());
    outfile.close();
    return tree_sha;
}
// Compute the SHA1 hash of the given data and return it as a 40-character hex string.
std::string compute_sha1_as_hex(const std::string &data) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// Compress the given string using zlib and return the compressed data as a std::string.
std::string compress_data(const std::string &data) {
    uLongf compressedSize = compressBound(data.size());
    std::vector<char> buffer(compressedSize);
    int ret = compress(reinterpret_cast<Bytef*>(buffer.data()), &compressedSize,
                       reinterpret_cast<const Bytef*>(data.data()), data.size());
    if (ret != Z_OK) {
        throw std::runtime_error("Compression failed with error code: " + std::to_string(ret));
    }
    return std::string(buffer.data(), compressedSize);
}

void commit_tree(const std::string &tree_sha,
    const std::optional<std::string> &parent_commit_sha,
    const std::string &message) {
// Build the commit body using std::ostringstream.
std::ostringstream body;
body << "tree " << tree_sha << "\n";
if (parent_commit_sha.has_value() && !parent_commit_sha->empty()) {
body << "parent " << *parent_commit_sha << "\n";
}
body << "author Nikola <nikolavla@gmail.com> 708104450+0000\n";
body << "committer Nikola <nikolavla@gmail.com> 708104450+0000\n";
body << "\n" << message << "\n";
std::string body_str = body.str();

// Build the header: "commit <body_length>\0"
std::ostringstream header;
header << "commit " << body_str.size();
header.put('\0');  // Append the null byte explicitly.
std::string commit_contents = header.str() + body_str;

// Compute the commit SHA using our helper.
std::string commit_hash = compute_sha1_as_hex(commit_contents);

// Compress the commit object using our compress_data() helper.
std::string compressed_data = compress_data(commit_contents);

// Build the output path using std::ostringstream.
std::ostringstream dir_oss;
dir_oss << ".git/objects/" << commit_hash.substr(0, 2);
std::string directory = dir_oss.str();
std::filesystem::create_directories(directory);

std::ostringstream filepath;
filepath << directory << "/" << commit_hash.substr(2);
std::ofstream output(filepath.str(), std::ios::binary);
if (!output.is_open()) {
std::cerr << "Failed to write commit object file: " << filepath.str() << "\n";
exit(EXIT_FAILURE);
}
output.write(compressed_data.data(), compressed_data.size());
output.close();

// Print the commit SHA to stdout.
std::cout << commit_hash << std::endl;
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
        // Call write_tree on the current directory (ignoring .git)
        std::string tree_hash = write_tree(fs::current_path().string());
        if (tree_hash.empty()) {
            std::cerr << "Error in writing tree object\n";
            return EXIT_FAILURE;
        }
        std::cout << tree_hash << "\n";
    }else if (command == "commit-tree") {
        std::string tree_sha(argv[2]);
        std::string parent_commit_sha(argv[4]);
        std::string message(argv[6]);
        commit_tree(tree_sha, parent_commit_sha, message);
      }
    else {
        std::cerr << "Unknown command " << command << '\n';
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
