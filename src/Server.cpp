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
#include <ctime>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <map>
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



// --- Data Structures for Refs ---
struct GitRef {
    std::string name;
    std::string hash;
};

// --- Helper: Build object path ---
std::string get_object_path(const std::string& hash, const std::string& output_path = ".") {
    return output_path + "/.git/objects/" + hash.substr(0, 2) + "/" + hash.substr(2);
}

// --- Helper: Convert hash to hex string (if given raw binary) ---
std::string hash_to_hex(const std::string& hash) {
    std::stringstream ss;
    for (unsigned char c : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

// --- CURL Write Callback ---
size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* response = reinterpret_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

// --- Initialize CURL ---
CURL* init_curl() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    return curl;
}

// --- HTTP GET ---
std::string http_get(CURL* curl, const std::string& url) {
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("HTTP GET failed: " + std::string(curl_easy_strerror(res)));
    }
    return response;
}

// --- Get Remote Refs URL ---
std::string get_refs_url(const std::string& repo_url) {
    std::string url = repo_url;
    if (url.back() == '/') {
        url.pop_back();
    }
    // Append ".git/info/refs?service=git-upload-pack"
    return url + ".git/info/refs?service=git-upload-pack";
}

// --- Get Upload Pack URL ---
std::string get_upload_pack_url(const std::string& repo_url) {
    std::string url = repo_url;
    if (url.back() == '/') {
        url.pop_back();
    }
    if (url.substr(url.size()-4) != ".git") {
        url += ".git";
    }
    return url + "/git-upload-pack";
}

// --- Parse Remote Refs ---
// Very simple parser: splits lines and extracts ref names and hashes.
std::vector<GitRef> parse_git_refs(const std::string& response) {
    std::vector<GitRef> refs;
    std::istringstream iss(response);
    std::string line;
    // Skip first two lines (protocol header and blank line)
    std::getline(iss, line);
    std::getline(iss, line);
    while (std::getline(iss, line)) {
        if (line.size() < 44) continue;
        // Assume hash is characters 4-43 and ref name starts at index 44
        std::string hash = line.substr(4, 40);
        size_t ref_pos = line.find(" refs/");
        if (ref_pos != std::string::npos) {
            std::string name = line.substr(ref_pos + 1);
            refs.push_back({name, hash});
        }
    }
    return refs;
}
void init_git(const std::string& target_path = ".") {
    // Create the target directory if it doesn't exist.
    fs::create_directories(target_path);
    // Create the .git directory and its subdirectories.
    fs::create_directory(target_path + "/.git");
    fs::create_directory(target_path + "/.git/objects");
    fs::create_directory(target_path + "/.git/refs");

    // Create the HEAD file with the default reference.
    std::ofstream headFile(target_path + "/.git/HEAD");
    if (headFile.is_open()) {
        headFile << "ref: refs/heads/main\n";
        headFile.close();
    } else {
        throw std::runtime_error("Failed to create .git/HEAD file");
    }
}

// --- Fetch Pack ---
// Builds a simple request body (with "want" lines) and performs an HTTP POST.
std::string fetch_pack(CURL* curl, const std::string& url, const std::vector<GitRef>& refs) {
    std::string response;
    std::stringstream req_body;
    // For simplicity, request the first ref (you could improve this to request more).
    if (!refs.empty()) {
        std::string want_line = "want " + refs[0].hash + "\n";
        // The length prefix is the length of the want_line plus 4 (for the prefix itself).
        std::stringstream length_prefix;
        length_prefix << std::hex << std::setw(4) << std::setfill('0') << (want_line.size() + 4);
        req_body << length_prefix.str() << want_line;
    }
    // End the request with "0000"
    req_body << "0000";
    std::string req_str = req_body.str();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_str.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("HTTP POST failed: " + std::string(curl_easy_strerror(res)));
    }
    return response;
}

// --- Process Packfile ---
// This is a simplified function to process a packfile response from the server.
// In a complete implementation, you would parse the packfile format and write objects.
void process_packfile(const std::string& pack_data, const std::string& output_path) {
    // For demonstration, we just print the packfile size.
    std::cout << "Received packfile of size " << pack_data.size() << " bytes.\n";
    // TODO: Unpack the packfile and write objects to .git/objects.
    // You can reuse your existing packfile processing functions here.
}

// --- Clone Repository ---
// This function ties together the clone process.
void clone_repository(const std::string& repo_url, const std::string& output_path) {
    // Initialize CURL.
    CURL* curl = init_curl();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    try {
        // Initialize the local repository structure in output_path.
        init_git(output_path);
        // Fetch remote refs.
        std::string refs_url = get_refs_url(repo_url);
        std::string refs_response = http_get(curl, refs_url);
        auto refs = parse_git_refs(refs_response);
        if (refs.empty()) {
            throw std::runtime_error("No refs found from remote");
        }
        // Fetch packfile using the first ref (for simplicity).
        std::string upload_pack_url = get_upload_pack_url(repo_url);
        std::string pack_response = fetch_pack(curl, upload_pack_url, refs);
        // Process the packfile to populate .git/objects.
        process_packfile(pack_response, output_path);
        // Optionally, update HEAD (for example, set HEAD to the ref "refs/heads/main")
        std::ofstream headFile(fs::path(output_path) / ".git/HEAD");
        if (headFile.is_open()) {
            headFile << "ref: refs/heads/main\n";
            headFile.close();
        }
        curl_easy_cleanup(curl);
    } catch (const std::exception& e) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Clone failed: " + std::string(e.what()));
    }
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
      }else if (command == "clone") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " clone <repo_url> <output_path>" << std::endl;
            return EXIT_FAILURE;
        }
        try {
            std::string repo_url = argv[2];
            std::string output_path = argv[3];
            clone_repository(repo_url, output_path);
            std::cout << "Clone completed successfully.\n";
        } catch (const std::exception& e) {
            std::cerr << "Clone error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    }
    else {
        std::cerr << "Unknown command " << command << '\n';
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
