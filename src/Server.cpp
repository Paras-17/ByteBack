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
#include <openssl/evp.h>
#include <cstring>
#include <optional>
#include <ctime>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <map>
#include <stdexcept>

namespace fs = std::filesystem;
const size_t CHUNK_SIZE = 32768;
const size_t SHA_CHUNK_SIZE = 8192;

// ----------------------------------------------------------------
// Data Structures
// ----------------------------------------------------------------

struct TreeEntry {
    std::string mode; // "100644" for file, "40000" for directory
    std::string name;
    std::string sha;  // 40-char hex SHA
};

struct FileSystemEntry {
    std::string mode;
    std::string name;
    std::string hash;
};

struct GitRef {
    std::string name;
    std::string hash;
};

struct CommitInfo {
    std::string tree_hash;
    std::vector<std::string> parent_hashes;
    std::string author;
    std::string committer;
    std::string message;
};

const std::map<int, std::string> PACK_OBJECT_TYPES = {
    {1, "commit"},
    {2, "tree"},
    {3, "blob"},
    {4, "tag"},
    {6, "ofs_delta"},
    {7, "ref_delta"}
};

// ----------------------------------------------------------------
// Utility Functions
// ----------------------------------------------------------------

// Convert a 40-character hex string into its raw 20-byte binary form.
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

// Compute SHA1 hash for data and return a 40-character hex string.
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

// Compress data using zlib.
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

// Write an object to .git/objects.
// object_data must be the uncompressed data (including header).
std::string write_object(const std::string &object_data) {
    std::string hashString = compute_sha1_as_hex(object_data);
    std::string compressed = compress_data(object_data);
    std::string dir = ".git/objects/" + hashString.substr(0, 2);
    fs::create_directories(dir);
    std::string object_path = dir + "/" + hashString.substr(2);
    if (!fs::exists(object_path)) {
        std::ofstream out(object_path, std::ios::binary);
        if (!out.is_open()) {
            throw std::runtime_error("Failed to write object file: " + object_path);
        }
        out.write(compressed.data(), compressed.size());
    }
    return hashString;
}

// Read an object (after decompression) and return its content (after header).
std::string read_object(const std::string &hash, const std::string &git_base = ".") {
    std::string path = git_base + "/.git/objects/" + hash.substr(0, 2) + "/" + hash.substr(2);
    if (!fs::exists(path)) {
        throw std::runtime_error("Object not found: " + hash);
    }
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Cannot open file: " + path);
    std::ostringstream oss;
    oss << file.rdbuf();
    std::string compressed_data = oss.str();
    uLongf decompressed_size = compressed_data.size() * 4;
    std::vector<char> buffer(decompressed_size);
    int ret = uncompress(reinterpret_cast<Bytef*>(buffer.data()), &decompressed_size,
                         reinterpret_cast<const Bytef*>(compressed_data.data()),
                         compressed_data.size());
    while (ret == Z_BUF_ERROR) {
        decompressed_size *= 2;
        buffer.resize(decompressed_size);
        ret = uncompress(reinterpret_cast<Bytef*>(buffer.data()), &decompressed_size,
                         reinterpret_cast<const Bytef*>(compressed_data.data()),
                         compressed_data.size());
    }
    if (ret != Z_OK) {
        throw std::runtime_error("Decompression failed with error code: " + std::to_string(ret));
    }
    buffer.resize(decompressed_size);
    std::string full_data(buffer.begin(), buffer.end());
    auto pos = full_data.find('\0');
    if (pos == std::string::npos)
        throw std::runtime_error("Invalid object format");
    return full_data.substr(pos + 1);
}

// Returns the object path for a given hash.
std::string get_object_path(const std::string &hash, const std::string &output_path = ".") {
    return output_path + "/.git/objects/" + hash.substr(0, 2) + "/" + hash.substr(2);
}

// ----------------------------------------------------------------
// Blob & Tree Functions
// ----------------------------------------------------------------

// Create a blob object from a file.
std::string hash_object(const std::string &file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Cannot open file: " + file_path);
    std::ostringstream oss;
    oss << file.rdbuf();
    std::string content = oss.str();
    file.close();
    std::string header = "blob " + std::to_string(content.size()) + '\0';
    std::string blob_object = header + content;
    return write_object(blob_object);
}

// Recursively write a tree object from a directory and return its hash.
std::string write_tree(const std::string &dir_path) {
    fs::path dir(dir_path);
    std::vector<std::pair<std::string, std::string>> entries; // (name, entry_data)
    std::string mode, sha1;
    for (const auto &entry : fs::directory_iterator(dir)) {
        std::string name = entry.path().filename().string();
        if (name == ".git") continue;
        if (entry.is_directory()) {
            mode = "40000";
            sha1 = write_tree(entry.path().string());
        } else if (entry.is_regular_file()) {
            mode = "100644";
            sha1 = hash_object(entry.path().string());
        } else {
            continue;
        }
        // Convert 40-char SHA to raw binary.
        std::string binary_sha;
        for (size_t i = 0; i < sha1.length(); i += 2) {
            std::string byteStr = sha1.substr(i, 2);
            char byte = static_cast<char>(std::stoi(byteStr, nullptr, 16));
            binary_sha.push_back(byte);
        }
        std::string entry_data = mode + " " + name + '\0' + binary_sha;
        entries.push_back({name, entry_data});
    }
    std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
        return a.first < b.first;
    });
    std::string tree_content;
    for (const auto &p : entries) {
        tree_content += p.second;
    }
    std::string header = "tree " + std::to_string(tree_content.size());
    header.push_back('\0');
    std::string tree_store = header + tree_content;
    std::string tree_hash = write_object(tree_store);
    return tree_hash;
}

// ----------------------------------------------------------------
// Commit Functions
// ----------------------------------------------------------------

// Build commit content string given a tree hash, parent hashes, and a message.
std::string get_commit_content(
    const std::string &tree_hash,
    const std::vector<std::string> &parents,
    const std::string &message
) {
    std::string timestamp = std::to_string(std::time(nullptr));
    std::string timezone = "+0000";
    std::ostringstream commit;
    commit << "tree " << tree_hash << "\n";
    for (const auto &p : parents) {
        commit << "parent " << p << "\n";
    }
    commit << "author Nikola <nikolavla@gmail.com> " << timestamp << " " << timezone << "\n";
    commit << "committer Nikola <nikolavla@gmail.com> " << timestamp << " " << timezone << "\n";
    commit << "\n" << message << "\n";
    std::string body = commit.str();
    std::ostringstream header;
    header << "commit " << body.size();
    header.put('\0');
    return header.str() + body;
}

// Create a commit object.
void commit_tree(const std::string &tree_sha,
                 const std::optional<std::string> &parent_commit_sha,
                 const std::string &message) {
    std::vector<std::string> parents;
    if (parent_commit_sha.has_value() && !parent_commit_sha->empty()) {
        parents.push_back(*parent_commit_sha);
    }
    std::string commit_contents = get_commit_content(tree_sha, parents, message);
    std::string commit_hash = write_object(commit_contents);
    std::cout << commit_hash << std::endl;
}

// ----------------------------------------------------------------
// Clone and Packfile Functions (Simplified)
// ----------------------------------------------------------------

// CURL write callback.
size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* response = reinterpret_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

// Initialize CURL.
CURL* init_curl() {
    CURL* curl = curl_easy_init();
    if (!curl)
        throw std::runtime_error("Failed to initialize CURL");
    return curl;
}

// Perform HTTP GET.
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

// Construct remote refs URL.
std::string get_refs_url(const std::string& repo_url) {
    std::string url = repo_url;
    if (url.back() == '/')
        url.pop_back();
    return url + ".git/info/refs?service=git-upload-pack";
}

// Construct remote upload-pack URL.
std::string get_upload_pack_url(const std::string& repo_url) {
    std::string url = repo_url;
    if (url.back() == '/')
        url.pop_back();
    if (url.substr(url.size()-4) != ".git")
        url += ".git";
    return url + "/git-upload-pack";
}

// Parse remote refs from response.
std::vector<GitRef> parse_git_refs(const std::string& response) {
    std::vector<GitRef> refs;
    std::istringstream iss(response);
    std::string line;
    std::getline(iss, line);
    std::getline(iss, line);
    while (std::getline(iss, line)) {
        if (line.size() < 44) continue;
        std::string hash = line.substr(4, 40);
        size_t ref_pos = line.find(" refs/");
        if (ref_pos != std::string::npos) {
            std::string name = line.substr(ref_pos + 1);
            refs.push_back({name, hash});
        }
    }
    return refs;
}

// Fetch packfile via HTTP POST.
std::string fetch_pack(CURL* curl, const std::string& url, const std::vector<GitRef>& refs) {
    std::string response;
    std::stringstream req_body;
    if (!refs.empty()) {
        std::string want_line = "want " + refs[0].hash + "\n";
        std::stringstream length_prefix;
        length_prefix << std::hex << std::setw(4) << std::setfill('0') 
                      << (want_line.size() + 4);
        req_body << length_prefix.str() << want_line;
    }
    // Append flush and done packets.
    req_body << "0000" << "0009done\n";
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

// Minimal packfile processing: store the packfile without unpacking.
void process_packfile(const std::string& pack_data, const std::string& output_path) {
    std::string pack_dir = output_path + "/.git/objects/pack";
    fs::create_directories(pack_dir);
    std::string pack_path = pack_dir + "/packfile.pack";
    std::ofstream out(pack_path, std::ios::binary);
    if (!out.is_open())
        throw std::runtime_error("Failed to write packfile");
    out.write(pack_data.data(), pack_data.size());
    out.close();
    std::cout << "Stored packfile at " << pack_path << ". Unpacking not implemented.\n";
}

// ----------------------------------------------------------------
// Clone Functionality
// ----------------------------------------------------------------

// Initialize a Git repository in the target path.
void init_git(const std::string& target_path = ".") {
    fs::create_directories(target_path);
    fs::create_directory(target_path + "/.git");
    fs::create_directory(target_path + "/.git/objects");
    fs::create_directory(target_path + "/.git/refs");

    std::ofstream headFile(target_path + "/.git/HEAD");
    if (headFile.is_open()) {
        headFile << "ref: refs/heads/main\n";
        headFile.close();
    } else {
        throw std::runtime_error("Failed to create .git/HEAD file");
    }
}

// Clone a repository from repo_url into output_path.
void clone_repository(const std::string& repo_url, const std::string& output_path) {
    CURL* curl = init_curl();
    if (!curl)
        throw std::runtime_error("Failed to initialize CURL");
    try {
        init_git(output_path);
        std::string refs_url = get_refs_url(repo_url);
        std::string refs_response = http_get(curl, refs_url);
        auto refs = parse_git_refs(refs_response);
        if (refs.empty())
            throw std::runtime_error("No refs found from remote");
        std::string upload_pack_url = get_upload_pack_url(repo_url);
        std::string pack_response = fetch_pack(curl, upload_pack_url, refs);
        // For now, we simply store the packfile.
        process_packfile(pack_response, output_path);
        // Update HEAD (set to refs/heads/main for simplicity).
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
// Command Handlers
// ----------------------------------------------------------------

int handle_init() {
    try {
        init_git();
        std::cout << "Initialized git directory\n";
    } catch (const fs::filesystem_error& e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handle_cat_file(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " cat-file -p <hash>\n";
        return EXIT_FAILURE;
    }
    std::string hash = argv[3];
    try {
        std::string content = read_object(hash);
        std::cout << content;
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handle_hash_object(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " hash-object -w <file>\n";
        return EXIT_FAILURE;
    }
    std::string flag = argv[2];
    if (flag != "-w") {
        std::cerr << "Expected -w flag for writing the object.\n";
        return EXIT_FAILURE;
    }
    std::string file_path = argv[3];
    try {
        std::string hash = hash_object(file_path);
        std::cout << hash << "\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handle_ls_tree(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " ls-tree --name-only <tree_sha>\n";
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
    try {
        std::string content = read_object(tree_sha);
        size_t pos = content.find('\0');
        if (pos == std::string::npos) {
            std::cerr << "Invalid tree object format: header not found.\n";
            return EXIT_FAILURE;
        }
        pos++;
        while (pos < content.size()) {
            size_t space_pos = content.find(' ', pos);
            if (space_pos == std::string::npos) break;
            std::string mode = content.substr(pos, space_pos - pos);
            pos = space_pos + 1;
            size_t null_pos = content.find('\0', pos);
            if (null_pos == std::string::npos) break;
            std::string name = content.substr(pos, null_pos - pos);
            std::cout << name << "\n";
            pos = null_pos + 1 + 20; // Skip SHA bytes.
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handle_write_tree(int argc, char* argv[]) {
    try {
        std::string tree_hash = write_tree(fs::current_path().string());
        std::cout << tree_hash << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Error in writing tree object: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handle_commit_tree(int argc, char* argv[]) {
    if (argc < 7) {
        std::cerr << "Usage: " << argv[0] << " commit-tree <tree_sha> -p <commit_sha> -m <message>\n";
        return EXIT_FAILURE;
    }
    std::string tree_sha = argv[2];
    std::string parent_commit_sha = argv[4];
    std::string message = argv[6];
    try {
        commit_tree(tree_sha, parent_commit_sha, message);
    } catch (const std::exception &e) {
        std::cerr << "Commit-tree error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handle_clone(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " clone <repo_url> <output_path>\n";
        return EXIT_FAILURE;
    }
    std::string repo_url = argv[2];
    std::string output_path = argv[3];
    try {
        clone_repository(repo_url, output_path);
        std::cout << "Clone completed successfully.\n";
    } catch (const std::exception &e) {
        std::cerr << "Clone error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// ----------------------------------------------------------------
// Main: Command Dispatch
// ----------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    std::cerr << "Logs from your program will appear here!\n";
    if (argc < 2) {
        std::cerr << "No command provided.\n";
        return EXIT_FAILURE;
    }
    
    std::string command = argv[1];
    if (command == "init") {
        return handle_init();
    } else if (command == "cat-file") {
        return handle_cat_file(argc, argv);
    } else if (command == "hash-object") {
        return handle_hash_object(argc, argv);
    } else if (command == "ls-tree") {
        return handle_ls_tree(argc, argv);
    } else if (command == "write-tree") {
        return handle_write_tree(argc, argv);
    } else if (command == "commit-tree") {
        return handle_commit_tree(argc, argv);
    } else if (command == "clone") {
        return handle_clone(argc, argv);
    } else {
        std::cerr << "Unknown command " << command << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
