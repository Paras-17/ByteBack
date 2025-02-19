#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm> 
#include <zlib.h>
#include <openssl/evp.h>
#include <sstream>
#include <cstring>
#include <ctime>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <map>


const size_t CHUNK_SIZE = 32768;
const size_t SHA_CHUNK_SIZE = 8192;

namespace fs = std::filesystem;


struct FileSystemEntry {
    std::string mode;
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


struct GitObject {
    std::string type;
    std::vector<char> content;
};


struct GitRef {
    std::string name;
    std::string hash;
};


struct TreeEntry {
    std::string mode;  // File permissions (like "100644" for regular file)
    std::string type;  // "blob" for files, "tree" for directories
    std::string name;  // Filename or directory name
    std::string hash;  // SHA-1 hash of the object
};


const std::map<int, std::string> PACK_OBJECT_TYPES = {
    {1, "commit"},
    {2, "tree"},
    {3, "blob"},
    {4, "tag"},
    {6, "ofs_delta"},    // offset delta
    {7, "ref_delta"}     // reference delta
};



void check_git_initialised() {
    if (!fs::exists(".git") || ! fs::exists(".git/objects") || !fs::exists(".git/refs")) {
        throw std::runtime_error("Git is not initialised!");
    }
}

std::string get_object_path(const std::string& hash, const std::string& output_path = ".") {
    return output_path + "/.git/objects/" + hash.substr(0, 2) + "/" + hash.substr(2);
}


std::string hash_to_hex(const std::string& hash) {
    std::stringstream ss;
    for (unsigned char c : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
    }
    return ss.str();
}


std::string get_sha1_raw_for_string(const std::string& data) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha1(), NULL);
    EVP_DigestUpdate(context, data.c_str(), data.length());
    unsigned char hash[20];
    unsigned int length;
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);
    return std::string(reinterpret_cast<char*>(hash), 20);
}


std::vector<char> decompress_zlib(const std::vector<unsigned char>& compressed) {
    z_stream strm;
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    std::vector<char> uncompressed_data;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = compressed.size();
    strm.next_in = const_cast<Bytef*>(compressed.data());

    if (inflateInit(&strm) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib inflation");
    }

    int ret;
    do {
        strm.avail_out = CHUNK_SIZE;
        strm.next_out = buffer.data();
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&strm);
            throw std::runtime_error("Zlib inflation failed");
        }
        int have = CHUNK_SIZE - strm.avail_out;
        uncompressed_data.insert(uncompressed_data.end(), reinterpret_cast<char*>(buffer.data()), reinterpret_cast<char*>(buffer.data()+have));
    } while (strm.avail_out == 0);

    inflateEnd(&strm);
    return uncompressed_data;
}


std::string compress_zlib(const std::string& input) {
    if (input.empty()) {
        return {};
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
        throw std::runtime_error("Zlib deflation failed");
    }
    strm.avail_in = input.size();
    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));

    int ret;
    char buffer[CHUNK_SIZE];
    std::string compressed;

    do {
        strm.next_out = reinterpret_cast<Bytef*>(buffer);
        strm.avail_out = CHUNK_SIZE;

        ret = deflate(&strm, Z_FINISH);
        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&strm);
            throw std::runtime_error("Zlib deflation failed");
        }
        int have = CHUNK_SIZE - strm.avail_out;
        compressed.append(buffer, have);
    } while (strm.avail_out == 0);

    deflateEnd(&strm);
    return compressed;
}


std::string get_object(const std::string& hash, const std::string& git_base = ".") {
    std::string path = get_object_path(hash, git_base);
    std::cout << "path: " << path << std::endl;

    if (!fs::exists(path)) {
        throw std::runtime_error("Object not found: " + hash);
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }

    const std::vector<unsigned char> compressed_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::vector<char> decompressed = decompress_zlib(compressed_data);
    
    auto null_pos = std::find(decompressed.begin(), decompressed.end(), '\0');
    if (null_pos == decompressed.end()) {
        throw std::runtime_error("Invalid object format");
    }

    return std::string(null_pos + 1, decompressed.end());
}

bool ends_with(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string get_refs_url(const std::string& repo_url) {
    std::string git_url = repo_url;
    if (ends_with(git_url, "/")) {
        git_url = git_url.substr(0, git_url.length() - 1);
    }
    std::cout << git_url << ".git/info/refs?service=git-upload-pack" << std::endl;
    return git_url + ".git/info/refs?service=git-upload-pack";
}



std::string get_upload_pack_url(const std::string& repo_url) {
    std::string base_url = repo_url;
    if (base_url.back() == '/') base_url.pop_back();
    if (base_url.substr(base_url.length() - 4) != ".git") base_url += ".git";
    return base_url + "/git-upload-pack";
}


size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* response = (std::string*)userdata;
    response->append(ptr, size * nmemb);
    return size * nmemb;
}


CURL* init_curl() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    return curl;
}


void init_git(const std::string& target_path = ".") {
    std::filesystem::create_directories(target_path);
    std::filesystem::create_directory(target_path + "/.git");
    std::filesystem::create_directory(target_path + "/.git/objects");
    std::filesystem::create_directory(target_path + "/.git/refs");

    std::ofstream headFile(target_path + "/.git/HEAD");
    if (headFile.is_open()) {
        headFile << "ref: refs/heads/main\n";
        headFile.close();
    } else {
        throw std::runtime_error("Failed to create .git/HEAD file");
    }
}


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
        throw std::runtime_error("Failed to perform HTTP request: " + std::string(curl_easy_strerror(res)));
    }


    return response;
}


std::string fetch_pack(CURL* curl, const std::string& url, const std::vector<GitRef>& refs) {
    std::string response;
    std::stringstream request_body;
    
    for (const auto& ref : refs) {
        std::string want_line = "want " + ref.hash + "\n";
        std::stringstream length_prefix;
        length_prefix << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned int>(want_line.length() + 4);
        request_body << length_prefix.str() << want_line;
    }
    request_body << "0000" << "0009done\n"; 
    std::string request_str = request_body.str();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to perform HTTP request: " + std::string(curl_easy_strerror(res)));
    }
    
    return response;
}


std::vector<GitRef> parse_git_refs(const std::string& response) {
    std::vector<GitRef> refs;
    std::istringstream stream(response);
    std::string line;

    std::getline(stream, line); // First line with # service=git-upload-pack
    std::getline(stream, line); // Empty line (0000)

    while (std::getline(stream, line)) {
        if (line.length() < 4) continue;
        
        // Convert first 4 hex chars to length
        int length;
        std::stringstream ss;
        ss << std::hex << line.substr(0, 4);
        ss >> length;
        
        if (length == 0) continue; // Skip 0000 lines
        
        if (length >= 44) {  // Minimum length for a ref line
            std::string hash = line.substr(4, 40);
            size_t name_start = line.find(" refs/");
            if (name_start != std::string::npos) {
                std::string name = line.substr(name_start + 1);
                size_t null_pos = name.find('\0');
                if (null_pos != std::string::npos) {
                    name = name.substr(0, null_pos);
                }
                refs.push_back({name, hash});
            }
        }
    }

    return refs;
}


void store_compressed_data(const std::string& hash, const std::string& compressed, const std::string& output_path = ".") {
    std::string path = get_object_path(hash, output_path);
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream output_file(path, std::ios::binary);
    if  (!output_file) {
        throw std::runtime_error("Cannot open input file");
    }
    output_file.write(compressed.data(), compressed.size());
    output_file.close();
}


std::string get_commit_content(
    const std::string& tree_hash,   
    const std::vector<std::string>& parents, 
    const std::string& message
) {
    std::string timestamp = std::to_string(std::time(nullptr));
    std::string timezone = "+0000";

    std::string commit_content;
    commit_content += "tree " + tree_hash + '\n';
    for (auto& parent : parents) {
        commit_content += "parent " + parent + '\n';
    }
    commit_content += "author Linus Torvalds <torvalds@linux-foundation.org> " + timestamp + " " + timezone + '\n';
    commit_content += "committer Linus Torvalds <torvalds@linux-foundation.org> " + timestamp + " " + timezone + '\n';
    commit_content += '\n' + message + '\n';
    std::string header = "commit " + std::to_string(commit_content.size()) + '\0';

    return header + commit_content;
}


std::vector<unsigned char> apply_delta(
    const std::vector<unsigned char>& base, 
    const std::vector<unsigned char>& delta
) {
    std::vector<unsigned char> result;
    size_t pos = 0;

    // Read source size (variable length)
    size_t source_size = 0;
    size_t shift = 0;
    while (pos < delta.size()) {
        unsigned char byte = delta[pos++];
        source_size |= (byte & 127) << shift;
        if (!(byte & 128)) break;
        shift += 7;
    }

    // Read target size (variable length)
    size_t target_size = 0;
    shift = 0;
    while (pos < delta.size()) {
        unsigned char byte = delta[pos++];
        target_size |= (byte & 127) << shift;
        if (!(byte & 128)) break;
        shift += 7;
    }

    // Apply delta instructions
    while (pos < delta.size()) {
        unsigned char cmd = delta[pos++];
        if (cmd & 128) {  // copy instruction
            size_t offset = 0;
            size_t size = 0;
            if (cmd & 1) offset |= delta[pos++];
            if (cmd & 2) offset |= delta[pos++] << 8;
            if (cmd & 4) offset |= delta[pos++] << 16;
            if (cmd & 8) offset |= delta[pos++] << 24;
            if (cmd & 16) size |= delta[pos++];
            if (cmd & 32) size |= delta[pos++] << 8;
            if (cmd & 64) size |= delta[pos++] << 16;
            if (size == 0) size = 0x10000;
            
            if (offset + size > base.size()) {
                throw std::runtime_error("Delta copy out of bounds");
            }
            result.insert(result.end(), 
                         base.begin() + offset, 
                         base.begin() + offset + size);
        } else if (cmd) {  // insert instruction
            if (pos + cmd > delta.size()) {
                throw std::runtime_error("Delta insert out of bounds");
            }
            result.insert(result.end(), 
                         delta.begin() + pos, 
                         delta.begin() + pos + cmd);
            pos += cmd;
        } else {
            throw std::runtime_error("Invalid delta instruction");
        }
    }

    if (result.size() != target_size) {
        throw std::runtime_error("Delta reconstruction size mismatch");
    }

    return result;
}


void process_packfile(const std::string& pack_data, const std::string& output_path) {
    // 0008NAK\n          NAK response
    // PACK[...]          Packfile data
    // 0000               End marker

    // skip NAK
    size_t pos = pack_data.find('\n');
    pos++;

    // check PACK
    if (pack_data.substr(pos, 4) != "PACK") {
        throw std::runtime_error("Invalid pack signature");
    }
    pos += 4;

    // version parsing
    uint32_t version;
    memcpy(&version, pack_data.data() + pos, 4);
    version = ntohl(version);
    pos += 4;

    // number of objects parsing
    uint32_t num_objects;
    memcpy(&num_objects, pack_data.data() + pos, 4);
    num_objects = ntohl(num_objects);
    pos += 4;
    
    std::cout << "version: " << version << ", num_objects: " << num_objects << ", size: " << pack_data.size() << std::endl;

    // read each object
    for (uint32_t i = 0; i < num_objects; i++) {
        uint8_t byte = pack_data[pos++];
        int type = (byte >> 4) & 7;
        size_t size = byte & 15;
        size_t shift = 4;

        std::cout << "Processing object " << i << ", type: " << type << ", initial pos: " << pos << std::endl;

        // parse variable length size
        while (byte & 128) {
            byte = pack_data[pos++];
            size |= (byte & 127) << shift;
            shift += 7;
        }

        std::cout << "Object size: " << size << ", pos after size: " << pos << std::endl;

        size_t start_pos = pos; 
        if (type == 1 || type == 2 || type == 3 || type == 4) {
            // decompress
            z_stream zs;
            memset(&zs, 0, sizeof(zs));
            if (inflateInit(&zs) != Z_OK) {
                throw std::runtime_error("Failed to initialize zlib");
            }
            zs.next_in = (Bytef*)(pack_data.data() + pos);
            zs.avail_in = pack_data.size() - pos;
            std::vector<unsigned char> uncompressed;
            unsigned char outbuffer[8192];
            do {
                zs.next_out = outbuffer;
                zs.avail_out = sizeof(outbuffer);
                int ret = inflate(&zs, Z_NO_FLUSH);
                if (ret != Z_OK && ret != Z_STREAM_END) {
                    inflateEnd(&zs);
                    throw std::runtime_error("Decompression failed");
                }
                uncompressed.insert(uncompressed.end(), outbuffer, outbuffer + (sizeof(outbuffer) - zs.avail_out));
            } while (zs.avail_out == 0);
            pos += zs.total_in;
            inflateEnd(&zs);

            // save
            std::string full_object = PACK_OBJECT_TYPES.at(type) + " " + std::to_string(uncompressed.size()) + '\0';
            full_object.insert(full_object.end(), uncompressed.begin(), uncompressed.end());
            std::string compressed = compress_zlib(full_object);
            std::string hash = get_sha1_raw_for_string(full_object);
            std::cout << "hash: " << hash_to_hex(hash) << std::endl;
            store_compressed_data(hash_to_hex(hash), compressed, output_path);

            // final check
            if (uncompressed.size() != size) {
                throw std::runtime_error("Uncompressed size mismatch");
            }
        } else if (type == 6) {  // ofs_delta
            size_t offset = 0;
            do {
                if (pos >= pack_data.size()) {
                    throw std::runtime_error("Unexpected end of data while parsing offset");
                }
                byte = pack_data[pos++];
                offset = ((offset + 1) << 7) | (byte & 127);
            } while (byte & 128);
        } else if (type == 7) {  // ref_delta
            // Read 20-byte base object SHA-1
            if (pos + 20 > pack_data.size()) {
                throw std::runtime_error("Unexpected end of data while parsing ref-delta");
            }
            std::string raw_object_hash = pack_data.substr(pos, 20);
            std::string object_hash = hash_to_hex(raw_object_hash);
            pos += 20;

            // decompress
            z_stream zs;
            memset(&zs, 0, sizeof(zs));
            if (inflateInit(&zs) != Z_OK) {
                throw std::runtime_error("Failed to initialize zlib");
            }
            zs.next_in = (Bytef*)(pack_data.data() + pos);
            zs.avail_in = pack_data.size() - pos;
            std::vector<unsigned char> uncompressed;
            unsigned char outbuffer[8192];
            do {
                zs.next_out = outbuffer;
                zs.avail_out = sizeof(outbuffer);
                int ret = inflate(&zs, Z_NO_FLUSH);
                if (ret != Z_OK && ret != Z_STREAM_END) {
                    inflateEnd(&zs);
                    throw std::runtime_error("Decompression failed");
                }
                uncompressed.insert(uncompressed.end(), outbuffer, outbuffer + (sizeof(outbuffer) - zs.avail_out));
            } while (zs.avail_out == 0);
            pos += zs.total_in;
            inflateEnd(&zs);

            std::cout << "object_hash: " << object_hash << std::endl;
            // Get base object
            std::string base_object = get_object(object_hash, output_path);

            // Apply delta
            std::vector<unsigned char> reconstructed = apply_delta(
                std::vector<unsigned char>(base_object.begin(), base_object.end()),
                uncompressed
            );

            // Save reconstructed object
            std::string full_object = "blob " + std::to_string(reconstructed.size()) + '\0';
            full_object.insert(full_object.end(), reconstructed.begin(), reconstructed.end());
            std::string compressed = compress_zlib(full_object);
            std::string hash = get_sha1_raw_for_string(full_object);
            std::cout << "hash: " << hash_to_hex(hash) << std::endl;
            store_compressed_data(hash_to_hex(hash), compressed, output_path);

            // final check
            if (uncompressed.size() != size) {
                throw std::runtime_error("Uncompressed size mismatch");
            }
        }

        // std::cout << "num: " << i << ", type: " << type << ", size: " << size << ", pos: " << pos << std::endl;
        std::cout << "Consumed bytes: " << (pos - start_pos) << std::endl;
        std::cout << "New pos: " << pos << std::endl;
        std::cout << "------------------------" << std::endl;

    }
}


void write_files(const std::string& tree_hash, const std::string& git_path, const std::string& output_path) {
    auto tree_content = get_object(tree_hash, git_path);

    size_t pos = 0;
    while (pos < tree_content.size()) {
        std::cout << "tree_hash: " << tree_hash << ", pos: " << pos << std::endl;

        // Parse mode (e.g., "100644")
        size_t space = tree_content.find(' ', pos);
        std::string mode = tree_content.substr(pos, space - pos);
        pos = space + 1;

        // Parse name
        size_t null_term = tree_content.find('\0', pos);
        std::string name = tree_content.substr(pos, null_term - pos);
        pos = null_term + 1;

        // Get hash (20 bytes)
        std::string hash = tree_content.substr(pos, 20);
        std::string hex_hash = hash_to_hex(hash);
        pos += 20;

        std::cout << "name: " << name << ", hex_hash: " << hex_hash << ", mode: " << mode << std::endl;

        std::string full_path = output_path + "/" + name;
        std::cout << "full_path: " << full_path << std::endl;

        if (mode == "40000") {  // Directory
            if (!std::filesystem::exists(full_path)) {
                std::filesystem::create_directory(full_path);
            }
            write_files(hex_hash, git_path, full_path);  // Recursively process subdirectory
        } else {  // File
            auto blob_content = get_object(hex_hash, git_path);
            std::ofstream file(full_path, std::ios::binary);
            file.write(blob_content.data(), blob_content.size());
        }
    }
}


std::string get_sha1(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }
    size_t file_size = file.tellg();
    file.seekg(0);

    std::string header = "blob " + std::to_string(file_size) + '\0';

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha1(), NULL);

    EVP_DigestUpdate(context, header.c_str(), header.length());

    char buffer[SHA_CHUNK_SIZE];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(context, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        EVP_DigestUpdate(context, buffer, file.gcount());
    }

    unsigned char hash[20];
    unsigned int length;
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);
    return std::string(reinterpret_cast<char*>(hash), 20);
}


void write_hash_object(const std::string& input_path, const std::string& hash) {
    std::ifstream file(input_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::string to_compress = "blob " + std::to_string(file_size) + '\0' + content;
    std::string compressed = compress_zlib(to_compress);

    std::string output_path = get_object_path(hash);
    fs::create_directories(fs::path(output_path).parent_path());
    std::ofstream output_file(output_path, std::ios::binary);
    if  (!output_file) {
        throw std::runtime_error("Cannot open input file");
    }
    output_file.write(compressed.data(), compressed.size());
    output_file.close();
}


std::vector<std::string> ls_tree_names(std::vector<char>& tree_data) {
    std::vector<std::string> names;
    size_t pos = 0;

    // tree 100\0                  # Header: "tree " + size + null byte
    // 100644 file1.txt\0xxxxx     # mode + space + filename + null + SHA-1 (20 bytes)
    // 100644 file2.txt\0yyyyy     # next entry
    // 040000 folder\0zzzzz        # directory entry
    //
    // [mode] space [path] 0x00 [sha-1]


    // skip header
    while (pos < tree_data.size() && tree_data[pos] != '\0') {
        pos++;
    }
    // skip null byte
    pos++;

    while (pos < tree_data.size()) {
        // skip mode
        while (pos < tree_data.size() && tree_data[pos] != ' ') {
            pos++;
        }
        // skip space
        pos++;

        std::string name;
        while (pos < tree_data.size() && tree_data[pos] != '\0') {
            name += tree_data[pos++];
        }
        names.push_back(name);

        // skip null byte
        pos++;
        // skip sha1
        pos += 20;
    }
    return names;
}


std::string write_tree(const std::string& dir_path) {
    std::vector<FileSystemEntry> fs_entries;
    for (const auto& entry : fs::directory_iterator(dir_path)) {
        FileSystemEntry fs_entry;
        fs_entry.name = entry.path().filename().string();
        if (fs_entry.name == ".git") {
            continue;
        } else if (fs::is_regular_file(entry)) {
            fs_entry.mode = "100644";
            std::string raw_hash = get_sha1(entry.path());
            fs_entry.hash = raw_hash;
            write_hash_object(entry.path(), hash_to_hex(raw_hash));
        } else if (fs::is_directory(entry)) {
            fs_entry.mode = "40000";
            fs_entry.hash = write_tree(entry.path());
        } else {
            continue;
        }
        fs_entries.push_back(fs_entry);
    }

    std::sort(fs_entries.begin(), fs_entries.end(), [](const FileSystemEntry& a, const FileSystemEntry& b){
        return a.name < b.name;
    });

    std::string tree_content;
    for (const auto& fs_entry : fs_entries) {
        tree_content += fs_entry.mode;
        tree_content += " ";
        tree_content += fs_entry.name;
        tree_content += '\0';
        tree_content += fs_entry.hash;
    }

    std::string to_compress = "tree " + std::to_string(tree_content.size()) + '\0' + tree_content;
    std::string tree_hash = get_sha1_raw_for_string(to_compress);
    std::string compressed = compress_zlib(to_compress);
    store_compressed_data(hash_to_hex(tree_hash), compressed);
    return tree_hash;
}


std::string commit_tree(const std::string& tree_hash, const std::string& parent, const std::string& message) {
    std::string to_compress = get_commit_content(tree_hash, {parent}, message);
    std::string raw_hash = get_sha1_raw_for_string(to_compress);
    std::string compressed = compress_zlib(to_compress);
    store_compressed_data(hash_to_hex(raw_hash), compressed);
    return raw_hash;
}


void clone_repository(const std::string& repo_url, const std::string& output_path) {
    CURL* curl = init_curl();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    try {
        init_git(output_path);
        auto refs_resp = http_get(curl, get_refs_url(repo_url));
        auto refs = parse_git_refs(refs_resp);
        auto pack_resp = fetch_pack(curl, get_upload_pack_url(repo_url), refs);
        process_packfile(pack_resp, output_path);

        std::string head_hash;
        for (const auto& ref : refs) {
            if (ref.name == "HEAD" || ref.name == "refs/heads/master" || ref.name == "refs/heads/main") {
                head_hash = ref.hash;
                break;
            }
        }

        if (head_hash.empty()) {
            throw std::runtime_error("Could not find HEAD reference");
        }

        // Get commit object
        auto commit_content = get_object(head_hash, output_path);

        const std::string tree_prefix = "tree ";
        size_t tree_pos = commit_content.find(tree_prefix);
        if (tree_pos == std::string::npos) {
            throw std::runtime_error("Invalid commit format: cannot find tree");
        }
        tree_pos += tree_prefix.length();
        size_t tree_end = commit_content.find('\n', tree_pos);
        if (tree_end == std::string::npos) {
            throw std::runtime_error("Invalid commit format: cannot find end of tree hash");
        }
        std::string tree_hash = commit_content.substr(tree_pos, tree_end - tree_pos);

        write_files(tree_hash, output_path, output_path);

        curl_easy_cleanup(curl);
    } catch (const std::exception& e) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Clone failed: " + std::string(e.what()));
    }
}


int handle_init() {
    try {
        init_git();
        std::cout << "Initialized git directory\n";
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


int handle_cat_file(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " cat-file -p <hash>" << std::endl;
        return EXIT_FAILURE;
    }
    check_git_initialised();
    std::string hash = argv[3];
    std::string object_path = get_object_path(hash);
    if (!fs::exists(object_path)) {
        std::cerr << "Object not found: " << hash << std::endl;
        return EXIT_FAILURE;
    }
    std::ifstream file(object_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }

    const std::vector<unsigned char> compressed_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    std::vector<char> decompressed_data = decompress_zlib(compressed_data);

    auto content_start = std::find(decompressed_data.begin(), decompressed_data.end(), '\0');

    if (content_start != decompressed_data.end()) {
        std::string text_data(content_start + 1, decompressed_data.end());
        std::cout << text_data;   
    }
    return EXIT_SUCCESS;
}


int handle_hash_object(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " hash-object -w <file>" << std::endl;
        return EXIT_FAILURE;
    }
    check_git_initialised();
    std::string input_path = argv[3];
    std::string raw_hash = get_sha1(input_path);
    std::string hash = hash_to_hex(raw_hash);
    std::cout << hash << std::endl;
    write_hash_object(input_path, hash);
    return EXIT_SUCCESS;
}


int handle_ls_tree_object(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " ls-tree --name-only <tree_sha>" << std::endl;
        return EXIT_FAILURE;
    }
    check_git_initialised();
    std::string hash = argv[3];
    std::string object_path = get_object_path(hash);
    if (!fs::exists(object_path)) {
        std::cerr << "Object not found: " << hash << std::endl;
        return EXIT_FAILURE;
    }
    std::ifstream file(object_path, std::ios::binary);
    const std::vector<unsigned char> compressed_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    std::vector<char> decompressed_data = decompress_zlib(compressed_data);
    auto names = ls_tree_names(decompressed_data);
    for (auto& name : names) {
        std::cout << name << std::endl;
    }
    return EXIT_SUCCESS;
}


int handle_write_tree_object(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " write-tree" << std::endl;
        return EXIT_FAILURE;
    }
    check_git_initialised();
    std::string hash = write_tree(".");
    std::cout << hash_to_hex(hash) << std::endl;
    return EXIT_SUCCESS;
}


int handle_commit_tree_object(int argc, char *argv[]) {
    if (argc < 7) {
        std::cerr << "Usage: " << argv[0] << " commit-tree <tree_sha> -p <commit_sha> -m <message>" << std::endl;
        return EXIT_FAILURE;
    }
    check_git_initialised();
    std::string tree_sha = argv[2];
    std::string commit_sha = argv[4];
    std::string message = argv[6];
    std::string hash = commit_tree(tree_sha, commit_sha, message);
    std::cout << hash_to_hex(hash) << std::endl;
    return EXIT_SUCCESS;
}


int handle_clone(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " clone <repo_url> <output_path>" << std::endl;
        return EXIT_FAILURE;
    }
    try {
        std::string repo_url = argv[2];
        std::string output_path = argv[3];
        clone_repository(repo_url, output_path);
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}


int handle_unknown(std::string& command) {
    std::cerr << "Unknown command " << command << '\n';
    return EXIT_FAILURE;
}


int main(int argc, char *argv[])
{
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

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
        return handle_ls_tree_object(argc, argv);
    } else if (command == "write-tree") {
        return handle_write_tree_object(argc, argv);
    } else if (command == "commit-tree") {
        return handle_commit_tree_object(argc, argv);
    } else if (command == "clone") {
        return handle_clone(argc, argv);
    } else {
        return handle_unknown(command);
    }
}