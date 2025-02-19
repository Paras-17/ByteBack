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

// =============================================================================
// MIND MAP: Git Object Storage Overview
// =============================================================================
/*
    Git Objects
    ├── Blob:
    │    ├── Content = File data
    │    ├── Header: "blob <size>\0"
    │    └── Stored compressed in .git/objects/XX/...
    ├── Tree:
    │    ├── Represents a directory snapshot
    │    ├── Each entry: "<mode> <name>\0" + raw 20-byte SHA
    │    └── Header: "tree <payload_size>\0"
    └── Commit:
         ├── Contains tree hash, parent(s), author, committer, message
         └── Header: "commit <body_size>\0"
*/

// =============================================================================
// Data Structures and Type Definitions
// =============================================================================

// Structure representing a directory (tree) entry.
struct DirEntry {
    std::string fileMode;   // e.g., "100644" for files, "40000" for directories
    std::string fileName;
    std::string objectHash; // 40-character hexadecimal SHA-1
};

// Structure representing a filesystem entry (used when building trees).
struct FS_Entry {
    std::string fileMode;
    std::string fileName;
    std::string objectHash;
};

// Structure representing a Git reference.
struct GitReference {
    std::string refName;
    std::string refHash;
};

// Structure representing commit metadata.
struct CommitMetadata {
    std::string treeHash;
    std::vector<std::string> parentHashes;
    std::string authorInfo;
    std::string committerInfo;
    std::string commitMessage;
};

// Mapping for packfile object types (used in clone functionality).
const std::map<int, std::string> PACK_OBJ_TYPE_MAP = {
    {1, "commit"},
    {2, "tree"},
    {3, "blob"},
    {4, "tag"},
    {6, "ofs_delta"},
    {7, "ref_delta"}
};

// =============================================================================
// Utility Functions (SHA, Compression, File I/O)
// =============================================================================

// Convert a 40-char hex string into a raw 20-byte string.
std::string convertHexToRaw(const std::string &hexStr) {
    std::string rawBytes;
    rawBytes.resize(20);
    for (size_t i = 0; i < 20; ++i) {
        std::string byteHex = hexStr.substr(i * 2, 2);
        unsigned int byteVal;
        std::istringstream(byteHex) >> std::hex >> byteVal;
        rawBytes[i] = static_cast<char>(byteVal);
    }
    return rawBytes;
}

// Compute the SHA-1 hash for the given data and return it as a 40-character hex string.
std::string computeSHA1Hex(const std::string &data) {
    unsigned char hashResult[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hashResult);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(hashResult[i]);
    }
    return oss.str();
}

// Compress input string using zlib.
std::string compressString(const std::string &inputData) {
    uLongf compSize = compressBound(inputData.size());
    std::vector<char> compBuffer(compSize);
    int res = compress(reinterpret_cast<Bytef*>(compBuffer.data()), &compSize,
                       reinterpret_cast<const Bytef*>(inputData.data()), inputData.size());
    if (res != Z_OK) {
        throw std::runtime_error("Zlib compression failed with error: " + std::to_string(res));
    }
    return std::string(compBuffer.data(), compSize);
}

// Write a Git object (blob, tree, commit) to .git/objects using its SHA hash for storage.
std::string storeGitObject(const std::string &uncompressedData) {
    // Compute SHA-1 hash.
    std::string objHash = computeSHA1Hex(uncompressedData);
    // Compress data.
    std::string compData = compressString(uncompressedData);
    // Build object path: .git/objects/<first two chars>/<remaining>
    std::string objDir = ".git/objects/" + objHash.substr(0, 2);
    fs::create_directories(objDir);
    std::string objPath = objDir + "/" + objHash.substr(2);
    // Write object if it doesn't exist.
    if (!fs::exists(objPath)) {
        std::ofstream outFile(objPath, std::ios::binary);
        if (!outFile.is_open())
            throw std::runtime_error("Unable to write object file: " + objPath);
        outFile.write(compData.data(), compData.size());
    }
    return objHash;
}

// Read and decompress a Git object from .git/objects.
std::string retrieveGitObject(const std::string &hash, const std::string &baseDir = ".") {
    std::string path = baseDir + "/.git/objects/" + hash.substr(0, 2) + "/" + hash.substr(2);
    if (!fs::exists(path))
        throw std::runtime_error("Git object not found: " + hash);
    std::ifstream inFile(path, std::ios::binary);
    if (!inFile)
        throw std::runtime_error("Cannot open Git object file: " + path);
    std::ostringstream oss;
    oss << inFile.rdbuf();
    std::string compData = oss.str();
    uLongf decompSize = compData.size() * 4;
    std::vector<char> buffer(decompSize);
    int ret = uncompress(reinterpret_cast<Bytef*>(buffer.data()), &decompSize,
                         reinterpret_cast<const Bytef*>(compData.data()), compData.size());
    while (ret == Z_BUF_ERROR) {
        decompSize *= 2;
        buffer.resize(decompSize);
        ret = uncompress(reinterpret_cast<Bytef*>(buffer.data()), &decompSize,
                         reinterpret_cast<const Bytef*>(compData.data()), compData.size());
    }
    if (ret != Z_OK)
        throw std::runtime_error("Decompression of Git object failed with error: " + std::to_string(ret));
    buffer.resize(decompSize);
    std::string fullData(buffer.begin(), buffer.end());
    // Skip header up to the first null character.
    size_t headerEnd = fullData.find('\0');
    if (headerEnd == std::string::npos)
        throw std::runtime_error("Malformed Git object: header not found");
    return fullData.substr(headerEnd + 1);
}

// Return object path based on SHA.
std::string buildObjectPath(const std::string &hash, const std::string &baseDir = ".") {
    return baseDir + "/.git/objects/" + hash.substr(0, 2) + "/" + hash.substr(2);
}

// =============================================================================
// Blob and Tree Functions
// =============================================================================

/*
    MIND MAP: Blob and Tree Creation
    ├── Blob:
    │    ├── Read file contents.
    │    ├── Build header: "blob <filesize>\0".
    │    └── Store compressed object.
    └── Tree:
         ├── For each entry in a directory:
         │     ├── File → Create blob.
         │     └── Directory → Recursively create tree.
         ├── Build entry: "<mode> <name>\0" + raw SHA.
         ├── Concatenate entries and prepend header: "tree <payload_size>\0".
         └── Store compressed tree object.
*/

// Create a blob object from a file.
std::string createBlobFromFile(const std::string &filePath) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile.is_open())
        throw std::runtime_error("Unable to open file for blob: " + filePath);
    std::ostringstream contentStream;
    contentStream << inFile.rdbuf();
    std::string fileContent = contentStream.str();
    inFile.close();

    std::string blobHeader = "blob " + std::to_string(fileContent.size()) + '\0';
    std::string blobData = blobHeader + fileContent;
    return storeGitObject(blobData);
}

// Recursively create a tree object from a directory.
std::string createTreeFromDirectory(const std::string &directoryPath) {
    fs::path dirPath(directoryPath);
    std::vector<std::pair<std::string, std::string>> treeEntries; // (entryName, entryData)
    std::string fileMode, objHash;

    for (const auto &entry : fs::directory_iterator(dirPath)) {
        std::string entryName = entry.path().filename().string();
        if (entryName == ".git")
            continue;
        if (entry.is_directory()) {
            fileMode = "40000";
            objHash = createTreeFromDirectory(entry.path().string());
        } else if (entry.is_regular_file()) {
            fileMode = "100644";
            objHash = createBlobFromFile(entry.path().string());
        } else {
            continue;
        }
        // Convert hex SHA to raw 20-byte string.
        std::string rawHash;
        for (size_t i = 0; i < objHash.length(); i += 2) {
            std::string byteStr = objHash.substr(i, 2);
            char byte = static_cast<char>(std::stoi(byteStr, nullptr, 16));
            rawHash.push_back(byte);
        }
        std::string entryData = fileMode + " " + entryName + '\0' + rawHash;
        treeEntries.push_back({entryName, entryData});
    }
    // Sort entries alphabetically by name.
    std::sort(treeEntries.begin(), treeEntries.end(), [](const auto &a, const auto &b) {
        return a.first < b.first;
    });
    std::string payload;
    for (const auto &p : treeEntries) {
        payload += p.second;
    }
    std::string treeHeader = "tree " + std::to_string(payload.size());
    treeHeader.push_back('\0');
    std::string fullTreeData = treeHeader + payload;
    return storeGitObject(fullTreeData);
}

// =============================================================================
// Commit Functions
// =============================================================================

/*
    MIND MAP: Commit Object Creation
    ├── Commit content includes:
    │     - Tree hash
    │     - Parent commit(s) (if any)
    │     - Author information
    │     - Committer information
    │     - Commit message
    ├── Header: "commit <body_size>\0"
    └── Store commit as Git object.
*/

// Build commit object content.
std::string buildCommitContent(const std::string &treeHash,
                               const std::vector<std::string> &parentHashes,
                               const std::string &commitMessage) {
    std::string timestamp = std::to_string(std::time(nullptr));
    std::string tz = "+0000";
    std::ostringstream commitStream;
    commitStream << "tree " << treeHash << "\n";
    for (const auto &parent : parentHashes) {
        commitStream << "parent " << parent << "\n";
    }
    commitStream << "author Nikola <nikolavla@gmail.com> " << timestamp << " " << tz << "\n";
    commitStream << "committer Nikola <nikolavla@gmail.com> " << timestamp << " " << tz << "\n";
    commitStream << "\n" << commitMessage << "\n";
    std::string commitBody = commitStream.str();
    std::ostringstream headerStream;
    headerStream << "commit " << commitBody.size();
    headerStream.put('\0');
    return headerStream.str() + commitBody;
}

// Create a commit object, store it, and print its hash.
void createCommit(const std::string &treeHash,
                  const std::optional<std::string> &parentCommitHash,
                  const std::string &commitMsg) {
    std::vector<std::string> parentList;
    if (parentCommitHash.has_value() && !parentCommitHash->empty()) {
        parentList.push_back(*parentCommitHash);
    }
    std::string commitContent = buildCommitContent(treeHash, parentList, commitMsg);
    std::string commitHash = storeGitObject(commitContent);
    std::cout << commitHash << std::endl;
}

// =============================================================================
// Clone and Packfile Functions (Simplified)
// =============================================================================

/*
    MIND MAP: Cloning a Repository (Simplified)
    ├── Initialize Local Repo (init_git)
    ├── Fetch Remote Refs (HTTP GET from .../info/refs)
    ├── Parse Refs
    ├── Request Packfile (HTTP POST to .../git-upload-pack)
    └── Process Packfile (stub: store packfile for now)
*/

size_t curlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* resp = reinterpret_cast<std::string*>(userdata);
    resp->append(ptr, size * nmemb);
    return size * nmemb;
}

CURL* setupCurl() {
    CURL* curlHandle = curl_easy_init();
    if (!curlHandle)
        throw std::runtime_error("CURL initialization failed");
    return curlHandle;
}

std::string performHttpGet(CURL* curlHandle, const std::string &url) {
    std::string resp;
    curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode result = curl_easy_perform(curlHandle);
    if (result != CURLE_OK) {
        curl_easy_cleanup(curlHandle);
        throw std::runtime_error("HTTP GET error: " + std::string(curl_easy_strerror(result)));
    }
    return resp;
}

std::string constructRefsURL(const std::string &repoURL) {
    std::string modURL = repoURL;
    if (ends_with(modURL, "/"))
        modURL = modURL.substr(0, modURL.length() - 1);
    std::cout << modURL << ".git/info/refs?service=git-upload-pack" << std::endl;
    return modURL + ".git/info/refs?service=git-upload-pack";
}

std::string constructUploadPackURL(const std::string &repoURL) {
    std::string baseURL = repoURL;
    if (baseURL.back() == '/')
        baseURL.pop_back();
    if (baseURL.substr(baseURL.size() - 4) != ".git")
        baseURL += ".git";
    return baseURL + "/git-upload-pack";
}

std::vector<GitReference> parseRefsResponse(const std::string &response) {
    std::vector<GitReference> refs;
    std::istringstream stream(response);
    std::string line;
    std::getline(stream, line); // Skip protocol header
    std::getline(stream, line); // Skip empty line
    while (std::getline(stream, line)) {
        if (line.size() < 44)
            continue;
        std::string refHash = line.substr(4, 40);
        size_t pos = line.find(" refs/");
        if (pos != std::string::npos) {
            std::string refName = line.substr(pos + 1);
            refs.push_back({refName, refHash});
        }
    }
    return refs;
}

std::string performHttpPost(CURL* curlHandle, const std::string &url, const std::string &postData) {
    std::string resp;
    curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curlHandle, CURLOPT_POST, 1L);
    curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode result = curl_easy_perform(curlHandle);
    if (result != CURLE_OK) {
        curl_easy_cleanup(curlHandle);
        throw std::runtime_error("HTTP POST error: " + std::string(curl_easy_strerror(result)));
    }
    return resp;
}

// Simplified: Store the packfile to .git/objects/pack/packfile.pack (unpacking not implemented).
void handlePackfile(const std::string &packData, const std::string &baseDir) {
    std::string packDir = baseDir + "/.git/objects/pack";
    fs::create_directories(packDir);
    std::string packPath = packDir + "/packfile.pack";
    std::ofstream packOut(packPath, std::ios::binary);
    if (!packOut.is_open())
        throw std::runtime_error("Failed to write packfile to disk");
    packOut.write(packData.data(), packData.size());
    packOut.close();
    std::cout << "Stored packfile at " << packPath << ". Unpacking not implemented.\n";
}

// Clone repository: fetch refs, request packfile, store packfile.
void cloneRepository(const std::string &repoURL, const std::string &destPath) {
    CURL* curlHandle = setupCurl();
    if (!curlHandle)
        throw std::runtime_error("CURL initialization error");
    try {
        init_git(destPath);
        std::string refsURL = constructRefsURL(repoURL);
        std::string refsResponse = performHttpGet(curlHandle, refsURL);
        auto remoteRefs = parseRefsResponse(refsResponse);
        if (remoteRefs.empty())
            throw std::runtime_error("No remote refs found");
        std::string uploadPackURL = constructUploadPackURL(repoURL);
        // Build minimal request: use first ref.
        std::stringstream reqStream;
        if (!remoteRefs.empty()) {
            std::string wantLine = "want " + remoteRefs[0].hash + "\n";
            reqStream << std::hex << std::setw(4) << std::setfill('0')
                      << (wantLine.size() + 4) << wantLine;
        }
        reqStream << "0000" << "0009done\n";
        std::string postData = reqStream.str();
        std::string packResponse = performHttpPost(curlHandle, uploadPackURL, postData);
        handlePackfile(packResponse, destPath);
        // Set HEAD to main (for simplicity)
        std::ofstream headFile(fs::path(destPath) / ".git/HEAD");
        if (headFile.is_open()) {
            headFile << "ref: refs/heads/main\n";
            headFile.close();
        }
        curl_easy_cleanup(curlHandle);
    } catch (const std::exception &e) {
        curl_easy_cleanup(curlHandle);
        throw std::runtime_error("Clone failed: " + std::string(e.what()));
    }
}

// =============================================================================
// Command Handlers
// =============================================================================

int handleInit() {
    try {
        init_git();
        std::cout << "Initialized git repository.\n";
    } catch (const fs::filesystem_error &err) {
        std::cerr << "Init error: " << err.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handleCatFile(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " cat-file -p <hash>\n";
        return EXIT_FAILURE;
    }
    try {
        std::string objHash = argv[3];
        check_git_initialised();
        std::string content = read_object(objHash);
        std::cout << content;
    } catch (const std::exception &ex) {
        std::cerr << "cat-file error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handleHashObject(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " hash-object -w <file>\n";
        return EXIT_FAILURE;
    }
    try {
        std::string flag = argv[2];
        if (flag != "-w") {
            std::cerr << "Expected -w flag.\n";
            return EXIT_FAILURE;
        }
        std::string filePath = argv[3];
        check_git_initialised();
        std::string blobHash = createBlobFromFile(filePath);
        std::cout << blobHash << "\n";
    } catch (const std::exception &ex) {
        std::cerr << "hash-object error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handleLsTree(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " ls-tree --name-only <tree_sha>\n";
        return EXIT_FAILURE;
    }
    try {
        std::string flag = argv[2];
        if (flag != "--name-only") {
            std::cerr << "Expected flag --name-only.\n";
            return EXIT_FAILURE;
        }
        std::string treeHash = argv[3];
        check_git_initialised();
        std::string treeData = read_object(treeHash);
        size_t pos = treeData.find('\0');
        if (pos == std::string::npos)
            throw std::runtime_error("Malformed tree object: header missing");
        pos++; // Skip header
        while (pos < treeData.size()) {
            size_t spacePos = treeData.find(' ', pos);
            if (spacePos == std::string::npos) break;
            std::string mode = treeData.substr(pos, spacePos - pos);
            pos = spacePos + 1;
            size_t nullPos = treeData.find('\0', pos);
            if (nullPos == std::string::npos) break;
            std::string fileName = treeData.substr(pos, nullPos - pos);
            std::cout << fileName << "\n";
            pos = nullPos + 1 + 20;
        }
    } catch (const std::exception &ex) {
        std::cerr << "ls-tree error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handleWriteTree(int argc, char* argv[]) {
    try {
        check_git_initialised();
        std::string treeHash = createTreeFromDirectory(fs::current_path().string());
        std::cout << hash_to_hex(treeHash) << "\n";
    } catch (const std::exception &ex) {
        std::cerr << "write-tree error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handleCommitTree(int argc, char* argv[]) {
    if (argc < 7) {
        std::cerr << "Usage: " << argv[0] << " commit-tree <tree_sha> -p <commit_sha> -m <message>\n";
        return EXIT_FAILURE;
    }
    try {
        check_git_initialised();
        std::string treeHash = argv[2];
        std::string parentHash = argv[4];
        std::string msg = argv[6];
        createCommit(treeHash, parentHash, msg);
    } catch (const std::exception &ex) {
        std::cerr << "commit-tree error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int handleClone(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " clone <repo_url> <output_path>\n";
        return EXIT_FAILURE;
    }
    try {
        std::string remoteURL = argv[2];
        std::string destDir = argv[3];
        cloneRepository(remoteURL, destDir);
        std::cout << "Clone completed successfully.\n";
    } catch (const std::exception &ex) {
        std::cerr << "Clone error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// =============================================================================
// Main Command Dispatch
// =============================================================================

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    std::cerr << "DEBUG: Starting Git clone/server simulation.\n";
    if (argc < 2) {
        std::cerr << "No command provided.\n";
        return EXIT_FAILURE;
    }
    
    std::string cmd = argv[1];
    if (cmd == "init") {
        return handleInit();
    } else if (cmd == "cat-file") {
        return handleCatFile(argc, argv);
    } else if (cmd == "hash-object") {
        return handleHashObject(argc, argv);
    } else if (cmd == "ls-tree") {
        return handleLsTree(argc, argv);
    } else if (cmd == "write-tree") {
        return handleWriteTree(argc, argv);
    } else if (cmd == "commit-tree") {
        return handleCommitTree(argc, argv);
    } else if (cmd == "clone") {
        return handleClone(argc, argv);
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}