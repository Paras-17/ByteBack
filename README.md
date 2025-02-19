# ByteBack C++ Project

This project is a simplified implementation of Git functionality written in C++. It provides basic commands for creating Git objects such as blobs, trees, and commits, and also includes a minimal clone functionality using Git's Smart HTTP transfer protocol.

## Overview

The implementation includes:

- **Blob Creation:** Reads file content, constructs a blob with header (`blob <size>\0`) and stores it in the Git object store.
- **Tree Creation:** Recursively scans directories (ignoring the .ByteBack folder) and creates tree objects. Each tree entry is stored as `<mode> <name>\0` followed by a 20-byte raw SHA-1 hash.
- **Commit Creation:** Builds commit objects containing the tree hash, parent commit (if any), author/committer information, and commit message. The commit object is stored with a header (`commit <body_size>\0`).
- **Clone Functionality:** Initializes a local repository, fetches remote references and a packfile via HTTP, and stores the packfile (packfile unpacking is not implemented in this version).

## Project Structure

The main file (`Server.cpp`) contains all functionality and command dispatch. The code is divided into several sections:

- **Utility Functions:** Functions for SHA-1 computation, zlib compression/decompression, and file I/O.
- **Blob & Tree Functions:** Functions to create blob objects from files (`createBlobFromFile()`) and recursively build tree objects (`createTreeFromDirectory()`).
- **Commit Functions:** Functions to build and store commit objects (`buildCommitContent()` and `createCommit()`).
- **Clone Functions:** Functions to perform HTTP GET/POST using libcurl, parse remote refs, and perform a minimal clone (`clone_repository()`).
- **Command Handlers:** Dedicated handlers for each command (e.g. `handle_init()`, `handle_cat_file()`, `handle_hash_object()`, `handle_ls_tree()`, `handle_write_tree()`, `handle_commit_tree()`, `handle_clone()`).

## Usage

Compile the project with a C++17 (or later) compliant compiler and ensure that the following libraries are installed:

- zlib
- OpenSSL
- libcurl

Below are the commands provided by the program:

### Initialize Repository
```
./ByteBack.sh init
```
Creates a new `.git` directory with subdirectories for objects and refs.

### Hash Object
```
./ByteBack.sh hash-object -w <file>
```
Reads the content of `<file>`, creates a blob object, and writes it to the object store.

### Write Tree
```
./ByteBack.sh write-tree
```
Recursively scans the current directory (ignoring `.git`), builds a tree object, and writes it.

### Commit Tree
```
./ByteBack.sh commit-tree <tree_sha> -p <parent_commit_sha> -m "Commit message"
```
Creates a commit object that references a tree and a parent commit.

### Cat File
```
./ByteBack.sh cat-file -p <hash>
```
Displays the contents of a Git object (e.g., blob, commit) by stripping the header.

### List Tree
```
./ByteBack.sh ls-tree --name-only <tree_sha>
```
Lists the names of entries in a tree object.

### Clone Repository
```
./ByteBack.sh clone <repo_url> <output_path>
```
Initializes a new repository in `<output_path>`, fetches remote references and a packfile (packfile unpacking is not implemented), and sets HEAD.

## Notes

- This project implements a simplified version of Git. Full packfile unpacking is not implemented.
- The clone functionality uses Git’s Smart HTTP protocol via libcurl.
- Ensure your environment has the necessary development libraries for zlib, OpenSSL, and libcurl.

## License

This project is distributed under the terms of the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html) (or later).

## Contact

For questions or issues, please contact [email](mailto:pa17112002@gmail.com).

