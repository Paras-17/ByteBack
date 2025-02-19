<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  
</head>
<body>
  <h1>Git Starter C++ Project</h1>
  
  <div class="section">
    <h2>Overview</h2>
    <p>
      This project is a simplified implementation of Git functionality written in C++. It provides basic commands for creating Git objects such as blobs, trees, and commits, and also includes a minimal clone functionality using Git's Smart HTTP transfer protocol.
    </p>
    <p>
      The implementation includes:
    </p>
    <ul>
      <li><strong>Blob Creation:</strong> Reads file content, constructs a blob with header ("blob &lt;size&gt;\0") and stores it in the Git object store.</li>
      <li><strong>Tree Creation:</strong> Recursively scans directories (ignoring the .git folder) and creates tree objects. Each tree entry is stored as "<code>&lt;mode&gt; &lt;name&gt;\0</code>" followed by a 20-byte raw SHA-1 hash.</li>
      <li><strong>Commit Creation:</strong> Builds commit objects containing the tree hash, parent commit (if any), author/committer information, and commit message. The commit object is stored with a header ("commit &lt;body_size&gt;\0").</li>
      <li><strong>Clone Functionality:</strong> Initializes a local repository, fetches remote references and a packfile via HTTP, and stores the packfile (packfile unpacking is not implemented in this version).</li>
    </ul>
  </div>

  <div class="section">
    <h2>Project Structure</h2>
    <p>The main file (<code>Server.cpp</code>) contains all functionality and command dispatch. The code is divided into several sections:</p>
    <ul>
      <li><strong>Utility Functions:</strong> Functions for SHA-1 computation, zlib compression/decompression, and file I/O.</li>
      <li><strong>Blob &amp; Tree Functions:</strong> Functions to create blob objects from files (<code>createBlobFromFile()</code>) and recursively build tree objects (<code>createTreeFromDirectory()</code>).</li>
      <li><strong>Commit Functions:</strong> Functions to build and store commit objects (<code>buildCommitContent()</code> and <code>createCommit()</code>).</li>
      <li><strong>Clone Functions:</strong> Functions to perform HTTP GET/POST using libcurl, parse remote refs, and perform a minimal clone (<code>clone_repository()</code>).</li>
      <li><strong>Command Handlers:</strong> Dedicated handlers for each command (e.g. <code>handle_init()</code>, <code>handle_cat_file()</code>, <code>handle_hash_object()</code>, <code>handle_ls_tree()</code>, <code>handle_write_tree()</code>, <code>handle_commit_tree()</code>, <code>handle_clone()</code>).</li>
    </ul>
  </div>

  <div class="section">
    <h2>Usage</h2>
    <p>Compile the project with a C++17 (or later) compliant compiler and ensure that the following libraries are installed:</p>
    <ul>
      <li>zlib</li>
      <li>OpenSSL</li>
      <li>libcurl</li>
    </ul>
    <p>Below are the commands provided by the program:</p>
    <h3>Initialize Repository</h3>
    <pre><code>./ByteBack.sh init</code></pre>
    <p>Creates a new <code>.git</code> directory with subdirectories for objects and refs.</p>
    
    <h3>Hash Object</h3>
    <pre><code>./ByteBack.sh hash-object -w &lt;file&gt;</code></pre>
    <p>Reads the content of <code>&lt;file&gt;</code>, creates a blob object, and writes it to the object store.</p>
    
    <h3>Write Tree</h3>
    <pre><code>./ByteBack.sh write-tree</code></pre>
    <p>Recursively scans the current directory (ignoring <code>.git</code>), builds a tree object, and writes it.</p>
    
    <h3>Commit Tree</h3>
    <pre><code>./ByteBack.sh commit-tree &lt;tree_sha&gt; -p &lt;parent_commit_sha&gt; -m "Commit message"</code></pre>
    <p>Creates a commit object that references a tree and a parent commit.</p>
    
    <h3>Cat File</h3>
    <pre><code>./ByteBack.sh cat-file -p &lt;hash&gt;</code></pre>
    <p>Displays the contents of a Git object (e.g., blob, commit) by stripping the header.</p>
    
    <h3>List Tree</h3>
    <pre><code>./ByteBack.sh ls-tree --name-only &lt;tree_sha&gt;</code></pre>
    <p>Lists the names of entries in a tree object.</p>
    
    <h3>Clone Repository</h3>
    <pre><code>./ByteBack.sh clone &lt;repo_url&gt; &lt;output_path&gt;</code></pre>
    <p>Initializes a new repository in <code>&lt;output_path&gt;</code>, fetches remote references and a packfile (packfile unpacking is not implemented), and sets HEAD.</p>
  </div>

  <div class="section">
    <h2>Notes</h2>
    <ul>
      <li>This project implements a simplified version of Git. Full packfile unpacking is not implemented.</li>
      <li>The clone functionality uses Git’s Smart HTTP protocol via libcurl.</li>
      <li>Ensure your environment has the necessary development libraries for zlib, OpenSSL, and libcurl.</li>
    </ul>
  </div>

  <div class="section">
    <h2>License</h2>
    <p>This project is distributed under the terms of the GNU General Public License v3.0 (or later).</p>
  </div>
  
  <div class="section">
    <h2>Contact</h2>
    <p>For questions or issues, please contact <a href="mailto:pa17112002@gmail.com">email</a>.</p>
  </div>
</body>
</html>
