use colored::*; // Allows for coloring console output for better readability.
use rayon::prelude::*; // Enables data parallelism for efficient processing.
use sha2::{Digest, Sha256}; // Provides the SHA-256 hashing algorithm.
use std::collections::HashMap; // A collection type for storing unique hash map of files.
use std::fs::File; // Enables reading from and writing to files.
use std::io::Write; // Trait that allows writing to I/O streams.
use std::io::{self, Read}; // Traits for reading from I/O streams.
use std::path::PathBuf; // Represents filesystem paths in a cross-platform manner.
use std::sync::Mutex; // Provides a mutual exclusion lock for safely sharing data between threads.
use walkdir::{DirEntry, WalkDir}; // Enables recursive directory walking.

/// Checks if a directory contains no subdirectories, only files.
///
/// # Arguments
///
/// * `entry` - A directory entry from `walkdir`.
///
/// # Returns
///
/// True if the directory is a leaf (contains no subdirectories), false otherwise.
fn is_leaf_directory(entry: &DirEntry) -> bool {
    WalkDir::new(entry.path())
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .all(|e| e.unwrap().file_type().is_file())
}

/// Computes the SHA-256 hash of a file's contents.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
/// # Returns
///
/// A `Result` which is either the hex-encoded hash string or an I/O error.
fn hash_file(path: &PathBuf) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Finds duplicate files within a directory by computing and comparing file hashes.
///
/// # Arguments
///
/// * `directory` - The path to the directory to search for duplicates in.
///
/// # Returns
///
/// A `Result` containing a hash map of file hashes to vectors of paths of files with that hash, or an I/O error.
fn find_duplicates_in_directory(directory: &PathBuf) -> io::Result<HashMap<String, Vec<PathBuf>>> {
    let duplicates = Mutex::new(HashMap::new());

    let paths: Vec<_> = WalkDir::new(directory)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();

    paths.par_iter().for_each(|entry| {
        let path = entry.path().to_path_buf();
        if path.is_file() {
            match hash_file(&path) {
                Ok(hash) => {
                    let mut duplicates = duplicates.lock().unwrap();
                    duplicates.entry(hash).or_insert_with(Vec::new).push(path);
                }
                Err(e) => eprintln!("Error hashing file {:?}: {}", path, e),
            }
        }
    });

    Ok(duplicates.into_inner().unwrap())
}

/// Scans directories starting from a root directory for duplicate files, logging findings.
///
/// # Arguments
///
/// * `root_directory` - The root directory to start the scan from.
/// * `log_file` - A mutable reference to the log file for writing log messages.
///
/// # Returns
///
/// A `Result` indicating success (`Ok`) or an error (`Err`).
fn scan_directories(root_directory: PathBuf, log_file: &mut File) -> io::Result<()> {
    // Convert the root directory PathBuf to a string slice for easier manipulation and comparison.
    let root_directory_str = root_directory.to_str().unwrap();

    for entry in WalkDir::new(&root_directory)
        .into_iter()
        .filter_entry(|e| e.file_type().is_dir())
    {
        let entry = entry?;

        if is_leaf_directory(&entry) {
            let path_str = entry.path().to_str().unwrap();
            let display_path = path_str
                .strip_prefix(root_directory_str)
                .unwrap_or(path_str)
                .trim_start_matches('\\');

            let scan_message = format!("Starting to scan in: {}", display_path);
            writeln!(log_file, "{}", scan_message)?;
            println!("{}", scan_message.blue());

            let duplicates = find_duplicates_in_directory(&entry.path().to_path_buf())?;

            for (_hash, paths) in duplicates {
                if paths.len() > 1 {
                    let paths_str: Vec<String> = paths
                        .iter()
                        .map(|path| {
                            let path_str = path.to_str().unwrap();
                            let display_path = path_str
                                .strip_prefix(root_directory_str)
                                .unwrap_or(path_str)
                                .trim_start_matches('\\');
                            display_path.to_string()
                        })
                        .collect();

                    let duplicates_message = format!("Duplicates: {}", paths_str.join(" AND "));
                    writeln!(log_file, "{}", duplicates_message)?;
                    println!("{}", duplicates_message.red());
                }
            }
        }
    }
    Ok(())
}

/// The entry point of the application.
///
/// Initializes the scanning process and prepares the log file.
fn main() -> io::Result<()> {
    // Define the root directory to scan and the path to the log file.
    let root_directory = PathBuf::from(
        r"M:\Music Production\Ableton Library\Samples\SAMPLE PACKS\DOWNLOADED PACKS\",
    );
    let log_file_path = "scan_log.txt";

    // Create or truncate the log file.
    let mut log_file = File::create(log_file_path)?;

    // Log the start of the scanning process.
    writeln!(
        log_file,
        "Starting to scan in rootDirectory: {:?}",
        root_directory
    )?;
    println!("Starting to scan in rootDirectory: {:?}", root_directory);

    // Begin scanning directories for duplicates, logging the findings.
    scan_directories(root_directory, &mut log_file)?;
    Ok(())
}
