use colored::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Mutex;
use walkdir::{DirEntry, WalkDir};
fn is_leaf_directory(entry: &DirEntry) -> bool {
    WalkDir::new(entry.path())
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .all(|e| e.unwrap().file_type().is_file())
}

fn hash_file(path: &PathBuf) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    Ok(format!("{:x}", hasher.finalize()))
}

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

fn scan_directories(root_directory: PathBuf, log_file: &mut File) -> io::Result<()> {
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

fn main() -> io::Result<()> {
    let root_directory = PathBuf::from(
        r"M:\Music Production\Ableton Library\Samples\SAMPLE PACKS\DOWNLOADED PACKS\",
    );
    let log_file_path = "scan_log.txt";

    let mut log_file = File::create(log_file_path)?;

    writeln!(
        log_file,
        "Starting to scan in rootDirectory: {:?}",
        root_directory
    )?;
    println!("Starting to scan in rootDirectory: {:?}", root_directory);

    scan_directories(root_directory, &mut log_file)?;
    Ok(())
}
