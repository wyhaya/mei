mod app;
mod lib;

use app::Options;
use lib::{CompressParams, Decode, Encode, FileType, Password, ScryptParams, DEFAULT_BUF_SIZE};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;
use walkdir::{DirEntry, WalkDir};

#[macro_export]
macro_rules! exit {
    ($($arg:tt)*) => {
        {
            eprint!("Error: ");
            eprintln!($($arg)*);
            exit(1)
        }
    };
}

fn main() {
    let options = app::options();
    if options.compress {
        compress_archive(options);
    } else {
        decompress_archive(options);
    }
}

fn compress_archive(options: Options) {
    // Check input path
    if !Path::new(&options.input).exists() {
        exit!("'{}' does not exist", options.input);
    }

    // Check output file
    if !options.force && Path::new(&options.output).exists() {
        exit!("'{}' already exist", options.output);
    }

    // Temp output file
    let temp = temp_path();
    let writer = buf_writer(&temp, true);
    let filter = Path::new(&temp).canonicalize().throw();

    // Input files
    let files = files(&options.input, filter);
    let prefix = Path::new(&options.input)
        .parent()
        .unwrap_or_else(|| Path::new(&options.input));

    let password = options
        .password
        .as_deref()
        .map(|key| Password::new(key, ScryptParams::default()));
    let params = *CompressParams::default().quality(options.quality);
    let mut encode = Encode::new(writer, &options.info, password, params).throw();

    for entry in files {
        let path = entry.path().strip_prefix(&prefix).throw().to_path_buf();
        let p = path.to_str().unwrap_or_default();
        if entry.path().is_dir() {
            println!("Adding: {}", p);
            encode.write_directory(p).throw();
        } else {
            print!("Adding: {}", p);
            let mut f = File::open(entry.path()).throw();
            let bytes = encode.write_file(p, &mut f).throw();
            let len = entry.metadata().throw().len() as f32;
            println!(" [{:.1}%]", (bytes as f32) / len * 100.);
        }
    }

    if Path::new(&options.output).is_dir() {
        fs::remove_dir_all(&options.output).throw();
    }
    fs::rename(temp, options.output).throw();
}

fn decompress_archive(options: Options) {
    let reader = buf_reader(&options.input);
    let root = {
        let path = PathBuf::from(&options.output);
        if !path.exists() {
            fs::create_dir_all(&path)
                .unwrap_or_else(|err| exit!("Failed to create '{}': {:#?}", options.output, err));
        } else {
            if !path.is_dir() {
                exit!("'{}' is not a directory", options.output)
            }
        }
        path
    };
    let mut decode = Decode::new(reader, options.password.as_deref(), DEFAULT_BUF_SIZE).throw();
    println!("Info: {}", decode.info());

    loop {
        let opt = decode.read_path().throw();
        let (file_type, file_path) = match opt {
            Some(opt) => opt,
            None => break,
        };
        let path = root.join(file_path);
        println!("Output: {}", path.display());

        match file_type {
            FileType::Directory => {
                if let Err(err) = fs::create_dir_all(&path) {
                    exit!("Failed to create '{}': {:#?}", path.display(), err);
                }
            }
            FileType::File => {
                let mut w = buf_writer(&path, options.force);
                if let Err(err) = decode.read_file(&mut w) {
                    exit!("Failed to read '{}': {:#?}", path.display(), err);
                }
            }
        }
    }
}

trait ThrowError<T> {
    fn throw(self) -> T;
}

impl<T, E: std::fmt::Debug> ThrowError<T> for Result<T, E> {
    fn throw(self) -> T {
        match self {
            Ok(val) => val,
            Err(err) => exit!("{:#?}", err),
        }
    }
}

fn temp_path() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = String::with_capacity(10);
    for _ in 0..10 {
        let n = rand::random::<f32>() * CHARS.len() as f32;
        name.push(CHARS[n as usize] as char);
    }
    name
}

fn buf_reader(p: &str) -> BufReader<File> {
    File::open(p)
        .map(|f| BufReader::new(f))
        .unwrap_or_else(|err| exit!("Failed to open '{}': {:?}", p, err))
}

fn buf_writer<P: AsRef<Path>>(p: P, force: bool) -> BufWriter<File> {
    let p = p.as_ref();
    if !force && p.exists() {
        exit!("File '{}' already exists", p.display());
    }
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    File::create(p)
        .map(|f| BufWriter::new(f))
        .unwrap_or_else(|err| exit!("Failed to create '{}': {:?}", p.display(), err))
}

fn files(path: &str, filter: PathBuf) -> impl Iterator<Item = DirEntry> {
    let mut excluded = false;
    WalkDir::new(path).into_iter().filter_map(move |rst| {
        let entry = rst.throw();
        if !excluded {
            let path = entry.path().canonicalize().throw();
            if path == filter {
                excluded = true;
                return None;
            }
        }
        return Some(entry);
    })
}
