mod app;
mod lib;

use app::Options;
use lib::{CompressParams, Decode, Encode, FileType, Password, ScryptParams, DEFAULT_BUF_SIZE};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;
use walkdir::WalkDir;

#[macro_export]
macro_rules! exit {
    ($($arg:tt)*) => {
        {
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

fn compress_archive(options: Options) {
    let input = Path::new(&options.input);
    if !input.exists() {
        exit!("'{}' does not exist", options.input);
    }
    let prefix = input.parent().unwrap_or_else(|| input);
    let output = Path::new(&options.output);
    let writer = buf_writer(output, options.force);
    let filter = output.canonicalize().unwrap();
    let password = options
        .password
        .as_deref()
        .map(|key| Password::new(key, ScryptParams::default()));
    let params = *CompressParams::default().quality(options.quality);
    let mut encode = Encode::new(writer, &options.info, password, params)
        .unwrap_or_else(|err| exit!("{:#?}", err));
    let mut exclude = true;
    let files = WalkDir::new(&options.input).into_iter().filter_map(|rst| {
        let entry = match rst {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("File error: {:?}", err);
                return None;
            }
        };
        if exclude {
            match entry.path().canonicalize() {
                Ok(path) => {
                    if path == filter {
                        exclude = false;
                        return None;
                    }
                }
                Err(err) => {
                    eprintln!("File error: {:?}", err);
                    return None;
                }
            };
        }
        return Some(entry);
    });

    for entry in files {
        let path = entry.path().strip_prefix(&prefix).unwrap().to_path_buf();
        let p = path.to_str().unwrap_or_default();
        if entry.path().is_dir() {
            println!("Adding: {}", p);
            encode
                .write_directory(p)
                .unwrap_or_else(|err| exit!("Failed to write directory: {:?}", err));
        } else {
            print!("Adding: {}", p);
            let mut f = File::open(entry.path())
                .unwrap_or_else(|err| exit!("Failed to open file: {:?}", err));
            let bytes = encode
                .write_file(p, &mut f)
                .unwrap_or_else(|err| exit!("Failed to write file: {:?}", err));
            let len = entry.metadata().unwrap().len() as f32;
            println!(" [{:.1}%]", (bytes as f32) / len * 100.);
        }
    }
}

fn decompress_archive(options: Options) {
    let reader = buf_reader(&options.input);
    let root = {
        let path = PathBuf::from(&options.output);
        if !path.exists() {
            let _ = fs::create_dir_all(&path);
        } else {
            if !path.is_dir() {
                exit!("'{:?}' is not a directory", path.display())
            }
        }
        path
    };
    let mut decode = Decode::new(reader, options.password.as_deref(), DEFAULT_BUF_SIZE)
        .unwrap_or_else(|err| exit!("{:#?}", err));
    println!("Info: {}", decode.info());

    loop {
        let opt = decode.read_path().unwrap_or_else(|err| exit!("{:#?}", err));
        let (file_type, path) = match opt {
            Some(opt) => opt,
            None => break,
        };
        let path = root.join(path);
        println!("Output: {}", path.display());

        match file_type {
            FileType::Directory => {
                if let Err(err) = fs::create_dir_all(&path) {
                    exit!("Failed to create '{}': {:?}", path.display(), err);
                }
            }
            FileType::File => {
                let mut writer = buf_writer(&path, options.force);
                if let Err(err) = decode.read_file(&mut writer) {
                    exit!("Failed to read '{}': {:?}", path.display(), err);
                }
            }
        }
    }
}
