mod lib;

use clap::{crate_name, crate_version, App, AppSettings, Arg};
use lib::{
    CompressParams, Decode, Encode, Error, FileType, Password, ScryptParams, DEFAULT_BUF_SIZE,
    DEFAULT_COMPRESS_QUALITY,
};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;
use walkdir::WalkDir;

macro_rules! exit {
    ($($arg:tt)*) => {
        {
            eprintln!($($arg)*);
            exit(1)
        }
    };
}

const DEFAULT_OUTPUT_FILE: &str = "archive.mei";
const DEFAULT_OUTPUT_DIR: &str = "./";

fn main() {
    let app = App::new(crate_name!())
        .global_setting(AppSettings::ColoredHelp)
        .version(format!("{} ({})", crate_version!(), env!("BUILD_DATE")).as_str())
        .usage(format!("{} <PATH> -d?", crate_name!()).as_str())
        .arg(
            Arg::with_name("PATH")
                .required(true)
                .help("Set the input file path"),
        )
        .arg(
            Arg::with_name("decompress")
                .short("d")
                .long("decompress")
                .help("Decompress archived file"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .value_name("PATH")
                .help("Set output file path"),
        )
        .arg(
            Arg::with_name("force")
                .short("f")
                .long("force")
                .help("Overwrite local files"),
        )
        .arg(
            Arg::with_name("info")
                .short("i")
                .long("info")
                .takes_value(true)
                .value_name("info")
                .conflicts_with("decompress")
                .help("Set archive file information"),
        )
        .arg(
            Arg::with_name("quality")
                .short("q")
                .long("quality")
                .takes_value(true)
                .value_name("1-11")
                .conflicts_with("decompress")
                .help("Set compression quality"),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .value_name("PASSWORD")
                .help("Set/Use archive file password"),
        )
        .get_matches();

    let input = app.value_of("PATH").unwrap();
    let info = app.value_of("info").unwrap_or_default();
    let password = app.value_of("password");
    let output = app.value_of("output");
    let force = app.is_present("force");
    let decompress = app.is_present("decompress");
    let quality = app
        .value_of("quality")
        .map(|s| {
            if let Ok(n) = s.parse::<u32>() {
                if n <= 11 && n >= 1 {
                    return n;
                }
            }
            exit!("The value of '--quality' is between 1-11")
        })
        .unwrap_or(DEFAULT_COMPRESS_QUALITY);

    let rst = match decompress {
        true => decompress_file(input, output.unwrap_or(DEFAULT_OUTPUT_DIR), force, password),
        false => compress_file(
            input,
            output.unwrap_or(DEFAULT_OUTPUT_FILE),
            force,
            password,
            info,
            quality,
        ),
    };
    if let Err(err) = rst {
        exit!("Failed: {:?}", err)
    }
}

fn buf_reader(p: &str) -> BufReader<File> {
    File::open(p)
        .map(|f| BufReader::new(f))
        .unwrap_or_else(|err| exit!("Failed to open '{}': {:?}", p, err))
}

fn buf_writer<P: AsRef<Path>>(p: P, force: bool) -> BufWriter<File> {
    let path = p.as_ref();
    if !force && path.exists() {
        exit!("File '{}' already exists", path.display());
    }
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|err| exit!("Failed to create '{}': {:?}", path.display(), err));
        }
    }
    File::create(path)
        .map(|f| BufWriter::new(f))
        .unwrap_or_else(|err| exit!("Failed to create '{}': {:?}", path.display(), err))
}

fn compress_file(
    input: &str,
    output: &str,
    force: bool,
    password: Option<&str>,
    info: &str,
    quality: u32,
) -> Result<(), Error> {
    if let Err(err) = fs::metadata(input) {
        exit!("Failed to get '{}' metadata: {:?}", input, err);
    }
    let prefix = Path::new(input)
        .parent()
        .unwrap_or_else(|| Path::new(input));
    let writer = buf_writer(&output, force);
    let output_path = Path::new(output).canonicalize().unwrap();
    let password = password.map(|key| Password::new(key, ScryptParams::default()));
    let mut params = CompressParams::default();
    params.quality(quality);
    let mut encode = Encode::new(writer, info, password, params)?;

    let mut exclude = true;
    let files = WalkDir::new(input).into_iter().filter_map(|rst| {
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
                    if path == output_path {
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
            if let Err(err) = encode.write_directory(p) {
                exit!("Failed to write directory: {:?}", err);
            }
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

    Ok(())
}

fn decompress_file(
    input: &str,
    output: &str,
    force: bool,
    password: Option<&str>,
) -> Result<(), Error> {
    let reader = buf_reader(input);
    let root = {
        let path = PathBuf::from(output);
        if !path.exists() {
            let _ = fs::create_dir_all(&path);
        } else {
            if !path.is_dir() {
                exit!("'{:?}' is not a directory", path.display())
            }
        }
        path
    };
    let mut decode = Decode::new(reader, password.as_deref(), DEFAULT_BUF_SIZE)?;
    if !decode.info().is_empty() {
        println!("Info: {}", decode.info());
    }

    loop {
        let (file_type, path) = match decode.read_path()? {
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
                let mut writer = buf_writer(&path, force);
                if let Err(err) = decode.read_file(&mut writer) {
                    exit!("Failed to read '{}': {:?}", path.display(), err);
                }
            }
        }
    }

    Ok(())
}
