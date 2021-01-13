use crate::exit;
use crate::lib::DEFAULT_COMPRESS_QUALITY;
use clap::{crate_name, crate_version, App, AppSettings, Arg};
use rpassword::prompt_password_stdout;

const DEFAULT_OUTPUT_FILE: &str = "archive.mei";
const DEFAULT_OUTPUT_DIR: &str = "./";

pub struct Options {
    pub input: String,
    pub info: String,
    pub password: Option<String>,
    pub force: bool,
    pub compress: bool,
    pub output: String,
    pub quality: u32,
}

pub fn options() -> Options {
    let app = App::new(crate_name!())
        .global_setting(AppSettings::ColoredHelp)
        .version(crate_version!())
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
                .value_name("PASSWORD")
                .min_values(0)
                .max_values(1)
                .help("Set/Use archive file password"),
        )
        .get_matches();

    Options {
        input: app.value_of("PATH").unwrap().to_string(),
        info: app.value_of("info").unwrap_or_default().to_string(),
        password: {
            if app.is_present("password") {
                let val = match app.value_of("password") {
                    Some(s) => s.to_string(),
                    None => prompt_password_stdout("Password: ").unwrap(),
                };
                Some(val)
            } else {
                None
            }
        },
        force: app.is_present("force"),
        compress: !app.is_present("decompress"),
        output: app
            .value_of("output")
            .unwrap_or_else(|| {
                if app.is_present("decompress") {
                    DEFAULT_OUTPUT_DIR
                } else {
                    DEFAULT_OUTPUT_FILE
                }
            })
            .to_string(),
        quality: app
            .value_of("quality")
            .map(|s| {
                if let Ok(n) = s.parse::<u32>() {
                    if n <= 11 && n >= 1 {
                        return n;
                    }
                }
                exit!("The value of '--quality' is between 1-11")
            })
            .unwrap_or(DEFAULT_COMPRESS_QUALITY),
    }
}
