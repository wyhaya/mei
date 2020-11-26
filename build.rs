fn main() {
    println!("cargo:rustc-env=BUILD_DATE={}", time::now_utc().rfc822());
}
