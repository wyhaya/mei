use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use brotli::{CompressorReader, DecompressorWriter};
use rand::{prelude::Rng, thread_rng};
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::string::FromUtf8Error;

// Reader buffer size
pub const DEFAULT_BUF_SIZE: usize = 1024 * 8;

// Brotli compress
pub const DEFAULT_COMPRESS_QUALITY: u32 = 4;
pub const DEFAULT_COMPRESS_WINDOW_SIZE: u32 = 20;

pub const DEFAULT_SCRYPT_N: u8 = 15;
pub const DEFAULT_SCRYPT_R: u32 = 8;
pub const DEFAULT_SCRYPT_P: u32 = 1;

// File encryption
const ENCRYPT_NONE: [u8; 1] = [0];
const ENCRYPT_AES_256_GCM: [u8; 1] = [1];

#[derive(Debug)]
pub enum Error {
    InvalidHead,
    InvalidVersion,
    InvalidEncryptMethod,
    InvalidScryptParams,
    EncryptionFailed,
    DecryptionFailed,
    FileType(u8),
    FilePath,
    PasswordRequired,
    NoPasswordRequired,
    /// Archive info / File path
    Utf8(FromUtf8Error),
    /// Chunk length cannot be greater than 65535
    ChunkTooLong,
    IO(IoError),
}

trait IoResultToResult<T> {
    fn rst(self) -> Result<T, Error>;
}

impl<T> IoResultToResult<T> for IoResult<T> {
    fn rst(self) -> Result<T, Error> {
        match self {
            Ok(val) => Ok(val),
            Err(err) => Err(Error::IO(err)),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum FileType {
    File,
    Directory,
}

impl FileType {
    const DIRECTORY: u8 = 0;
    const FILE: u8 = 1;

    fn parse(byte: u8) -> Result<Self, Error> {
        if byte == Self::FILE {
            return Ok(Self::File);
        }
        if byte == Self::DIRECTORY {
            return Ok(Self::Directory);
        }
        Err(Error::FileType(byte))
    }

    fn write<W: Write>(self, w: &mut W) -> IoResult<usize> {
        match self {
            FileType::Directory => w.write(&[Self::DIRECTORY]),
            FileType::File => w.write(&[Self::FILE]),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompressParams {
    buf_size: usize,
    quality: u32,
    window_size: u32,
}

impl Default for CompressParams {
    fn default() -> Self {
        CompressParams {
            buf_size: DEFAULT_BUF_SIZE,
            quality: DEFAULT_COMPRESS_QUALITY,
            window_size: DEFAULT_COMPRESS_WINDOW_SIZE,
        }
    }
}

#[allow(dead_code)]
impl CompressParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn buf_size(&mut self, n: usize) -> &mut Self {
        self.buf_size = n;
        self
    }

    pub fn quality(&mut self, n: u32) -> &mut Self {
        self.quality = n;
        self
    }

    pub fn window_size(&mut self, n: u32) -> &mut Self {
        self.window_size = n;
        self
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ScryptParams {
    pub salt: [u8; 16],
    pub n: u8,
    pub r: u32,
    pub p: u32,
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self {
            salt: thread_rng().gen(),
            n: DEFAULT_SCRYPT_N,
            r: DEFAULT_SCRYPT_R,
            p: DEFAULT_SCRYPT_P,
        }
    }
}

#[derive(Debug)]
pub struct Password<'a> {
    key: &'a str,
    params: ScryptParams,
}

impl<'a> Password<'a> {
    pub fn new(key: &'a str, params: ScryptParams) -> Self {
        Self { key, params }
    }
}

// Convert the password to Aes256Gcm key through scrypt
fn cipher(pw: Password) -> Result<Aes256Gcm, ()> {
    let params =
        scrypt::ScryptParams::new(pw.params.n, pw.params.r, pw.params.p).map_err(|_| ())?;
    let mut value = [0; 32];
    scrypt::scrypt(pw.key.as_bytes(), &pw.params.salt, &params, &mut value).unwrap();
    let key = GenericArray::from_slice(&value);
    Ok(Aes256Gcm::new(key))
}

// File identification
const HEAD: [u8; 3] = *b"mei";

fn read_head<R: Read>(r: &mut R) -> Result<(), Error> {
    let mut buf = [0; 3];
    r.read_exact(&mut buf).rst()?;
    if buf != HEAD {
        return Err(Error::InvalidHead);
    }
    Ok(())
}

fn write_head<W: Write>(w: &mut W) -> IoResult<usize> {
    w.write(&HEAD)
}

// File version
const VERSION: [u8; 1] = [1];

fn read_version<R: Read>(r: &mut R) -> Result<(), Error> {
    let mut buf = [0; 1];
    r.read_exact(&mut buf).rst()?;
    if buf != VERSION {
        return Err(Error::InvalidVersion);
    }
    Ok(())
}

fn write_version<W: Write>(w: &mut W) -> IoResult<usize> {
    w.write(&VERSION)
}

fn read_scrypt_option<R: Read>(r: &mut R) -> Result<Option<ScryptParams>, Error> {
    let mut buf = [0; 1];
    r.read_exact(&mut buf).rst()?;
    match buf {
        ENCRYPT_NONE => Ok(None),
        ENCRYPT_AES_256_GCM => {
            let mut salt_buf = [0; 16];
            r.read_exact(&mut salt_buf).rst()?;
            let mut n_buf = [0; 1];
            r.read_exact(&mut n_buf).rst()?;
            let mut r_buf = [0; 4];
            r.read_exact(&mut r_buf).rst()?;
            let mut p_buf = [0; 4];
            r.read_exact(&mut p_buf).rst()?;
            Ok(Some(ScryptParams {
                salt: salt_buf,
                n: u8::from_be_bytes(n_buf),
                r: u32::from_be_bytes(r_buf),
                p: u32::from_be_bytes(p_buf),
            }))
        }
        _ => Err(Error::InvalidEncryptMethod),
    }
}

fn write_scrypt_params<W: Write>(w: &mut W, params: Option<&ScryptParams>) -> IoResult<()> {
    match params {
        Some(params) => {
            w.write(&ENCRYPT_AES_256_GCM)?;
            w.write(&params.salt)?;
            w.write(&params.n.to_be_bytes())?;
            w.write(&params.r.to_be_bytes())?;
            w.write(&params.p.to_be_bytes())?;
        }
        None => {
            w.write(&ENCRYPT_NONE)?;
        }
    }
    Ok(())
}

fn read_chunk<R: Read>(r: &mut R) -> IoResult<Vec<u8>> {
    // 2 bytes chunk length
    let mut len = [0; 2];
    r.read_exact(&mut len)?;
    // Chunk
    let mut buf = vec![0; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_chunk<W: Write>(w: &mut W, buf: &[u8]) -> Result<(), Error> {
    if buf.len() > 65535 {
        return Err(Error::ChunkTooLong);
    }
    // 2 bytes chunk length
    w.write(&(buf.len() as u16).to_be_bytes()).rst()?;
    // Chunk
    w.write(&buf).rst()?;
    Ok(())
}

fn read_chunk_to_string<R: Read>(r: &mut R) -> Result<String, Error> {
    let buf = read_chunk(r).rst()?;
    String::from_utf8(buf).map_err(|err| Error::Utf8(err))
}

fn read_nonce<R: Read>(r: &mut R) -> IoResult<[u8; 12]> {
    let mut buf = [0; 12];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_encrypt_chunk<R: Read>(r: &mut R, cipher: &Aes256Gcm) -> Result<Option<Vec<u8>>, Error> {
    let encrypted = match read_chunk(r) {
        Ok(buf) => {
            if buf.is_empty() {
                return Ok(None);
            } else {
                buf
            }
        }
        Err(err) => {
            if err.kind() == ErrorKind::UnexpectedEof {
                return Ok(None);
            } else {
                return Err(Error::IO(err));
            }
        }
    };
    let nonce = read_nonce(r).rst()?;
    let data = match cipher.decrypt(GenericArray::from_slice(&nonce), &encrypted[..]) {
        Ok(data) => data,
        Err(_) => return Err(Error::DecryptionFailed),
    };
    Ok(Some(data))
}

fn write_encrypt_chunk<W: Write>(w: &mut W, cipher: &Aes256Gcm, buf: &[u8]) -> Result<(), Error> {
    if buf.is_empty() {
        write_chunk(w, &[])?;
    } else {
        let nonce: [u8; 12] = thread_rng().gen();
        let data = match cipher.encrypt(GenericArray::from_slice(&nonce), buf) {
            Ok(data) => data,
            Err(_) => return Err(Error::EncryptionFailed),
        };
        write_chunk(w, &data)?;
        w.write(&nonce).rst()?;
    }
    Ok(())
}

pub struct Encode<W> {
    inner: W,
    cipher: Option<Aes256Gcm>,
    params: CompressParams,
}

impl<W: Write> Encode<W> {
    pub fn new(
        mut writer: W,
        info: &str,
        password: Option<Password>,
        params: CompressParams,
    ) -> Result<Self, Error> {
        write_head(&mut writer).rst()?;
        write_version(&mut writer).rst()?;
        write_chunk(&mut writer, info.as_bytes())?;
        let scrypt = password.as_ref().map(|s| &s.params);
        write_scrypt_params(&mut writer, scrypt).rst()?;

        let cipher = match password {
            Some(pw) => match cipher(pw) {
                Ok(cipher) => Some(cipher),
                Err(_) => return Err(Error::InvalidScryptParams),
            },
            None => None,
        };

        Ok(Self {
            inner: writer,
            cipher,
            params,
        })
    }

    /// Add a directory to an archive
    pub fn write_directory(&mut self, p: &str) -> Result<(), Error> {
        // File type
        FileType::Directory.write(&mut self.inner).rst()?;
        // File path
        match &self.cipher {
            Some(cipher) => {
                write_encrypt_chunk(&mut self.inner, cipher, p.as_bytes())?;
            }
            None => {
                write_chunk(&mut self.inner, p.as_bytes())?;
            }
        }
        self.inner.flush().rst()
    }

    /// Add a file to an archive
    pub fn write_file<R: Read>(&mut self, p: &str, reader: &mut R) -> Result<usize, Error> {
        let mut bytes = 0;
        let mut reader = CompressorReader::new(
            reader,
            self.params.buf_size,
            self.params.quality,
            self.params.window_size,
        );
        // File type
        FileType::File.write(&mut self.inner).rst()?;

        match &self.cipher {
            Some(cipher) => {
                // File path
                write_encrypt_chunk(&mut self.inner, cipher, p.as_bytes())?;
                // File data
                let mut buf = vec![0; self.params.buf_size];
                loop {
                    match reader.read(&mut buf) {
                        Ok(n) => {
                            if n == 0 {
                                write_encrypt_chunk(&mut self.inner, cipher, &[])?;
                                break;
                            }
                            bytes += n;
                            write_encrypt_chunk(&mut self.inner, cipher, &buf[..n])?;
                        }
                        Err(err) => match err.kind() {
                            ErrorKind::UnexpectedEof => {
                                write_encrypt_chunk(&mut self.inner, cipher, &[])?;
                                break;
                            }
                            _ => return Err(Error::IO(err)),
                        },
                    };
                }
            }
            None => {
                // File path
                write_chunk(&mut self.inner, p.as_bytes())?;
                // File data
                let mut buf = vec![0; self.params.buf_size];
                loop {
                    match reader.read(&mut buf) {
                        Ok(n) => {
                            if n == 0 {
                                write_chunk(&mut self.inner, &[])?;
                                break;
                            }
                            bytes += n;
                            write_chunk(&mut self.inner, &buf[..n])?;
                        }
                        Err(err) => match err.kind() {
                            ErrorKind::UnexpectedEof => {
                                write_chunk(&mut self.inner, &[])?;
                                break;
                            }
                            _ => return Err(Error::IO(err)),
                        },
                    };
                }
            }
        }
        self.inner.flush().map(|_| bytes).rst()
    }
}

pub struct Decode<R> {
    inner: R,
    cipher: Option<Aes256Gcm>,
    info: String,
    buf_size: usize,
}

impl<R: Read> Decode<R> {
    pub fn new(mut reader: R, password: Option<&str>, buf_size: usize) -> Result<Self, Error> {
        read_head(&mut reader)?;
        read_version(&mut reader)?;
        let info = read_chunk_to_string(&mut reader)?;
        let params = read_scrypt_option(&mut reader)?;

        match (params.is_some(), password.is_some()) {
            (true, false) => return Err(Error::PasswordRequired),
            (false, true) => return Err(Error::NoPasswordRequired),
            _ => {}
        }

        let cipher = match password.zip(params) {
            Some((key, params)) => match cipher(Password { key, params }) {
                Ok(cipher) => Some(cipher),
                Err(_) => return Err(Error::InvalidScryptParams),
            },
            None => None,
        };

        Ok(Self {
            inner: reader,
            cipher,
            info,
            buf_size,
        })
    }

    pub fn info(&self) -> &str {
        &self.info
    }

    pub fn read_path(&mut self) -> Result<Option<(FileType, String)>, Error> {
        let mut buf = [0; 1];
        if let Err(err) = self.inner.read_exact(&mut buf) {
            if err.kind() == ErrorKind::UnexpectedEof {
                return Ok(None);
            } else {
                return Err(Error::IO(err));
            }
        }

        let file_type = FileType::parse(buf[0])?;
        let file_path = match &self.cipher {
            Some(cipher) => match read_encrypt_chunk(&mut self.inner, cipher)? {
                Some(buf) => String::from_utf8(buf).map_err(|err| Error::Utf8(err))?,
                None => return Err(Error::FilePath),
            },
            None => read_chunk_to_string(&mut self.inner)?,
        };

        Ok(Some((file_type, file_path)))
    }

    pub fn read_file<W: Write>(&mut self, writer: W) -> Result<(), Error> {
        let mut writer = DecompressorWriter::new(writer, self.buf_size);
        match &self.cipher {
            Some(cipher) => loop {
                let data = match read_encrypt_chunk(&mut self.inner, cipher)? {
                    Some(data) => data,
                    None => break,
                };
                writer.write(&data).rst()?;
            },
            None => loop {
                let data = read_chunk(&mut self.inner).rst()?;
                if data.is_empty() {
                    break;
                }
                writer.write(&data).rst()?;
            },
        }
        writer.flush().rst()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::fs::{File, OpenOptions};

    fn archive(name: &str) -> File {
        OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(temp_dir().join(name))
            .unwrap()
    }

    #[test]
    fn test_head() {
        write_head(&mut archive("name")).unwrap();
        read_head(&mut archive("name")).unwrap();
    }

    #[test]
    fn test_version() {
        write_version(&mut archive("version")).unwrap();
        read_version(&mut archive("version")).unwrap();
    }

    #[test]
    fn test_scrypt_params() {
        write_scrypt_params(&mut archive("scrypt"), None).unwrap();
        assert!(read_scrypt_option(&mut archive("scrypt"))
            .unwrap()
            .is_none());

        let opt = ScryptParams::default();
        write_scrypt_params(&mut archive("scrypt"), Some(&opt)).unwrap();
        let params = read_scrypt_option(&mut archive("scrypt")).unwrap().unwrap();
        assert_eq!(params.n, opt.n);
        assert_eq!(params.p, opt.p);
        assert_eq!(params.p, opt.p);
    }

    #[test]
    fn test_archive() {
        let mut f = archive("encode");
        let mut encode = Encode::new(&mut f, "info", None, CompressParams::default()).unwrap();
        encode.write_directory("directory").unwrap();
        encode.write_file("file", &mut archive("data")).unwrap();

        let mut f = archive("encode");
        let mut decode = Decode::new(&mut f, None, DEFAULT_BUF_SIZE).unwrap();
        assert_eq!(decode.info(), "info");

        assert_eq!(
            decode.read_path().unwrap().unwrap(),
            (FileType::Directory, "directory".to_string())
        );
        assert_eq!(
            decode.read_path().unwrap().unwrap(),
            (FileType::File, "file".to_string())
        );

        decode.read_file(&mut std::io::stdout()).unwrap();
        assert!(decode.read_path().unwrap().is_none());
    }
}
