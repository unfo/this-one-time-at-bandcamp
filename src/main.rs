extern crate ring;
extern crate base32;

use std::time::{SystemTime, UNIX_EPOCH};
use ring::{digest, hmac};
use base32::{decode, Alphabet};
use std::env;

const TS: u64 = 30;

fn main() {
    let secret = env::args().nth(1).unwrap();
    println!("One-time password is {}", totp_value(&secret));
}

fn time_counter() -> u64 {
    let now = SystemTime::now();
    let seconds_since_epoch = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    seconds_since_epoch / TS
}

fn hotp(secret: Vec<u8>, counter: u64) -> u32 {
    let key = hmac::SigningKey::new(&digest::SHA1, &secret);
    let signature = hmac::sign(&key, &transform_u64_to_array_of_u8(counter));
    let sign_bytes = signature.as_ref();
    let trunc_bytes = truncate(sign_bytes);
    let trunc_u32 = transform_u8_array_to_u32(trunc_bytes);
    trunc_u32 & 0x7FFFFFFF
}

fn transform_u8_array_to_u32(x:&[u8]) -> u32 {
    let a: u32 = x[0] as u32;
    let b: u32 = x[1] as u32;
    let c: u32 = x[2] as u32;
    let d: u32 = x[3] as u32;
    let shifted =
        a << 24 |
        b << 16 |
        c << 8 |
        d;
    shifted
}

fn transform_u64_to_array_of_u8(x:u64) -> [u8;8] {
    let b1 : u8 = ((x >> 56) & 0xff) as u8;
    let b2 : u8 = ((x >> 48) & 0xff) as u8;
    let b3 : u8 = ((x >> 40) & 0xff) as u8;
    let b4 : u8 = ((x >> 32) & 0xff) as u8;
    let b5 : u8 = ((x >> 24) & 0xff) as u8;
    let b6 : u8 = ((x >> 16) & 0xff) as u8;
    let b7 : u8 = ((x >> 8) & 0xff) as u8;
    let b8 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4, b5, b6, b7, b8]
}

fn truncate(bytes: &[u8]) -> &[u8] {
    let offset_byte:usize = (bytes[19] & 0b0000_1111) as usize;
    let trunc_bytes: &[u8] = &bytes[offset_byte..(offset_byte+4)];
    trunc_bytes
}

    let key_decoded = decode(Alphabet::RFC4648{ padding: false }, secret).unwrap();
    let otp_str = otp.to_string();
    match otp_str.len() {
        1 => format!("00000{}", otp),
        2 => format!("0000{}", otp),
        3 => format!("000{}", otp),
        4 => format!("00{}", otp),
        5 => format!("0{}", otp),
}