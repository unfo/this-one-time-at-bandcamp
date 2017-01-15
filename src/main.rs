extern crate ring;

use std::time::{SystemTime, UNIX_EPOCH};
use ring::{digest, hmac};

const TS: u64 = 30;

// Google implementation of the authenticator app does not support T0, TI values, hash methods and token lengths different from the default.
// It also expects the K secret key to be entered (or supplied in a QR code) in base-32 encoding according to RFC 3548
fn main() {
    println!("Hello OTP -> {}", totp_value());
}

// TC = floor((unixtime(now) − unixtime(T0)) / TS),
// TOTP = HOTP(SecretKey, TC),
// TOTP-Value = TOTP mod 10d, where d is the desired number of digits of the one-time password.
fn time_counter() -> u64 {
    let now = SystemTime::now();
    let seconds_since_epoch = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    seconds_since_epoch / TS
}

fn hotp(secret: &str, counter: u64) -> u32 {
    let key = hmac::SigningKey::new(&digest::SHA1, &[0,1]);
    let signature = hmac::sign(&key, &transform_u64_to_array_of_u8(counter));
    let sign_bytes = signature.as_ref();
    let trunc_bytes = truncate(sign_bytes);
    println!("trunc bytes -> {:?}", &trunc_bytes);
    let trunc_u32 = transform_u8_array_to_u32(trunc_bytes);
    let result = trunc_u32 & 0x7FFFFFFF;
    println!("first byte -> {} {}", trunc_u32, result);
    result
}

fn transform_u8_array_to_u32(x:&[u8]) -> u32 {
    let a: u32 = x[0] as u32;
    let b: u32 = x[1] as u32;
    let c: u32 = x[2] as u32;
    let d: u32 = x[3] as u32;
    let shifted =
        a.rotate_left(24) |
        b.rotate_left(16) |
        c.rotate_left(8) |
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
    println!("Sign bytes -> {:?}", bytes);
    let offset_byte:usize = (bytes[19] & 0b0000_1111) as usize;
    println!("offset byte -> {:?}", offset_byte);
    let trunc_bytes: &[u8] = &bytes[offset_byte..(offset_byte+4)];
    trunc_bytes
}

fn totp_value() -> u32 {
    hotp("secret", time_counter()) % 1000000
}