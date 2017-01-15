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
    let signature = hmac::sign(&key, "hello world".as_bytes());
    let sign_bytes = signature.as_ref();
    let trunc_bytes = truncate(sign_bytes);
    println!("trunc bytes -> {:?}", &trunc_bytes);
    let a: u32 = trunc_bytes[0] as u32;
    let b: u32 = trunc_bytes[1] as u32;
    let c: u32 = trunc_bytes[2] as u32;
    let d: u32 = trunc_bytes[3] as u32;
    let shifted =
        a.rotate_left(24) |
        b.rotate_left(16) |
        c.rotate_left(8) |
        d;
    let result = shifted & 0x7FFFFFFF;
    println!("first byte -> {} {}", shifted, result);
    result
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