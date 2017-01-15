use std::time::{SystemTime, UNIX_EPOCH};

const TS:u64 = 30;

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

fn hotp(secret: &str, counter: u64) -> u64 {
    counter
}

fn totp_value() -> u64 {
    hotp("secret", time_counter()) % 1000000
}