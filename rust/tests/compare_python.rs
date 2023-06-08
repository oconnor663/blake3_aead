use std::io::prelude::*;
use std::path::Path;
use std::process::{Command, Stdio};

const TEST_KEY: &[u8; 32] = b"whats the Elvish word for friend";
const TEST_NONCE: &[u8; 12] = b"foobarbazboo";
const MAX_BLOCK_COUNTER: u64 = (-64i64) as u64 / 64;

fn test_input(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    buf
}

fn run_python_script(script: &str, args: Vec<String>) -> Vec<u8> {
    let mut python_args = vec!["-c", script];
    for arg in &args {
        python_args.push(arg);
    }
    let cargo_toml_path = env!("CARGO_MANIFEST_DIR");
    let python_dir = Path::new(&cargo_toml_path).join("..").join("python");
    let output = Command::new("python3")
        .args(python_args)
        .stdout(Stdio::piped())
        .current_dir(python_dir)
        .output()
        .expect("exec error");
    if !output.stderr.is_empty() {
        println!("===== Python stderr =====");
        std::io::stdout().write_all(&output.stderr).unwrap();
    }
    assert!(output.status.success());
    output.stdout
}

#[test]
fn test_compare_python_universal_hash() {
    const PYTHON_SCRIPT: &str = r#"
import blake3_aead
import sys


assert len(sys.argv) == 4, "three args expected"
key = sys.argv[1].encode("ascii")
message = bytes.fromhex(sys.argv[2])
block_counter = int(sys.argv[3])
output = blake3_aead.universal_hash(key, message, block_counter)
sys.stdout.buffer.write(output)
"#;
    for len in [0, 1, 64, 1000] {
        dbg!(len);
        for block_counter in [0, 1, MAX_BLOCK_COUNTER - len as u64 / 64] {
            dbg!(block_counter);
            let message = test_input(len);
            let args = vec![
                String::from_utf8(TEST_KEY.to_vec()).unwrap(),
                hex::encode(&message),
                format!("{block_counter}"),
            ];
            let python_output = run_python_script(PYTHON_SCRIPT, args);
            let rust_output = blake3_aead::universal_hash(TEST_KEY, &message, block_counter);
            assert_eq!(python_output, rust_output);
        }
    }
}

#[test]
fn test_compare_python_encrypt() {
    const PYTHON_SCRIPT: &str = r#"
import blake3_aead
import sys


assert len(sys.argv) == 5, "four args expected"
key = sys.argv[1].encode("ascii")
nonce = sys.argv[2].encode("ascii")
plaintext = bytes.fromhex(sys.argv[3])
aad = bytes.fromhex(sys.argv[4])
output = blake3_aead.encrypt(key, nonce, plaintext, aad)
sys.stdout.buffer.write(output)
"#;
    for msg_len in [0, 1, 64, 1000] {
        dbg!(msg_len);
        for aad_len in [0, 1, 64, 1000] {
            dbg!(aad_len);
            let plaintext = test_input(msg_len);
            let aad = test_input(aad_len);
            let args = vec![
                String::from_utf8(TEST_KEY.to_vec()).unwrap(),
                String::from_utf8(TEST_NONCE.to_vec()).unwrap(),
                hex::encode(&plaintext),
                hex::encode(&aad),
            ];
            let python_output = run_python_script(PYTHON_SCRIPT, args);
            let mut ciphertext = plaintext.clone();
            ciphertext.resize(plaintext.len() + 16, 0u8);
            blake3_aead::encrypt_in_place(TEST_KEY, TEST_NONCE, &mut ciphertext, &aad);
            assert_eq!(python_output, ciphertext);
            #[cfg(feature = "std")]
            {
                let ciphertext_vec = blake3_aead::encrypt(TEST_KEY, TEST_NONCE, &plaintext, &aad);
                assert_eq!(python_output, ciphertext_vec);
            }
        }
    }
}
