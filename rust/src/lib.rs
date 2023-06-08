#![cfg_attr(not(feature = "std"), no_std)]

use blake3::KEY_LEN;
use constant_time_eq::constant_time_eq_16;
use core::cmp;

const BLOCK_LEN: usize = 64;
const TAG_LEN: usize = 16;

const MSG_HASH_SEEK: u64 = 1 << 63;
const MSG_HASH_COUNTER: u64 = MSG_HASH_SEEK / BLOCK_LEN as u64;
const AAD_HASH_SEEK: u64 = (1 << 63) + (1 << 62);
const AAD_HASH_COUNTER: u64 = AAD_HASH_SEEK / BLOCK_LEN as u64;

fn universal_hash_block(key: &[u8; KEY_LEN], block: &[u8], block_counter: u64) -> [u8; BLOCK_LEN] {
    debug_assert!(block.len() <= BLOCK_LEN);
    let mut xof = blake3::Hasher::new_keyed(key).update(block).finalize_xof();
    xof.set_position(BLOCK_LEN as u64 * block_counter);
    let mut output = [0u8; BLOCK_LEN];
    xof.fill(&mut output);
    output
}

// This will eventually be supported directly in the public blake3 API, with a high-efficiency
// implementation. In the meantime, this is a low-efficiency helper with a reasonably similar
// signature.
pub fn universal_hash(
    key: &[u8; KEY_LEN],
    mut message: &[u8],
    mut block_counter: u64,
) -> [u8; BLOCK_LEN] {
    let mut output = [0u8; BLOCK_LEN];
    loop {
        // Always compress at least one block, even if the message is empty.
        let block_len = cmp::min(BLOCK_LEN, message.len());
        let block = &message[..block_len];
        let block_output = universal_hash_block(key, block, block_counter);
        for i in 0..BLOCK_LEN {
            output[i] ^= block_output[i];
        }
        message = &message[block_len..];
        block_counter += 1;
        if message.is_empty() {
            return output;
        }
    }
}

// This will eventually be supported directly in the public blake3 API, with a high-efficiency
// implementation. In the meantime, this is a low-efficiency helper with a reasonably similar
// signature.
fn xof_xor(output: &mut blake3::OutputReader, mut dest: &mut [u8]) {
    while !dest.is_empty() {
        let mut output_block = [0u8; BLOCK_LEN];
        output.fill(&mut output_block);
        let block_len = cmp::min(BLOCK_LEN, dest.len());
        for i in 0..block_len {
            dest[i] ^= output_block[i];
        }
        dest = &mut dest[block_len..];
    }
}

/// `plaintext_with_tag_space` contains the plaintext plus TAG_LEN extra bytes at the end. The
/// plaintext is encrypted in-place, and the auth tag is written to the extra bytes. The initial
/// contents of the extra bytes are ignored.
pub fn encrypt_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    plaintext_with_tag_space: &mut [u8],
    aad: &[u8],
) {
    assert!(plaintext_with_tag_space.len() >= TAG_LEN);
    // Zero the last TAG_LEN bytes, in case there's garbage there.
    let plaintext_len = plaintext_with_tag_space.len() - TAG_LEN;
    for i in 0..TAG_LEN {
        plaintext_with_tag_space[plaintext_len + i] = 0;
    }
    let mut stream_output = blake3::Hasher::new_keyed(key).update(nonce).finalize_xof();
    xof_xor(&mut stream_output, plaintext_with_tag_space);
    if plaintext_len > 0 {
        let msg_tag = universal_hash(
            key,
            &plaintext_with_tag_space[..plaintext_len],
            MSG_HASH_COUNTER,
        );
        for i in 0..TAG_LEN {
            plaintext_with_tag_space[plaintext_len + i] ^= msg_tag[i];
        }
    }
    if aad.len() > 0 {
        let aad_tag = universal_hash(key, aad, AAD_HASH_COUNTER);
        for i in 0..TAG_LEN {
            plaintext_with_tag_space[plaintext_len + i] ^= aad_tag[i];
        }
    }
}

#[cfg(feature = "std")]
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    encrypt_in_place(key, nonce, &mut ciphertext, aad);
    ciphertext
}

/// The plaintext length is `ciphertext.len() - 16`, and it will be decrypted in-place at the front
/// of `ciphertext`. If authentication succeeds, this function returns the plaintext as a slice. If
/// authentication fails, or if the ciphertext is shorter than TAG_LEN, it returns `Err(())`.
pub fn decrypt_in_place<'msg>(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &'msg mut [u8],
    aad: &[u8],
) -> Result<&'msg mut [u8], ()> {
    if ciphertext.len() < TAG_LEN {
        return Err(());
    }
    // Zero the last TAG_LEN bytes, in case there's garbage there.
    let plaintext_len = ciphertext.len() - TAG_LEN;
    if plaintext_len > 0 {
        let msg_tag = universal_hash(key, &ciphertext[..plaintext_len], MSG_HASH_COUNTER);
        for i in 0..TAG_LEN {
            ciphertext[plaintext_len + i] ^= msg_tag[i];
        }
    }
    if aad.len() > 0 {
        let aad_tag = universal_hash(key, aad, AAD_HASH_COUNTER);
        for i in 0..TAG_LEN {
            ciphertext[plaintext_len + i] ^= aad_tag[i];
        }
    }
    let mut stream_output = blake3::Hasher::new_keyed(key).update(nonce).finalize_xof();
    xof_xor(&mut stream_output, ciphertext);
    let tag_bytes_remaining: &[u8; TAG_LEN] = ciphertext[plaintext_len..].try_into().unwrap();
    if !constant_time_eq_16(tag_bytes_remaining, &[0; TAG_LEN]) {
        // Zero out the whole buffer to be safe.
        for i in 0..ciphertext.len() {
            ciphertext[i] = 0;
        }
        return Err(());
    }
    Ok(&mut ciphertext[..plaintext_len])
}

#[cfg(feature = "std")]
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut plaintext = ciphertext.to_vec();
    decrypt_in_place(key, nonce, &mut plaintext, aad)?;
    plaintext.truncate(ciphertext.len() - TAG_LEN);
    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use super::*;

    fn paint_test_input(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
    }

    #[test]
    fn test_aead_round_trip() {
        const TEST_KEY: &[u8; 32] = b"whats the Elvish word for friend";
        const TEST_NONCE: &[u8; 12] = b"foobarbazboo";
        let mut input_buf = [0u8; 2000];
        paint_test_input(&mut input_buf);
        let mut output_buf = [0u8; 1000 + TAG_LEN];
        for msg_len in [0, 1, 64, 1000] {
            for aad_len in [0, 1, 64, 1000] {
                let plaintext = &input_buf[..msg_len];
                let aad = &input_buf[..1000 + aad_len];
                output_buf[..msg_len].copy_from_slice(plaintext);
                let msg_with_tag_space = &mut output_buf[..msg_len + TAG_LEN];
                encrypt_in_place(TEST_KEY, TEST_NONCE, msg_with_tag_space, aad);
                let decrypted =
                    decrypt_in_place(TEST_KEY, TEST_NONCE, msg_with_tag_space, aad).unwrap();
                assert_eq!(plaintext, decrypted);
                let bad_aad = b"bad aad";
                decrypt_in_place(TEST_KEY, TEST_NONCE, msg_with_tag_space, bad_aad).unwrap_err();

                #[cfg(feature = "std")]
                {
                    let ciphertext = encrypt(TEST_KEY, TEST_NONCE, plaintext, aad);
                    let decrypted = decrypt(TEST_KEY, TEST_NONCE, &ciphertext, aad).unwrap();
                    assert_eq!(plaintext, &decrypted[..]);
                    decrypt(TEST_KEY, TEST_NONCE, &ciphertext, bad_aad).unwrap_err();
                }
            }
        }
    }
}
