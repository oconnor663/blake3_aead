#![cfg_attr(not(feature = "std"), no_std)]

pub use blake3::KEY_LEN;
use constant_time_eq::constant_time_eq;

pub const TAG_LEN: usize = 16;
const BLOCK_LEN: usize = 64;
const MAX_NONCE_LEN: usize = BLOCK_LEN;
const MAX_MSG_LEN: u64 = 1 << 62;

const MSG_AUTH_SEEK: u64 = 0;
const AAD_AUTH_SEEK: u64 = 1 << 62;
const STREAM_SEEK: u64 = 1 << 63;

fn xor(dest: &mut [u8], other: &[u8]) {
    assert_eq!(dest.len(), other.len());
    for i in 0..dest.len() {
        dest[i] ^= other[i];
    }
}

// This will eventually be supported directly in the public blake3 API, with a high-efficiency
// implementation. In the meantime, this is a low-efficiency helper with a reasonably similar
// signature.
fn xof_xor(output: &mut blake3::OutputReader, seek: u64, dest: &mut [u8]) {
    debug_assert_eq!(0, seek % BLOCK_LEN as u64);
    output.set_position(seek);
    for dest_block in dest.chunks_mut(BLOCK_LEN) {
        let mut output_block = [0u8; BLOCK_LEN];
        output.fill(&mut output_block);
        xor(dest_block, &output_block[..dest_block.len()]);
    }
}

// This will eventually be supported directly in the public blake3 API, with a high-efficiency
// implementation. In the meantime, this is a low-efficiency helper with a reasonably similar
// signature.
pub fn universal_hash(key: &[u8; KEY_LEN], message: &[u8], initial_seek: u64) -> [u8; TAG_LEN] {
    debug_assert_eq!(0, initial_seek % BLOCK_LEN as u64);
    let mut output = [0u8; TAG_LEN];
    for (block_index, block) in message.chunks(BLOCK_LEN).enumerate() {
        let mut xof = blake3::Hasher::new_keyed(key).update(block).finalize_xof();
        let seek = initial_seek + (block_index * BLOCK_LEN) as u64;
        xof_xor(&mut xof, seek, &mut output);
    }
    return output;
}

/// `plaintext_and_tag` contains the plaintext plus `TAG_LEN` extra bytes at the end. The plaintext
/// is encrypted in-place, and the auth tag is written to the extra bytes. The initial contents of
/// the extra bytes are ignored.
pub fn encrypt_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    plaintext_and_tag: &mut [u8],
) {
    assert!(nonce.len() <= MAX_NONCE_LEN);
    assert!(aad.len() as u64 <= MAX_MSG_LEN);
    assert!(plaintext_and_tag.len() >= TAG_LEN);
    let plaintext_len = plaintext_and_tag.len() - TAG_LEN;
    assert!(plaintext_len as u64 <= MAX_MSG_LEN);
    // Zero the last TAG_LEN bytes, so that we don't xof_xor over garbage.
    for i in 0..TAG_LEN {
        plaintext_and_tag[plaintext_len + i] = 0;
    }
    let mut stream_output = blake3::Hasher::new_keyed(key).update(nonce).finalize_xof();
    xof_xor(&mut stream_output, STREAM_SEEK, plaintext_and_tag);
    let (plaintext, tag) = plaintext_and_tag.split_at_mut(plaintext_len);
    let msg_tag = universal_hash(key, plaintext, MSG_AUTH_SEEK);
    xor(tag, &msg_tag);
    let aad_tag = universal_hash(key, aad, AAD_AUTH_SEEK);
    xor(tag, &aad_tag);
}

#[cfg(feature = "std")]
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    encrypt_in_place(key, nonce, aad, &mut ciphertext);
    ciphertext
}

/// The plaintext length is `ciphertext.len() - 16`, and it will be decrypted in-place at the front
/// of `ciphertext`. If authentication succeeds, this function returns the plaintext as a slice. If
/// authentication fails, or if the ciphertext is shorter than `TAG_LEN`, it returns `Err(())`.
pub fn decrypt_in_place<'msg>(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &'msg mut [u8],
) -> Result<&'msg mut [u8], ()> {
    if nonce.len() > MAX_NONCE_LEN {
        return Err(());
    }
    if aad.len() as u64 > MAX_MSG_LEN {
        return Err(());
    }
    if ciphertext.len() < TAG_LEN {
        return Err(());
    }
    let plaintext_len = ciphertext.len() - TAG_LEN;
    if plaintext_len as u64 > MAX_MSG_LEN {
        return Err(());
    }
    let mut tag = universal_hash(key, &ciphertext[..plaintext_len], MSG_AUTH_SEEK);
    let aad_tag = universal_hash(key, aad, AAD_AUTH_SEEK);
    xor(&mut tag, &aad_tag);
    let mut stream_output = blake3::Hasher::new_keyed(key).update(nonce).finalize_xof();
    xof_xor(&mut stream_output, STREAM_SEEK, ciphertext);
    if !constant_time_eq(&tag, &ciphertext[plaintext_len..]) {
        // Invalid plaintext. Clear the whole buffer to be safe.
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
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut plaintext = ciphertext.to_vec();
    decrypt_in_place(key, nonce, aad, &mut plaintext)?;
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
                encrypt_in_place(TEST_KEY, TEST_NONCE, aad, msg_with_tag_space);
                let decrypted =
                    decrypt_in_place(TEST_KEY, TEST_NONCE, aad, msg_with_tag_space).unwrap();
                assert_eq!(plaintext, decrypted);
                let bad_aad = b"bad aad";
                decrypt_in_place(TEST_KEY, TEST_NONCE, bad_aad, msg_with_tag_space).unwrap_err();

                #[cfg(feature = "std")]
                {
                    let ciphertext = encrypt(TEST_KEY, TEST_NONCE, aad, plaintext);
                    let decrypted = decrypt(TEST_KEY, TEST_NONCE, aad, &ciphertext).unwrap();
                    assert_eq!(plaintext, &decrypted[..]);
                    decrypt(TEST_KEY, TEST_NONCE, bad_aad, &ciphertext).unwrap_err();
                }
            }
        }
    }
}
