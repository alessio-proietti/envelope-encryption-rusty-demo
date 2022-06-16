use base64::*;
use dryoc::dryocsecretbox::*;
#[cfg(target_os = "hermit")]
use hermit_sys as _;

// This "Object" represents a KMS Server, the TTP in Envelope Cncryption Protocol
struct KMS {
	cmk: dryoc::dryocsecretbox::Key,
}

impl KMS {
	fn new() -> Self {
		KMS { cmk: Key::gen() }
	}

	fn generate_data_key(&self) -> (String, String, String) {
		
		// fresh data key and nonce are generated as random bytes at request
		let plaintext_data_key = Key::gen();
		let nonce = Nonce::gen();

		// dryoc ciphertext is complex structure with authentication tag, needs SerDe and encoding
		let encrypted_data_key =
			DryocSecretBox::encrypt_to_vecbox(&plaintext_data_key, &nonce, &self.cmk);
		let serialized_encrypted_data_key = serde_json::to_string(&encrypted_data_key).unwrap();
		let encoded_encrypted_data_key = encode(serialized_encrypted_data_key.as_bytes());


		// plaintext data key, nonce are binaries and need text encoding for safe transport
		let encoded_plaintext_data_key = encode(&plaintext_data_key);
		let encoded_nonce = encode(&nonce);

		// send back a tuple, ideally nonce would be stored in a DB
		(
			encoded_plaintext_data_key,
			encoded_nonce,
			encoded_encrypted_data_key,
		)
	}

	fn decrypt_data_key(
		&self,
		encoded_serialized_encrypted_data_key: &String,
		encoded_nonce: &String,
	) -> String {

		// nonce can be simply decoded
		let nonce = decode(encoded_nonce).unwrap();
		
		// dryoc ciphertext is complex structure with authentication tag, needs SerDe 
		let bytes_serialized_encrypted_data_key =
			decode(encoded_serialized_encrypted_data_key).unwrap();
		let serialized_encrypted_data_key =
			String::from_utf8_lossy(&bytes_serialized_encrypted_data_key);
		let encrypted_data_key: VecBox =
			serde_json::from_str(&serialized_encrypted_data_key).unwrap();
		
		
			let plaintext_data_key = encrypted_data_key
			.decrypt_to_vec(&nonce, &self.cmk)
			.expect("unable to decrypt");

		// plaintext data key is binary and needs text encoding for safe transport
		return encode(plaintext_data_key);
	}
}

fn main() {
	// this is data we want to encrypt and store
	let message = b"a very secret message";

	// a singleton istance of KMS "Server" is instatiated
	let a_kms = KMS::new();


	/* First Phase of The Protocol */
	// we request a fresh data key pair for encryption
	let (encoded_data_key, encoded_nonce, encrypted_data_key) = a_kms.generate_data_key();

	// we decode from base64 a plaintext data key and a nonce
	let data_key = decode(&encoded_data_key).unwrap();
	let nonce = decode(&encoded_nonce).unwrap();

	// data message is encrypted
	let ciphertext = DryocSecretBox::encrypt_to_vecbox(&message, &nonce, &data_key);

	// data, encrypted data key, nonce are stored while plaintext key is (should be) discarded here
	let stored_ciphertext = (ciphertext, encrypted_data_key, encoded_nonce);

	/* Second Phase of The Protocol */
	// later on client request plaintext data to decrypt, send encrypted copy and receives backs the requested key
	let requested_data_key = a_kms.decrypt_data_key(&stored_ciphertext.1, &stored_ciphertext.2);
	
	// requested key and nonce are decoded from base64
	let decoded_requested_data_key = decode(&requested_data_key).unwrap();
	let decoded_nonce_2 = decode(&stored_ciphertext.2).unwrap();

	// Decryption of data at rest
	let deciphered_message = stored_ciphertext.0.decrypt_to_vec(&decoded_nonce_2, &decoded_requested_data_key).expect("unable to decrypt");
	

	// Here original message and original data key are compared with those obtained in the second phase of the protocol
	assert_eq!(String::from_utf8_lossy(&deciphered_message), String::from_utf8_lossy(message));
	assert_eq!(&encoded_data_key, &requested_data_key);

	// End
}
