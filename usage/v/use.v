#flag -L@VMODROOT/../../target/debug -lcrpgp
#include "@VMODROOT/../crpgp.h"

fn generate_key() ?SignedSecretKey {
	builder := new_secret_key_param_builder()?
	builder.primary_key_id("Omar Elawady <elawadio@incubaid.com>")?
	builder.key_type(C.KeyType{KeyType_Tag.ed_dsa, 0})?
	subkey_builder := new_subkey_params_builder()
	subkey_builder.key_type(C.KeyType{KeyType_Tag.ecdh, 0})?
	subkey := subkey_builder.build()?
	builder.subkey(subkey)?
	params := builder.build()?
	sk := params.generate_and_free()?
	ssk := sk.sign()?
	return ssk
}

fn main() {
	mut secret_key := generate_key()?
	// --- serialization deserialization ---
	mut armored := secret_key.to_armored()?
	println("signed secret key")
	println(armored)
	secret_key = signed_secret_key_from_armored(
		armored
	)?
	// -------------------------------------
	mut spk := secret_key.public_key()?.sign_and_free(secret_key)?
	// --- serialization deserialization ---
	armored = spk.to_armored()?
	println("signed public key")
	println(armored)
	spk = signed_public_key_from_armored(armored)?
	// -------------------------------------
	mut sig := secret_key.create_signature(str_to_bytes("omar"))?
	armored = sig.to_armored()?
	println("signature")
	println(armored)
	sig = signature_from_armored(armored)?
	spk.verify(str_to_bytes("omar"), sig)?
	println("verification succeeded")
	spk.verify(str_to_bytes("khaled"), sig) or {
		print("verification failed as expected for invalid sig:")
		println(err)
	}

	encrypted := spk.encrypt_with_any(str_to_bytes("omar\0"))?
	decrypted := secret_key.decrypt(encrypted)?
	print("decrypted (should be omar): ")
	println(unsafe { cstring_to_vstring(&char(&decrypted[0])) })
}