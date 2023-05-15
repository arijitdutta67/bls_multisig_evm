use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use sha2::{Digest, Sha256};

fn main() {
    let message = "Testing optimised EVM multisig";
    let multisig: BlsMultisig = BlsMultisig::sign(&message);
    println!("message = {}", multisig.message);
    println!("multisig = {}", multisig.signature);
    println!("aggregated public key = {}", multisig.apk);
    BlsMultisig::verify(&multisig);
}

struct BlsMultisig {
    apk: G2Affine,
    pubkeys: Vec<G1Affine>,
    message: String,
    signature: G1Affine,
}

impl BlsMultisig {
    // compute multisig
    // Todo: To added proof of possession test in the submitter to avoid Rogue key attack
    fn sign(message: &str) -> BlsMultisig {
        println!("Computing the multisig...");
        let g1_generator = G1Affine::generator();
        let g2_generator = G2Affine::generator();

        //generate the secret keys of Alice, Bob, and Chalie
        let alice_seed = "Alice";
        let bob_seed = "Bob";
        let charlie_seed = "Charlie";
        let alice_sk = Self::hash_to_scalar(&alice_seed);
        let bob_sk = Self::hash_to_scalar(&bob_seed);
        let charlie_sk = Self::hash_to_scalar(&charlie_seed);

        // Generate the hash to curve of the message
        let message_scalar = Self::hash_to_scalar(&message);
        let h_m: G1Affine = (g1_generator * message_scalar).into();

        // Compute the multisignature
        // Todo: this will change when the submitter is refactored out from the sign code
        let mut aggr_sk: Scalar = alice_sk;
        aggr_sk += bob_sk;
        aggr_sk += charlie_sk;
        let sigma: G1Affine = (h_m * aggr_sk).into();

        // Compute the public keys (apk and p_1)
        let alice_pk1: G1Affine = (g1_generator * alice_sk).into();
        let alice_pk2: G2Affine = (g2_generator * alice_sk).into();
        let bob_pk1: G1Affine = (g1_generator * bob_sk).into();
        let bob_pk2: G2Affine = (g2_generator * bob_sk).into();
        let charlie_pk1: G1Affine = (g1_generator * charlie_sk).into();
        let charlie_pk2: G2Affine = (g2_generator * charlie_sk).into();
        let mut apk: G2Projective = alice_pk2.into();
        let bob_pk2: G2Projective = bob_pk2.into();
        apk += bob_pk2;
        let charlie_pk2: G2Projective = charlie_pk2.into();
        apk += charlie_pk2;
        let apk: G2Affine = apk.into();
        BlsMultisig {
            apk: apk,
            pubkeys: [alice_pk1, bob_pk1, charlie_pk1].to_vec(),
            message: message.to_string(),
            signature: sigma,
        }
    }
    // Method to convert a string to a field scalar
    fn hash_to_scalar(data: &str) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        let result_bytes: [u8; 32] = result.into();
        let scalar: Scalar = Scalar::from_bytes(&result_bytes).unwrap();
        scalar
    }
    // Verify the multisig
    fn verify(multisig: &BlsMultisig) {
        println!("Verifying the multisig...");
        let g1_generator = G1Affine::generator();
        let g2_generator = G2Affine::generator();
        let message = multisig.message.clone();
        let apk = multisig.apk.clone();
        let sigma = multisig.signature.clone();
        let alice_pk1 = multisig.pubkeys[0].clone();
        let bob_pk1 = multisig.pubkeys[1].clone();
        let charlie_pk1 = multisig.pubkeys[2].clone();

        // Compute alpha
        let alpha_seed = "Alpha";
        let alpha = Self::hash_to_scalar(&alpha_seed);

        // Compute the hash to curve of the message
        let message_scalar = Self::hash_to_scalar(&message);
        let h_m: G1Affine = (g1_generator * message_scalar).into();

        // Compute P_1
        let mut p_1: G1Projective = alice_pk1.into();
        let bob_pk1_projective: G1Projective = bob_pk1.into();
        p_1 += bob_pk1_projective;
        let charlie_pk1_projective: G1Projective = charlie_pk1.into();
        p_1 += charlie_pk1_projective;
        let p_1: G1Affine = p_1.into();

        // compute pairing_1 (negative of the original)
        let mut pairing_1_l: G1Projective = sigma.into();
        let alpha_p_1: G1Projective = (p_1 * alpha).into();
        pairing_1_l -= alpha_p_1;
        let pairing_1_l: G1Affine = pairing_1_l.into();
        let pairing_1_r: G2Affine = g2_generator;
        let pairing_1 = pairing(&pairing_1_l, &pairing_1_r);

        // compute pairing_2
        let mut pairing_2_l: G1Projective = h_m.into();
        let alpha_h: G1Projective = (g1_generator * alpha).into();
        pairing_2_l -= alpha_h;
        let pairing_2_l: G1Affine = pairing_2_l.into();
        let pairing_2_r: G2Affine = apk;
        let pairing_2 = pairing(&pairing_2_l, &pairing_2_r);

        // compair the pairings
        if pairing_1 == pairing_2 {
            println!("The signature is verified successfully.");
        } else {
            println!("The signature could not be verified.");
        }
    }
}
