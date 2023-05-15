pragma circom 2.1.4;

include "bls12_381.circom";

template Verify () {

// Define input
signal input apk_affine_x : Fr;
signal input apk_affine_y : Fr;
signal input p1_x: Fq;
signal input p1_y: Fq;
signal input s_x: Fq;
signal input s_y: Fq;

// Define local variables
var apk : G2Affine = G2Affine([apk_affine_x, apk_affine_y]);
var p1: G1Affine = G1Affine(p1_x, p1_y);
var s: G1Affine = G1Affine(s_x, s_y);


var msg_scalar : Fr;
var alpha : Fr;
var h_m : G1;


// Compute message scalar from message hash
msg_scalar := hash_to_scalar("Testing optimised EVM multisig");

// Compute alpha from a fixed seed
alpha := hash_to_scalar("Alpha");

// Compute hash-to-curve of the message
h_m := g1_generator * msg_scalar;

// Verify the signature by comparing pairings
assert(pairing(s - p1 * alpha, g2_generator) == pairing(h_m - g1_generator * alpha, apk));
}

component main = Verify(); 


/* INPUT = {
    "u": 4965661367192848881,
    "apk_affine_x": 0x08d994afe84cca59864e13f363ec395ddb6bde0cb2b74645ac07bf4fb5e98614b4aa4982e62f838044ee0149cb643d3b + 0x06e2f8b753f1c6cc770891d788118d74fe24cdbdc6c9329fad73c49262625e6b8cc806779689d9e7e7f71c0ffb8106b6*u,
    "apk_affine_y": 0x1901f54c3df24de14eddb68f194269ad7ed54333db60887cd3938e57be504aa941293a7d36d5edb988848fd892c0133d + 0x0db7dfe3c0c5f08e50903703b94c4789dea8bba238da4d0dd79fbee9b77fdbcd3114bbfdb05c5117e8e98c3bdcf76e12*u,
    "p1_x": 0x08b7b97314360cb8d6f56995e79a4155d011e7a0eeb267b23a39d0f1e76ce3e498577a051f33db356f632fdf1c62c1e2,
    "p1_y": 0x19e9b29259118c1750b75b498f5c158d82edda5bacaa922e74195a547f8e060336999ea861817a380773e614b64fc76f,
    "s_x": 0x0f47e2d01e7dd437c88d653c99bd8c358493b492cfa75cf59e1be7d3692cae4643946a5ab6096817ee11631fa6be9629,
    "s_y": 0x168c525764dc1a99069b3212fd17df8d0682779818f5c347e15abfdcb45ec64e2752f9851d7db0d789b8ee650878ce73
} */