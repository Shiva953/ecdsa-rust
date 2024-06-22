use std::env;
use crate::{PrivateKey, Signature, GENERATOR_TABLE};
use crate::sign::sign;
use crate::verify::verify;
use tiny_keccak::{Hasher, Sha3};
use zkp_elliptic_curve::{ScalarFieldElement, Affine};
use zkp_u256::U256;
use rand::Rng;

mod private_key;
mod public_key;
mod signature;
mod sign;
mod verify;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;
use ECC_impl_rust::PublicKey;

fn main(){
    let mut message = String::from("init");
    let args: Vec = env::args().collect();
        if args.len() >1 {

            message = args[1].clone();
        }
    println!("Message: {}",message);

    let mut msg=message.as_bytes();

    let mut sha3 = Sha3::v256();
    sha3.update(message);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    let u256_output = U256::from_bytes_be(&output);
    let mut digest = ScalarFieldElement::from(u256_output);
    
    let mut rng = rand::thread_rng();
    let random_scalar = ScalarFieldElement::random(&mut rng);
    let private_key = PrivateKey::new(random_scalar);
    println!("Private Key:{:?}", private_key.as_scalar_field_element().into());

    let signature: Signature = sign(&private_key, &digest);
    println!("Signature: {:?}",signature);

    let public_key = PublicKey::from(&private_key); 
    let sig_verify = verify(&signature, &public_key, &digest);

    if sig_verify{ 
            println!("Message signature is valid", message); 
        } else { 
            println!("Invalid Message Signature", message);
        }

}