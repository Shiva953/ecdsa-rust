#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    rust_2018_idioms,
    future_incompatible,
    unused,

    unused_lifetimes,
    unused_qualifications,
    unused_results,

    anonymous_parameters,
    deprecated_in_future,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    keyword_idents,
    macro_use_extern_crate,
)]
#![cfg_attr(feature = "std", warn(missing_debug_implementations,))]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::wildcard_imports)]

mod private_key;
mod public_key;
mod signature;
mod sign;
mod verify;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;


use std::prelude::v1::*;
use zkp_elliptic_curve::{window_table_affine, Affine, GENERATOR};
#[cfg(not(feature = "std"))]
extern crate no_std_compat as std;
use lazy_static::lazy_static;

lazy_static! {
    static ref GENERATOR_TABLE: [Affine; 32] = {
        let mut naf = <[Affine; 32]>::default();
        window_table_affine(&GENERATOR, &mut naf);
        naf
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use zkp_elliptic_curve::ScalarFieldElement;

    proptest!(
        #[test]
        fn test_ecdsa(digest: ScalarFieldElement, private_key: PrivateKey) {
            let public_key = PublicKey::from(&private_key);
            let signature = private_key.sign(&digest);
            prop_assert!(verify(&signature, &public_key, &digest));
        }
    );
}