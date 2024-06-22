#![allow(unused_qualifications)]

use crate::{Signature, GENERATOR_TABLE};
#[cfg(feature = "parity_codec")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};
use zkp_elliptic_curve::{base_mul, Affine, ScalarFieldElement};
use zkp_primefield::{Inv, Zero};
use zkp_u256::U256;

#[cfg(any(test, feature = "proptest"))]
use proptest_derive::Arbitrary;

#[derive(PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(test, derive(Arbitrary))]
#[cfg_attr(test, proptest(no_params))]
#[cfg_attr(feature = "parity_codec", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub struct PrivateKey(ScalarFieldElement);

use crate::sign::sign;

impl PrivateKey {
    pub fn new(scalar: ScalarFieldElement) -> Self {
        Self(scalar)
    }

    pub fn as_scalar_field_element(&self) -> &ScalarFieldElement {
        &self.0
    }

    pub fn hash(&self, digest: &ScalarFieldElement, nonce: u64) -> ScalarFieldElement {
        let mut output = [0; 32];
        let mut sha3 = Sha3::v256();
        sha3.update(
            &[
                self.0.to_uint().to_bytes_be(),
                digest.to_uint().to_bytes_be(),
                U256::from(nonce).to_bytes_be(),
            ]
            .concat(),
        );
        sha3.finalize(&mut output);
        U256::from_bytes_be(&output).into()
    }
}

impl From<ScalarFieldElement> for PrivateKey {
    fn from(scalar: ScalarFieldElement) -> Self {
        Self(scalar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signature;
    use zkp_macros_decl::u256h;

    #[test]
    fn test_sign() {
        let digest = ScalarFieldElement::from(u256h!(
            "01921ce52df68f0185ade7572776513304bdd4a07faf6cf28cefc65a86fc496c"
        ));
        let private_key = PrivateKey::from(u256h!(
            "03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc"
        ));
        let expected = Signature::new(
            ScalarFieldElement::from(u256h!(
                "006d1f96368ae3a73893790a957d86850d443e77c157682cc65f4943b8385bcb"
            )),
            ScalarFieldElement::from(u256h!(
                "05a48d5ab6ccea487a6d0c2e9bc5ea5e5c7857252f72937250ef3ad8b290b29f"
            )),
        );
        let result = sign(&private_key, &digest);
        assert_eq!(result, expected);
    }
}