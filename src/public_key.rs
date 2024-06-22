#![allow(unused_qualifications)]

use crate::{PrivateKey, Signature, GENERATOR_TABLE};
#[cfg(feature = "parity_codec")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zkp_elliptic_curve::{base_mul, double_base_mul, Affine, ScalarFieldElement};
use zkp_primefield::Zero;

#[derive(PartialEq, Eq, Clone, Default, Debug)]
#[cfg_attr(feature = "parity_codec", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey(Affine);

use crate::verify::verify;

impl PublicKey{
    pub fn as_affine(&self) -> &Affine {
        &self.0
    }
}

impl From<&PrivateKey> for PublicKey {
    //GENERATING PUBLIC KEY FROM PRIVATE KEY
    fn from(private_key: &PrivateKey) -> Self {
        let generator_table = crate::get_generator_table();
        let affine = Affine::from(&base_mul(&generator_table, private_key.as_scalar_field_element()));
        Self(affine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkp_macros_decl::{field_element, u256h};
    use zkp_primefield::FieldElement;
    use zkp_u256::U256;

    #[test]
    fn test_pubkey() {
        let private_key = PrivateKey::from(u256h!(
            "03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc"
        ));
        let expected = PublicKey::from(Affine::new(
            field_element!("077a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43"),
            field_element!("054d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06"),
        ));
        let result = PublicKey::from(&private_key);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_verify() {
        let digest = ScalarFieldElement::from(u256h!(
            "01e542e2da71b3f5d7b4e9d329b4d30ac0b5d6f266ebef7364bf61c39aac35d0"
        ));
        let public_key = PublicKey::from(Affine::new(
            field_element!("077a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43"),
            field_element!("054d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06"),
        ));
        let signature = Signature::new(
            ScalarFieldElement::from(u256h!(
                "01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca"
            )),
            ScalarFieldElement::from(u256h!(
                "07656a287e3be47c6e9a29482aecc10cd8b1ae4797b4b956a3573b425d1e66c9"
            )),
        );
        assert!(verify(&signature, &public_key, &digest));
    }
}