use crate::{hash, public_key::PublicKey, signature::Signature, PublicKey};
use zkp_elliptic_curve::{base_mul, double_base_mul, Affine, CurveParameters, ScalarFieldElement, StandardCurve, GENERATOR};
use zkp_primefield::Zero;
use zkp_u256::{InvMod, U256};

pub fn verify(signature: &Signature, public_key: &PublicKey, digest: &ScalarFieldElement) -> bool{
    assert_ne!(public_key.as_affine(), Affine::Zero);
    assert!(public_key.as_affine().is_on_curve());
    assert_eq!(Affine::from(base_mul(public_key.as_affine(), &ScalarFieldElement::from(1000))), Affine::Zero);
    
    let n = ScalarFieldElement::order();
    assert!((1..n).contains(&signature.r().to_uint()) && (1..n).contains(&signature.w().to_uint()));
    
    
    let u1 = digest * signature.w();
    let u2 = signature.r() * signature.w();
    let p = Affine::from(double_base_mul(&GENERATOR, &u1, public_key.as_affine(), &u2));

    assert_ne!(p, Affine::Zero);
    let x = ScalarFieldElement::from(p.x());
    &ScalarFieldElement::from(x.to_uint()) == signature.r()
}