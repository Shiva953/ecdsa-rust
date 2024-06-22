use crate::{hash, private_key::PrivateKey, signature::Signature};
use zkp_elliptic_curve::{base_mul, Affine, CurveParameters, ScalarFieldElement, StandardCurve, GENERATOR};
use zkp_primefield::Zero;
use zkp_u256::{Inv, InvMod, U256};


pub fn sign(private_key: &PrivateKey, digest: &ScalarFieldElement) -> Signature{
    for i in 1..1000{
        let mut k = ScalarFieldElement::from(private_key.hash(digest, i as u64));
        if(k.is_zero()){
            continue;
        }
        // R = k.G, . is the ecc mult
        let mut R = Affine::from(&base_mul(&*GENERATOR, &k));
        match R{
            Affine::Zero => continue,
            Affine::Point { x, .. } => {
                let r_x = ScalarFieldElement::from(x.to_uint());
                if(r_x.is_zero()){
                    continue;
                }
                let d = private_key.as_scalar_field_element();
                let s = Inv((&r_x * d) + digest);
                match s{
                    Some(val) => {return Signature::new(r_x, k * val)},
                    None => continue
                }
            },
        }
        panic!("k not found in 1000 tries!")
    }
}