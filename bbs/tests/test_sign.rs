
mod tests {
    use bbs::bbs_bn254::*;
    use ark_bn254::Fr as Scalar;
    #[test]
    fn test_sign() {
        let (params, pk, sk) = keygen(5);
        let messages = vec![
            Scalar::from(10u64),
            Scalar::from(20u64),
            Scalar::from(30u64),
            Scalar::from(40u64),
            Scalar::from(50u64),
        ];

        let signature = sign_no_blind(&params, &sk, &messages).unwrap();
        assert!(signature.A.is_on_curve());
    }
}