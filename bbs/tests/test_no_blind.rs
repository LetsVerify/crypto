mod tests {
    use ark_bn254::Fr as Scalar;
    use bbs::bbs_bn254::{verify::verify_no_blind, *};
    #[test]
    fn test_no_blind() {
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

        let ok = verify_no_blind(&params, &pk, &messages, &signature).unwrap();
        assert!(ok);
    }
}
