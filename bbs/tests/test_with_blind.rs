mod tests {
    use ark_bn254::Fr as Scalar;
    use bbs::bbs_bn254::{blind::unblind, verify::verify_no_blind, *};
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

        let commitment = blind(&params, &messages, &3).unwrap();

        // m0, m1, m2 are visual, m3, m4 are blinded
        let visual_messages = messages[..3].to_vec();
        let mut signature = sign_with_blind(&params, &sk, &3, &commitment.commitment, &visual_messages).unwrap();

        signature = unblind(&params, &signature, &commitment).unwrap();

        let ok = verify_no_blind(&params, &pk, &messages, &signature).unwrap();
        assert!(ok);
    }
}
