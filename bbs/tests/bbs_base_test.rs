mod tests {
    use bbs::bbs::*;
    use bbs::structs::*;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use ark_bn254::Fr as Scalar;

    #[test]
    fn bbs_base_test() {
        let mut rng = test_rng();
        let l = 5;
        
        // 1. Setup
        let params = setup(l, &mut rng);
        
        // 2. KeyGen
        let (pk, sk) = keygen(&mut rng);
        
        // 3. Create Messages
        let mut msgs = Vec::new();
        for _ in 0..l {
            msgs.push(Scalar::rand(&mut rng));
        }
        let messages = Messages(msgs);
        
        // 4. Sign
        let signature = sign(&messages, &params, &sk, &mut rng).expect("failed to sign");
        
        // 5. Verify
        let is_valid = verify(&messages, &signature, &params, &pk);
        assert!(is_valid, "BBS signature verification failed!");
    }
}