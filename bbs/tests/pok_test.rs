mod tests {
    use ark_bn254::Fr as Scalar;
    use ark_std::UniformRand;
    use ark_std::test_rng;
    use bbs::bbs::*;
    use bbs::pok::*;
    use bbs::structs::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_pok_interactive() {
        let mut rng = test_rng();
        let l = 5;

        let params = setup(l, &mut rng);
        let (pk, sk) = keygen(&mut rng);

        let mut msgs = Vec::new();
        for _ in 0..l {
            msgs.push(Scalar::rand(&mut rng));
        }
        let messages = Messages(msgs.clone());

        let signature = sign(&messages, &params, &sk, &mut rng).expect("failed to sign");

        // Let's disclose indices 0 and 2
        let mut disclosed_indices = HashSet::new();
        disclosed_indices.insert(0);
        disclosed_indices.insert(2);

        let mut disclosed_msgs = HashMap::new();
        disclosed_msgs.insert(0, msgs[0]);
        disclosed_msgs.insert(2, msgs[2]);

        // Prover Step 1
        let (commitment, state) =
            pok_commit(&params, &messages, &signature, &disclosed_indices, &mut rng).unwrap();

        // Verifier Step 1
        let challenge = Scalar::rand(&mut rng);

        // Prover Step 2
        let response = pok_prove(&state, &challenge);

        // Verifier Step 2
        let is_valid = pok_verify(
            &params,
            &pk,
            &disclosed_msgs,
            &commitment,
            &challenge,
            &response,
        );
        assert!(is_valid, "Interactive PoK verification failed!");
    }

    #[test]
    fn test_pok_non_interactive() {
        let mut rng = test_rng();
        let l = 5;

        let params = setup(l, &mut rng);
        println!("{:?}", params);
        let (pk, sk) = keygen(&mut rng);
        println!("Public Key: {:?}, Private Key: {:?}", pk, sk);

        let mut msgs = Vec::new();
        for _ in 0..l {
            msgs.push(Scalar::rand(&mut rng));
        }
        let messages = Messages(msgs.clone());

        let signature = sign(&messages, &params, &sk, &mut rng).expect("failed to sign");

        // Let's disclose indices 1 and 4
        let mut disclosed_indices = HashSet::new();
        disclosed_indices.insert(1);
        disclosed_indices.insert(4);

        let mut disclosed_msgs = HashMap::new();
        disclosed_msgs.insert(1, msgs[1]);
        disclosed_msgs.insert(4, msgs[4]);

        let ctx = "LestsVerify".as_bytes();

        // NIZK Prove
        let proof = nizk_prove(
            ctx,
            &params,
            &pk,
            &messages,
            &signature,
            &disclosed_indices,
            &mut rng,
        )
        .unwrap();

        // NIZK Verify
        let is_valid = nizk_verify(ctx, &params, &pk, &disclosed_msgs, &proof);
        assert!(is_valid, "Non-Interactive PoK verification failed!");
    }

    #[test]
    fn test_pok_non_interactive_prefix() {
        let mut rng = test_rng();
        let l = 5;

        let params = setup(l, &mut rng);
        let (pk, sk) = keygen(&mut rng);

        let mut msgs = Vec::new();
        for _ in 0..l {
            msgs.push(Scalar::rand(&mut rng));
        }
        let messages = Messages(msgs.clone());

        let signature = sign(&messages, &params, &sk, &mut rng).expect("failed to sign");

        // Disclose indices 0..2 (count = 3)
        let disclosed_count = 3;
        let disclosed_msgs = &msgs[0..disclosed_count];

        let ctx = "LestsVerify".as_bytes();
        // NIZK Prove
        let proof = nizk_prove_prefix(
            ctx,
            &params,
            &pk,
            &messages,
            &signature,
            disclosed_count,
            &mut rng,
        )
        .unwrap();

        // NIZK Verify
        let is_valid = nizk_verify_prefix(ctx, &params, &pk, disclosed_msgs, &proof);
        assert!(is_valid, "Prefix Non-Interactive PoK verification failed!");
    }
}
