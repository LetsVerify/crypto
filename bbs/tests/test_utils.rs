mod tests {
    use ark_bn254::Fr as Scalar;
    use bbs::bbs_bn254::{Parameters, Signature, keygen, sign_no_blind};

    #[test]
    fn test_to_json() {
        let (params, _, sk) = keygen(5);
        let mut json_str = params.export_to_json();
        println!("Parameters in JSON format: {}", json_str);

        let new_params = Parameters::load_from_json(&json_str).unwrap();
        assert_eq!(params.L, new_params.L);
        assert_eq!(params.H[1], new_params.H[1]);

        let mut messages = Vec::new();
        for i in 0..params.L {
            let msg = Scalar::from((i + 1) as u64);
            messages.push(msg);
        }

        let signature = sign_no_blind(&params, &sk, &messages).unwrap();
        json_str = signature.export_to_json();
        println!("\nSignature in JSON format: {}", json_str);

        let new_signature = Signature::load_from_json(&json_str).unwrap();
        assert_eq!(signature.A, new_signature.A);
    }
}
