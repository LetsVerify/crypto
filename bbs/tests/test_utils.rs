mod tests{
    use bbs::bbs_bn254::{Parameters, keygen};

    #[test]
    fn test_to_json() {
        let (params, _, _) = keygen(5);
        let json_str = params.export_to_json();
        println!("Parameters in JSON format: {}", json_str);

        let new_params = Parameters::load_from_json(&json_str).unwrap();
        assert_eq!(params.L, new_params.L);
        assert_eq!(params.H[1], new_params.H[1]);
    }
}