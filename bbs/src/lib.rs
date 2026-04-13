pub mod bbs;
mod modified_serde;
pub mod pok;
pub mod pub_use;
pub mod structs;
pub mod extend;
pub mod extend_structs;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
