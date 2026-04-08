use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

pub fn serialize_scalar<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = Vec::new();
    scalar
        .serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

pub fn deserialize_scalar<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    Scalar::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
}

pub fn serialize_g1<S>(g1: &G1, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = Vec::new();
    g1.serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

pub fn serialize_vec_g1<S>(g1_vec: &Vec<G1>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(g1_vec.len()))?;
    for g1 in g1_vec {
        let mut bytes = Vec::new();
        g1.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        seq.serialize_element(&bytes)?;
    }
    seq.end()
}

pub fn serialize_g2<S>(g2: &G2, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = Vec::new();
    g2.serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

pub fn deserialize_g1<'de, D>(deserializer: D) -> Result<G1, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    G1::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
}

pub fn deserialize_g2<'de, D>(deserializer: D) -> Result<G2, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    G2::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
}

pub fn deserialize_vec_g1<'de, D>(deserializer: D) -> Result<Vec<G1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes_vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
    bytes_vec
        .into_iter()
        .map(|bytes| G1::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom))
        .collect()
}

pub fn serialize_vec_scalar<S>(scalar_vec: &Vec<Scalar>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(scalar_vec.len()))?;
    for scalar in scalar_vec {
        let mut bytes = Vec::new();
        scalar
            .serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        seq.serialize_element(&bytes)?;
    }
    seq.end()
}

pub fn deserialize_vec_scalar<'de, D>(deserializer: D) -> Result<Vec<Scalar>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes_vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
    bytes_vec
        .into_iter()
        .map(|bytes| Scalar::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom))
        .collect()
}