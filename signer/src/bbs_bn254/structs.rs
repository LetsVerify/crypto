#![allow(non_snake_case, dead_code)]

use ark_bn254::{G1Affine as G1, G2Affine as G2, Fr as Scalar};

/// BBS+ 公共参数
/// 包含签名系统的生成元和消息基点
pub struct Parameters {
    /// 消息数量上限
    pub L: usize,
    /// G1 生成元 g1
    pub g1: G1,
    /// G2 生成元 g2
    pub g2: G2,
    /// 消息基点向量 H = [h_0, h_1, ..., h_L]
    /// h_0 用于盲化因子，h_1..h_L 分别对应每条消息
    pub H: Vec<G1>,
}

/// BBS+ 公钥
/// w = x * g2，由私钥 x 和生成元 g2 计算得出
pub struct PublicKey {
    pub w: G2,
}

/// BBS+ 私钥
pub struct PrivateKey {
    /// 私钥标量 x ∈ Fr
    pub x: Scalar,
}

/// BBS+ 签名
/// 签名由三元组 (A, e, s) 构成，满足：
///   e(A, w + e*g2) = e(g1 + h_0*s + h_1*m_1 + ... + h_L*m_L, g2)
pub struct Signature {
    /// G1 上的签名点 A
    pub A: G1,
    /// 随机标量 e ∈ Fr
    pub e: Scalar,
    /// 随机标量 s ∈ Fr
    pub s: Scalar,
}

/// 待签消息集合
pub struct Messages {
    /// 消息标量列表 m_1, ..., m_L（每条消息映射为 Fr 元素）
    pub msgs: Vec<Scalar>,
}

/// 盲签名请求中的承诺
/// 持有者隐藏部分消息并生成承诺 C = h_0*s' + h_1*m_1 + ...
pub struct BlindedCommitment {
    /// 承诺点 C ∈ G1
    pub commitment: G1,
    /// 盲化因子 s' ∈ Fr
    pub blinding_factor: Scalar,
}

/// 盲签名承诺的知识证明（PoK of Committed Values）
/// 用于证明持有者知道承诺 C 中隐藏消息的具体值，而不泄露这些值
pub struct CommitmentProof {
    /// 挑战值 c ∈ Fr（Fiat-Shamir 哈希）
    pub challenge: Scalar,
    /// 盲化因子响应 s_hat = s' + c * blinding_factor
    pub s_hat: Scalar,
    /// 各隐藏消息的响应 m_hat_i = r_i + c * m_i
    pub m_hats: Vec<Scalar>,
}

/// 签名知识证明（PoK of Signature）
/// 用于选择性披露：在不暴露签名 (A, e, s) 的前提下，
/// 证明持有者拥有一个对部分消息的有效 BBS+ 签名
pub struct SignatureProof {
    /// 随机化签名点 A' = A * r1
    pub A_prime: G1,
    /// A_bar = A' * (-e) + h_0 * (s - s'' * r1)（中间计算点）
    pub A_bar: G1,
    /// D = h_0^r2 * B^r1 的中间点
    pub D: G1,
    /// 挑战值 c ∈ Fr（Fiat-Shamir 哈希）
    pub challenge: Scalar,
    /// e 的响应：e_hat = e_tilde + c * e
    pub e_hat: Scalar,
    /// r2 的响应：r2_hat = r2_tilde + c * r2
    pub r2_hat: Scalar,
    /// r3 的响应：r3_hat = r3_tilde + c * r3（r3 = 1/r1）
    pub r3_hat: Scalar,
    /// s'' 的响应：s_hat = s_tilde + c * s''
    pub s_hat: Scalar,
    /// 各隐藏消息的响应：m_hat_i = m_tilde_i + c * m_i
    pub m_hats: Vec<Scalar>,
    /// 被披露的消息索引及其值
    pub disclosed: Vec<(usize, Scalar)>,
}