# Rust CISA Full Aggregation Playground

Full aggregation is an interactive protocol for aggregating signatures signing over different messages from multiple signers. The following is an rust implementation of the [dahLIAS](https://eprint.iacr.org/2025/692.pdf) full aggregation protocol.

## The Protocol

### Setup

Signers must generate and persist their keypairs
$(x_i, X_i = x_i \cdot G)$

### Nonce Collection

1. Signers generate nonce pairs $(r_1, r_2)$ and send the corresponding public components $(R_1 = r_1 \cdot G, R_2 = r_2 \cdot G)$ to the coordinator. Along side their message $m_i$ and public key $X_i$.

2. Coordinator will collect all the nonce pairs and then compute the effective "group" nonce.

    $$R_1 = \sum_{i=1}^n R_{1,i}; R_2 = \sum_{i=1}^n R_{2,i}$$
    $$ctx_i = (R_1, R_2, (X_i, m_i, R_{2, i}))$$
    $$\beta = H_{non}(ctx)$$

### Signature Generation

1. Coordinator will distribute the effective nonce ($R$) and the context ($ctx$) to the signers.

2. Signers calculate their challenge $c_i = H_{sig}(L, R, X_i, m_i)$ where $L$ is list of tuples $(X_i, m_i)$.
and sign $s_i = r_{1,i} + \beta r_{2,i} + c_i x_i$. Signers send their signature $s_i$ to the coordinator.

3. Lastly, coordinator will aggregate all the signatures $s_i$ to get the final signature $s = \sum_{i=1}^n s_i$.
The final signature is $\sigma = (s, R)$.

### Verification

Verification is defined as:
$$g^s = R \prod_{i=1}^n X_i^{H_{sig}(L, R, X_i, m_i)}$$
