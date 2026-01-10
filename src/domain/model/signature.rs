pub struct Digest<T> {
    pub digest: T,
}
pub struct SignatureShare<T> {
    pub index: usize,
    pub signature_share: T,
}

pub struct Signature<T> {
    pub signature: T,
}

impl<T> Digest<T> {
    pub fn new(digest: T) -> Self {
        Self { digest }
    }
}

impl<T> SignatureShare<T> {
    fn new(index: usize, signature_share: T) -> Self {
        Self {
            index,
            signature_share,
        }
    }
}

impl<T> Signature<T> {
    pub fn new(signature: T) -> Self {
        Self { signature }
    }
}
