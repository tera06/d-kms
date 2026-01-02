pub struct Digest<T> {
    digest: T,
}
pub struct SignatureShare<T> {
    signature_share: T,
}

pub struct Signature<T> {
    signature: T,
}

impl<T> Digest<T> {
    pub fn new(digest: T) -> Self {
        Self { digest }
    }
}

impl<T> SignatureShare<T> {
    fn new(signature_share: T) -> Self {
        Self { signature_share }
    }
}

impl<T> Signature<T> {
    fn new(signature: T) -> Self {
        Self { signature }
    }
}
