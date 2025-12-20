pub(super) struct Digest<T> {
    digest: T,
}
pub(super) struct SignatureShare<T> {
    signature_share: T,
}

pub(super) struct Signature<T> {
    signature: T,
}

impl<T> Digest<T> {
    fn new(digest: T) -> Self {
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
