# Domain
- model
  - key.rs
    - public_key
      - verify(signature, digest)
    - secret_key 
    - secret_key_share
    - sign(digest)
  - signature.rs
    - digest
    - signature_share
    - signature
- repository
  - public_key_repository
    - save
  - secret_key_share_repository
    - save
- service
  - -combine_signature_share





# Application Service

# Infrastructure