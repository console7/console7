// Package keybrokergcp is the Console7 reference KMS-backed CA root for the keybroker's signing
// identity (ARCHITECTURE.md §6.4). It implements keybroker/signing.CA — the trust anchor every
// per-session NHI certificate and evidence-sink certificate chains to — backed by a Cloud KMS
// asymmetric-sign key (EC_SIGN_P256_SHA256) whose PRIVATE key never leaves KMS.
//
// This is the production counterpart to signing.DevCA (an in-process ed25519 dev root): where DevCA
// holds the root key in memory, this provider's Sign delegates to Cloud KMS AsymmetricSign, so the
// control plane (and this process) hold no root signing key at rest — the keybroker custodies only a
// KMS handle + IAM (roles/cloudkms.signerVerifier on exactly one key). Root() returns the EC-P256
// PUBLIC key (fetched from KMS GetPublicKey at construction), the anchor a verifier pins;
// signing.Verify / VerifySinkSignature dispatch to their EC-P256 arm for it.
//
// The KMS key MUST live in a keyring DISTINCT from the secrets KEK (providers/secrets-gcp): the
// keybroker is a separately-hardened artifact with its own signing identity and MUST NOT be fused
// with the secrets substrate (ARCHITECTURE.md §6.4). That separation is provisioned + enforced by
// deploy/gcp/modules/keybroker-signing (the forthcoming A3 deploy rung), not by this provider — this
// provider only consumes the key version it is configured with.
//
// SHAPE (mirrors providers/secrets-gcp): the cloud.google.com/go/kms client is confined behind the
// kmsAsymmetricSigner port (kms_gcp.go); New wires the real adapter, NewWithPorts wires the
// in-process EC fake (fakes.go) so the CA's Sign -> Root round-trip is exercised in CI with no GCP
// project. CRC32C integrity is checked on every KMS call in both directions (the secrets-gcp lesson).
package keybrokergcp
