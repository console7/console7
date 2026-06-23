package keybrokergcp

import "errors"

// Config configures the production CA (New). It names the Cloud KMS asymmetric-sign key VERSION the
// keybroker root signs with — provisioned by deploy/gcp/modules/keybroker-signing.
type Config struct {
	// KeyVersionName is the full Cloud KMS CryptoKeyVersion resource id, e.g.
	// "projects/<p>/locations/<r>/keyRings/<kr>/cryptoKeys/<prefix>-nhi-ca/cryptoKeyVersions/1".
	// AsymmetricSign and GetPublicKey both operate on a specific VERSION, so this is the version
	// resource (not the crypto-key resource). Required.
	KeyVersionName string
}

func (c Config) validate() error {
	if c.KeyVersionName == "" {
		return errors.New("keybrokergcp: Config.KeyVersionName is required (the Cloud KMS CryptoKeyVersion resource id)")
	}
	return nil
}
