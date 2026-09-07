// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"fmt"
	"log/slog"
)

// KeyDecryptor unwraps a KMS-wrapped data encryption key (DEK). It is the
// cloud-provider seam: a GCP implementation (kms/gcp) presents a Confidential
// Space attestation token to Workload Identity Federation and calls Cloud KMS
// decrypt; other providers (AWS KMS, Azure Key Vault) can implement the same
// interface without the rest of the broker changing.
//
// Implementations MUST fail closed: any error in attestation, identity exchange,
// or the decrypt call returns a non-nil error and no key material (invariant
// I-B8). The returned DEK is caller-owned and MUST be zeroized after use.
type KeyDecryptor interface {
	// DecryptDEK returns the plaintext DEK for a wrapped DEK. The wrapped bytes
	// come from Envelope.WrappedDEK.
	DecryptDEK(ctx context.Context, wrappedDEK []byte) (dek []byte, err error)

	// Name identifies the provider for logs and audit. It MUST NOT contain any
	// secret, key, or token material — it is a static label such as "gcp-kms".
	Name() string
}

// EnvelopeUnwrapper implements Unwrapper for AlgKMSGCM envelopes by composing a
// provider KeyDecryptor (unwrap the DEK) with AES-256-GCM (decrypt the secret
// under the DEK). This split keeps the AES half provider-agnostic and confines
// all cloud-specific code to the KeyDecryptor.
//
// It is the production path behind the Unwrapper seam; DevKEK is its local-dev
// counterpart (invariant I-B6 lives here: the DEK is fetched per unwrap under a
// live attestation, never cached).
type EnvelopeUnwrapper struct {
	dec KeyDecryptor
	log *slog.Logger
}

// NewEnvelopeUnwrapper builds an EnvelopeUnwrapper over a provider decryptor.
// A nil logger is replaced with slog.Default().
func NewEnvelopeUnwrapper(dec KeyDecryptor, log *slog.Logger) (*EnvelopeUnwrapper, error) {
	if dec == nil {
		return nil, fmt.Errorf("kms: KeyDecryptor is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &EnvelopeUnwrapper{dec: dec, log: log}, nil
}

// Unwrap decrypts an AlgKMSGCM envelope. It never logs any key or secret
// material — only the provider name and the wrapped-DEK/ciphertext lengths.
func (u *EnvelopeUnwrapper) Unwrap(ctx context.Context, env Envelope, aad []byte) ([]byte, error) {
	if env.Alg != AlgKMSGCM {
		return nil, fmt.Errorf("unsupported envelope alg %q (want %q)", env.Alg, AlgKMSGCM)
	}
	if err := requireAADVersion(env); err != nil {
		return nil, err
	}
	if len(env.WrappedDEK) == 0 {
		return nil, fmt.Errorf("envelope has no wrapped DEK")
	}

	u.log.Debug("unwrapping secret",
		slog.String("provider", u.dec.Name()),
		slog.Int("wrapped_dek_bytes", len(env.WrappedDEK)),
		slog.Int("ciphertext_bytes", len(env.Ciphertext)))

	dek, err := u.dec.DecryptDEK(ctx, env.WrappedDEK)
	if err != nil {
		// Fail closed; the caller maps this to 503 with no secret material.
		u.log.Warn("DEK unwrap failed", slog.String("provider", u.dec.Name()), slog.String("err", err.Error()))
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}
	defer Zero(dek)

	secret, err := openGCM(dek, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		u.log.Warn("secret decrypt failed", slog.String("provider", u.dec.Name()))
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	return secret, nil
}
