/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package awsra

import (
	"context"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/cryptosuites"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/integrations/awsra/createsession"
	"github.com/gravitational/teleport/lib/tlsca"
)

func TestGenerateCredentials(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	mockCertGen := &mockCertificateGenerator{
		t: t,
	}

	mockCreateSessionAPI := func(ctx context.Context, req createsession.CreateSessionRequest) (*createsession.CreateSessionResponse, error) {
		return &createsession.CreateSessionResponse{
			Version:         1,
			AccessKeyID:     "mock-access-key-id",
			SecretAccessKey: "mock-secret-access-key",
			SessionToken:    "mock-session-token",
			Expiration:      clock.Now().Add(1 * time.Hour).Format(time.RFC3339),
		}, nil
	}

	req := GenerateCredentialsRequest{
		Clock:                 clock,
		TrustAnchorARN:        "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/12345678-1234-1234-1234-123456789012",
		ProfileARN:            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/12345678-1234-1234-1234-123456789012",
		RoleARN:               "arn:aws:iam::123456789012:role/teleport-role",
		SubjectCommonName:     "test-common-name",
		DurationSeconds:       nil,
		AcceptRoleSessionName: true,
		CertificateGenerator:  mockCertGen,
		createSession:         mockCreateSessionAPI,
	}

	credentials, err := GenerateCredentials(ctx, req)
	require.NoError(t, err)

	// Validate the returned credentials
	require.Equal(t, 1, credentials.Version)
	require.Equal(t, "mock-access-key-id", credentials.AccessKeyID)
	require.Equal(t, "mock-secret-access-key", credentials.SecretAccessKey)
	require.Equal(t, "mock-session-token", credentials.SessionToken)
	require.NotEmpty(t, credentials.Expiration)
}

// mockCertificateGenerator is a mock implementation of the CertificateGenerator interface.
type mockCertificateGenerator struct {
	t *testing.T
}

func (m *mockCertificateGenerator) GenerateCertificate(req tlsca.CertificateRequest) ([]byte, error) {
	caPriv, err := cryptosuites.GenerateKeyWithAlgorithm(cryptosuites.ECDSAP256)
	require.NoError(m.t, err)

	caCert, err := tlsca.GenerateSelfSignedCAWithSigner(
		caPriv,
		pkix.Name{
			CommonName: req.Subject.CommonName,
		}, nil, defaults.CATTL)
	require.NoError(m.t, err)

	ca, err := tlsca.FromCertAndSigner(caCert, caPriv)
	require.NoError(m.t, err)

	return ca.GenerateCertificate(req)
}
