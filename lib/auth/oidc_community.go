/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// communityOIDCService implements the OIDCService interface for the community
// edition, providing OIDC authentication support using coreos/go-oidc.
type communityOIDCService struct {
	a *Server
}

// NewCommunityOIDCService creates a new OIDC service implementation for the
// community edition.
func NewCommunityOIDCService(a *Server) OIDCService {
	return &communityOIDCService{a: a}
}

// CreateOIDCAuthRequest creates a new OIDC authentication request that can be
// used to redirect the user to the identity provider.
func (s *communityOIDCService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getOIDCConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Validate the client redirect URL for non-web sessions.
	if !req.CreateWebSession {
		ceremonyType := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremonyType = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremonyType, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	// Discover the OIDC provider.
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "failed to discover OIDC provider at %s", connector.GetIssuerURL())
	}

	// Get the appropriate redirect URL for this connector.
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build scopes. Default to "openid" if no scopes are specified.
	scopes := connector.GetScope()
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	// Create the OAuth2 config.
	oauthConfig := &oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	// Generate the state token.
	req.StateToken, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build the authorization URL.
	opts := []oauth2.AuthCodeOption{}

	if connector.GetPrompt() != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", connector.GetPrompt()))
	}

	if acr := connector.GetACR(); acr != "" {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", acr))
	}

	if req.LoginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}

	// Handle PKCE if enabled.
	if connector.IsPKCEEnabled() {
		codeVerifier, err := utils.CryptoRandomHex(32)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req.PkceVerifier = codeVerifier
		opts = append(opts,
			oauth2.S256ChallengeOption(codeVerifier),
		)
	}

	req.RedirectURL = oauthConfig.AuthCodeURL(req.StateToken, opts...)
	s.a.logger.DebugContext(ctx, "Creating OIDC auth request", "redirect_url", req.RedirectURL)

	if err := s.a.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// CreateOIDCAuthRequestForMFA creates an OIDC auth request specifically for
// MFA verification flows.
func (s *communityOIDCService) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getOIDCConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Apply MFA settings override if available.
	if err := connector.WithMFASettings(); err != nil {
		return nil, trace.Wrap(err)
	}

	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "failed to discover OIDC provider at %s", connector.GetIssuerURL())
	}

	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	scopes := connector.GetScope()
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	oauthConfig := &oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	req.StateToken, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.RedirectURL = oauthConfig.AuthCodeURL(req.StateToken)
	if err := s.a.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// ValidateOIDCAuthCallback validates an OIDC callback from the identity
// provider and returns the authenticated user's information.
func (s *communityOIDCService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	logger := s.a.logger.With(teleport.ComponentKey, "oidc")

	// Check for errors from the IdP.
	if errParam := q.Get("error"); errParam != "" {
		errDesc := q.Get("error_description")
		return nil, trace.AccessDenied("OIDC provider returned error: %s (%s)", errParam, errDesc)
	}

	code := q.Get("code")
	if code == "" {
		return nil, trace.BadParameter("missing code query parameter in OIDC callback")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		return nil, trace.BadParameter("missing state query parameter in OIDC callback")
	}

	// Retrieve the stored auth request.
	req, err := s.a.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "failed to get OIDC auth request")
	}

	// Get the connector.
	connector, err := s.getOIDCConnectorForRequest(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Discover the OIDC provider.
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "failed to discover OIDC provider at %s", connector.GetIssuerURL())
	}

	// Get the appropriate redirect URL.
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	scopes := connector.GetScope()
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	oauthConfig := &oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	// Exchange the authorization code for tokens.
	exchangeOpts := []oauth2.AuthCodeOption{}
	if req.PkceVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(req.PkceVerifier))
	}

	token, err := oauthConfig.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, trace.Wrap(err, "failed to exchange OIDC authorization code for token")
	}

	// Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, trace.AccessDenied("OIDC provider did not return an id_token")
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: connector.GetClientID(),
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, trace.Wrap(err, "failed to verify OIDC ID token")
	}

	logger.DebugContext(ctx, "Successfully verified OIDC ID token",
		"subject", idToken.Subject,
		"issuer", idToken.Issuer,
		"connector", req.ConnectorID,
	)

	// Extract claims from the ID token.
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, trace.Wrap(err, "failed to extract claims from ID token")
	}

	logger.DebugContext(ctx, "Extracted OIDC claims", "claims", claims)

	// Map claims to roles using the connector's claims_to_roles configuration.
	traits := oidcClaimsToTraits(claims)
	roles, kubeGroups, kubeUsers := oidcMapClaimsToRoles(connector, traits)
	if len(roles) == 0 {
		return nil, trace.AccessDenied(
			"unable to map OIDC claims to any roles for connector %q; check claims_to_roles configuration",
			req.ConnectorID,
		)
	}

	// Determine the username.
	username := s.getOIDCUsername(connector, claims, idToken)
	if username == "" {
		return nil, trace.AccessDenied("could not determine username from OIDC claims")
	}

	// Build complete trait set.
	allTraits := make(map[string][]string)
	for k, v := range traits {
		allTraits[k] = v
	}
	allTraits[constants.TraitLogins] = []string{username}
	allTraits[constants.TraitKubeGroups] = kubeGroups
	allTraits[constants.TraitKubeUsers] = kubeUsers

	// Evaluate login rules.
	evaluationInput := &loginrule.EvaluationInput{
		Traits: allTraits,
	}
	evaluationOutput, err := s.a.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	allTraits = evaluationOutput.Traits

	// Recalculate kube groups/users in case login rules changed them.
	kubeGroups = allTraits[constants.TraitKubeGroups]
	kubeUsers = allTraits[constants.TraitKubeUsers]

	// Calculate session TTL based on roles.
	fetchedRoles, err := services.FetchRoles(roles, s.a, allTraits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sessionTTL := fetchedRoles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	if req.CertTTL > 0 && req.CertTTL < sessionTTL {
		sessionTTL = req.CertTTL
	}

	// Create or update the user.
	user, err := s.createOIDCUser(ctx, &CreateUserParams{
		ConnectorName: req.ConnectorID,
		Username:      username,
		Roles:         roles,
		KubeGroups:    kubeGroups,
		KubeUsers:     kubeUsers,
		Traits:        allTraits,
		SessionTTL:    sessionTTL,
	}, req.SSOTestFlow)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.a.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := s.a.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// In test flow, skip signing and creating web sessions.
	if req.SSOTestFlow {
		return &authclient.OIDCAuthResponse{
			Req: authclient.OIDCAuthRequest{
				ConnectorID: req.ConnectorID,
			},
			Identity: types.ExternalIdentity{
				ConnectorID: req.ConnectorID,
				Username:    username,
			},
			Username: username,
		}, nil
	}

	return s.makeOIDCAuthResponse(ctx, req, userState, username, sessionTTL, logger)
}

// getOIDCConnector retrieves the OIDC connector for the given request,
// using the embedded connector spec for test/SSOTestFlow if available.
func (s *communityOIDCService) getOIDCConnector(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow && req.ConnectorSpec != nil {
		connector, err := types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	connector, err := s.a.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// getOIDCConnectorForRequest retrieves the OIDC connector for callback
// validation.
func (s *communityOIDCService) getOIDCConnectorForRequest(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow && req.ConnectorSpec != nil {
		connector, err := types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	connector, err := s.a.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// getOIDCUsername extracts the username from OIDC claims, respecting the
// connector's username_claim configuration.
func (s *communityOIDCService) getOIDCUsername(connector types.OIDCConnector, claims map[string]interface{}, idToken *oidc.IDToken) string {
	// If a username_claim is specified, use that.
	if usernameClaim := connector.GetUsernameClaim(); usernameClaim != "" {
		if val, ok := claims[usernameClaim]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}

	// Try common claims in order of preference.
	for _, claim := range []string{"email", "preferred_username", "name", "sub"} {
		if val, ok := claims[claim]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}

	// Fall back to the subject.
	return idToken.Subject
}

// createOIDCUser creates or updates a user based on OIDC authentication.
func (s *communityOIDCService) createOIDCUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	s.a.logger.DebugContext(ctx, "Generating dynamic OIDC identity",
		"connector_name", p.ConnectorName,
		"user_name", p.Username,
		"roles", p.Roles,
		"dry_run", dryRun,
	)

	expires := s.a.GetClock().Now().UTC().Add(p.SessionTTL)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: s.a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		return user, nil
	}

	existingUser, err := s.a.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user",
				existingUser.GetName())
		}

		user.SetRevision(existingUser.GetRevision())
		if _, err := s.a.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := s.a.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

// makeOIDCAuthResponse creates the OIDC auth response including web session
// and/or certificates as needed.
func (s *communityOIDCService) makeOIDCAuthResponse(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	userState services.UserState,
	username string,
	sessionTTL time.Duration,
	logger *slog.Logger,
) (*authclient.OIDCAuthResponse, error) {
	auth := authclient.OIDCAuthResponse{
		Req: authclient.OIDCAuthRequest{
			ConnectorID:       req.ConnectorID,
			CSRFToken:         req.CSRFToken,
			CreateWebSession:  req.CreateWebSession,
			ClientRedirectURL: req.ClientRedirectURL,
		},
		Identity: types.ExternalIdentity{
			ConnectorID: req.ConnectorID,
			Username:    username,
		},
		Username: userState.GetName(),
	}

	// If the request is coming from a browser, create a web session.
	if req.CreateWebSession {
		session, err := s.a.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            s.a.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create web session")
		}

		auth.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := s.a.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
			Scope:                   req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create session certificate")
		}

		clusterName, err := s.a.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster name")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := s.a.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster's host CA")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	if o, err := s.a.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = o
	} else {
		logger.WarnContext(ctx, "Failed to calculate client options for OIDC login", "username", userState.GetName(), "error", err)
	}

	return &auth, nil
}

// oidcClaimsToTraits converts OIDC claims to a trait map.
func oidcClaimsToTraits(claims map[string]interface{}) map[string][]string {
	traits := make(map[string][]string)

	for key, value := range claims {
		switch v := value.(type) {
		case string:
			traits[key] = []string{v}
		case []interface{}:
			var vals []string
			for _, item := range v {
				if strVal, ok := item.(string); ok {
					vals = append(vals, strVal)
				}
			}
			if len(vals) > 0 {
				traits[key] = vals
			}
		case bool:
			if v {
				traits[key] = []string{"true"}
			} else {
				traits[key] = []string{"false"}
			}
		case float64:
			traits[key] = []string{fmt.Sprintf("%g", v)}
		}
	}

	return traits
}

// oidcMapClaimsToRoles maps OIDC claims to Teleport roles using the
// connector's claims_to_roles configuration.
func oidcMapClaimsToRoles(connector types.OIDCConnector, traits map[string][]string) (roles, kubeGroups, kubeUsers []string) {
	roleSet := make(map[string]bool)

	for _, mapping := range connector.GetClaimsToRoles() {
		claimValues, ok := traits[mapping.Claim]
		if !ok {
			continue
		}

		for _, claimValue := range claimValues {
			if mapping.Value == "*" || mapping.Value == claimValue {
				for _, role := range mapping.Roles {
					if utils.ContainsExpansion(role) {
						expanded, err := utils.ReplaceRegexp(mapping.Value, role, claimValue)
						if err != nil {
							continue
						}
						roleSet[expanded] = true
					} else {
						roleSet[role] = true
					}
				}
			}
		}
	}

	for role := range roleSet {
		roles = append(roles, role)
	}

	return roles, kubeGroups, kubeUsers
}
