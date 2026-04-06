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
	"log/slog"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// communitySAMLService implements the SAMLService interface for the community
// edition, providing SAML 2.0 authentication support using the gosaml2 library.
type communitySAMLService struct {
	a *Server
}

// NewCommunitySAMLService creates a new SAML service implementation for the
// community edition.
func NewCommunitySAMLService(a *Server) SAMLService {
	return &communitySAMLService{a: a}
}

// CreateSAMLAuthRequest creates a new SAML authentication request that can be
// used to redirect the user to the identity provider.
func (s *communitySAMLService) CreateSAMLAuthRequest(ctx context.Context, req types.SAMLAuthRequest) (*types.SAMLAuthRequest, error) {
	connector, err := s.a.GetSAMLConnector(ctx, req.ConnectorID, true)
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

	// Use connector spec from test flow if provided.
	if req.SSOTestFlow && req.ConnectorSpec != nil {
		testConnector, err := types.NewSAMLConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		connector = testConnector
	}

	// Create the SAML service provider from the connector configuration.
	sp, err := services.GetSAMLServiceProvider(connector, s.a.GetClock())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Generate a unique request ID.
	req.ID, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build the SAML auth request based on the preferred binding.
	preferredBinding := connector.GetPreferredRequestBinding()
	if preferredBinding == types.SAMLRequestHTTPPostBinding {
		// HTTP-POST binding: generate a POST form body.
		postBody, err := sp.BuildAuthBodyPost(req.ID)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req.PostForm = postBody
	} else {
		// HTTP-Redirect binding (default): generate a redirect URL.
		redirectURL, err := sp.BuildAuthURL(req.ID)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req.RedirectURL = redirectURL
	}

	if err := s.a.Services.CreateSAMLAuthRequest(ctx, req, defaults.SAMLAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// CreateSAMLAuthRequestForMFA creates a SAML auth request specifically for
// MFA verification flows.
func (s *communitySAMLService) CreateSAMLAuthRequestForMFA(ctx context.Context, req types.SAMLAuthRequest) (*types.SAMLAuthRequest, error) {
	connector, err := s.a.GetSAMLConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Apply MFA settings override if available.
	if err := connector.WithMFASettings(); err != nil {
		return nil, trace.Wrap(err)
	}

	sp, err := services.GetSAMLServiceProvider(connector, s.a.GetClock())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.ID, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	redirectURL, err := sp.BuildAuthURL(req.ID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.RedirectURL = redirectURL

	if err := s.a.Services.CreateSAMLAuthRequest(ctx, req, defaults.SAMLAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// ValidateSAMLResponse validates a SAML response from the identity provider
// and returns the authenticated user's information.
func (s *communitySAMLService) ValidateSAMLResponse(ctx context.Context, samlResponse, connectorID, clientIP string) (*authclient.SAMLAuthResponse, error) {
	logger := s.a.logger.With(teleport.ComponentKey, "saml")

	connector, err := s.a.GetSAMLConnector(ctx, connectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sp, err := services.GetSAMLServiceProvider(connector, s.a.GetClock())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Validate the SAML response and extract assertion info.
	assertionInfo, err := sp.RetrieveAssertionInfo(samlResponse)
	if err != nil {
		return nil, trace.AccessDenied("failed to validate SAML response: %v", err)
	}

	if assertionInfo.WarningInfo != nil {
		if assertionInfo.WarningInfo.NotInAudience {
			return nil, trace.AccessDenied("SAML response audience mismatch")
		}
		if assertionInfo.WarningInfo.InvalidTime {
			return nil, trace.AccessDenied("SAML response has expired or is not yet valid")
		}
	}

	logger.DebugContext(ctx, "Successfully validated SAML response",
		"name_id", assertionInfo.NameID,
		"connector", connectorID,
	)

	// Convert SAML assertions to traits.
	traits := services.SAMLAssertionsToTraits(*assertionInfo)
	logger.DebugContext(ctx, "Extracted SAML traits", "traits", traits)

	// Map attributes to roles using the connector's attribute mappings.
	roles, kubeGroups, kubeUsers := samlMapAttributesToRoles(connector, traits)
	if len(roles) == 0 {
		return nil, trace.AccessDenied(
			"unable to map SAML attributes to any roles for connector %q; check attributes_to_roles configuration",
			connectorID,
		)
	}

	// Determine the username from the SAML NameID.
	username := assertionInfo.NameID
	if username == "" {
		return nil, trace.AccessDenied("SAML response did not contain a NameID")
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

	// Create or update the user.
	user, err := s.createSAMLUser(ctx, &CreateUserParams{
		ConnectorName: connectorID,
		Username:      username,
		Roles:         roles,
		KubeGroups:    kubeGroups,
		KubeUsers:     kubeUsers,
		Traits:        allTraits,
		SessionTTL:    sessionTTL,
	}, false)
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

	return s.makeSAMLAuthResponse(ctx, userState, connectorID, username, sessionTTL, clientIP, logger)
}

// createSAMLUser creates or updates a user based on SAML authentication.
func (s *communitySAMLService) createSAMLUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	s.a.logger.DebugContext(ctx, "Generating dynamic SAML identity",
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
			SAMLIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: s.a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.SAML,
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
			return nil, trace.AlreadyExists("local user %q already exists and is not a SAML user",
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

// makeSAMLAuthResponse creates the SAML auth response including web session
// and/or certificates as needed.
func (s *communitySAMLService) makeSAMLAuthResponse(
	ctx context.Context,
	userState services.UserState,
	connectorID, username string,
	sessionTTL time.Duration,
	clientIP string,
	logger *slog.Logger,
) (*authclient.SAMLAuthResponse, error) {
	auth := authclient.SAMLAuthResponse{
		Req: authclient.SAMLAuthRequest{
			ID:        connectorID,
			CSRFToken: "",
		},
		Identity: types.ExternalIdentity{
			ConnectorID: connectorID,
			Username:    username,
		},
		Username: userState.GetName(),
	}

	if o, err := s.a.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = o
	} else {
		logger.WarnContext(ctx, "Failed to calculate client options for SAML login", "username", userState.GetName(), "error", err)
	}

	return &auth, nil
}

// samlMapAttributesToRoles maps SAML assertion attributes to Teleport roles
// using the connector's attributes_to_roles configuration.
func samlMapAttributesToRoles(connector types.SAMLConnector, traits map[string][]string) (roles, kubeGroups, kubeUsers []string) {
	roleSet := make(map[string]bool)

	for _, mapping := range connector.GetAttributesToRoles() {
		attrValues, ok := traits[mapping.Name]
		if !ok {
			continue
		}

		for _, attrValue := range attrValues {
			if mapping.Value == "*" || mapping.Value == attrValue {
				for _, role := range mapping.Roles {
					if utils.ContainsExpansion(role) {
						// Handle role template expansion.
						expanded, err := utils.ReplaceRegexp(mapping.Value, role, attrValue)
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
