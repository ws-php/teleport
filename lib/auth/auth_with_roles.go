/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"io"
	"net/url"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
	"github.com/tstranex/u2f"
)

type AuthWithRoles struct {
	authServer *AuthServer
	checker    services.AccessChecker
	user       string
	sessions   session.Service
	alog       events.IAuditLog
}

func (a *AuthWithRoles) action(namespace string, resourceKind, action string) error {
	return a.checker.CheckResourceAction(namespace, resourceKind, action)
}

// currentUserAction is a special checker that allows certain actions for users
// even if they are not admins, e.g. update their own passwords,
// or generate certificates, otherwise it will require admin privileges
func (a *AuthWithRoles) currentUserAction(username string) error {
	if username == a.user {
		return nil
	}
	return a.checker.CheckResourceAction(
		defaults.Namespace, services.KindUser, services.ActionWrite)
}

func (a *AuthWithRoles) GetSessions(namespace string) ([]session.Session, error) {
	if err := a.action(namespace, services.KindSession, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.sessions.GetSessions(namespace)
}

func (a *AuthWithRoles) GetSession(namespace string, id session.ID) (*session.Session, error) {
	if err := a.action(namespace, services.KindSession, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.sessions.GetSession(namespace, id)
}

func (a *AuthWithRoles) CreateSession(s session.Session) error {
	if err := a.action(s.Namespace, services.KindSession, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.CreateSession(s)
}

func (a *AuthWithRoles) UpdateSession(req session.UpdateRequest) error {
	if err := a.action(req.Namespace, services.KindSession, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.UpdateSession(req)
}

func (a *AuthWithRoles) UpsertCertAuthority(ca services.CertAuthority, ttl time.Duration) error {
	if err := a.action(defaults.Namespace, services.KindCertAuthority, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertCertAuthority(ca, ttl)
}

func (a *AuthWithRoles) GetCertAuthorities(caType services.CertAuthType, loadKeys bool) ([]services.CertAuthority, error) {
	if loadKeys {
		// loading private key implies admin access, what in our case == Write access to them
		if err := a.action(defaults.Namespace, services.KindCertAuthority, services.ActionWrite); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := a.action(defaults.Namespace, services.KindCertAuthority, services.ActionRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetCertAuthorities(caType, loadKeys)
}

func (a *AuthWithRoles) GetCertAuthority(id services.CertAuthID, loadKeys bool) (services.CertAuthority, error) {
	if loadKeys {
		// loading private key implies admin access, what in our case == Write access to them
		if err := a.action(defaults.Namespace, services.KindCertAuthority, services.ActionWrite); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := a.action(defaults.Namespace, services.KindCertAuthority, services.ActionRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetCertAuthority(id, loadKeys)
}

func (a *AuthWithRoles) GetDomainName() (string, error) {
	// anyone can read it, no harm in that
	return a.authServer.GetDomainName()
}

func (a *AuthWithRoles) DeleteCertAuthority(id services.CertAuthID) error {
	if err := a.action(defaults.Namespace, services.KindCertAuthority, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteCertAuthority(id)
}

func (a *AuthWithRoles) GenerateToken(roles teleport.Roles, ttl time.Duration) (string, error) {
	if err := a.action(defaults.Namespace, services.KindToken, services.ActionWrite); err != nil {
		return "", trace.Wrap(err)
	}
	return a.authServer.GenerateToken(roles, ttl)
}

func (a *AuthWithRoles) RegisterUsingToken(token, hostID string, nodeName string, role teleport.Role) (*PackedKeys, error) {
	// tokens have authz mechanism  on their own, no need to check
	return a.authServer.RegisterUsingToken(token, hostID, nodeName, role)
}

func (a *AuthWithRoles) RegisterNewAuthServer(token string) error {
	// tokens have authz mechanism  on their own, no need to check
	return a.authServer.RegisterNewAuthServer(token)
}

func (a *AuthWithRoles) RegisterNewTrustedCluster(token string) error {
	return a.authServer.RegisterNewTrustedCluster(token)
}

func (a *AuthWithRoles) UpsertNode(s services.Server, ttl time.Duration) error {
	if err := a.action(s.GetNamespace(), services.KindNode, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertNode(s, ttl)
}

func (a *AuthWithRoles) GetNodes(namespace string) ([]services.Server, error) {
	if err := a.action(namespace, services.KindNode, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNodes(namespace)
}

func (a *AuthWithRoles) UpsertAuthServer(s services.Server, ttl time.Duration) error {
	if err := a.action(defaults.Namespace, services.KindAuthServer, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertAuthServer(s, ttl)
}

func (a *AuthWithRoles) GetAuthServers() ([]services.Server, error) {
	if err := a.action(defaults.Namespace, services.KindAuthServer, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetAuthServers()
}

func (a *AuthWithRoles) UpsertProxy(s services.Server, ttl time.Duration) error {
	if err := a.action(defaults.Namespace, services.KindProxy, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertProxy(s, ttl)
}

func (a *AuthWithRoles) GetProxies() ([]services.Server, error) {
	if err := a.action(defaults.Namespace, services.KindProxy, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetProxies()
}

func (a *AuthWithRoles) UpsertReverseTunnel(r services.ReverseTunnel, ttl time.Duration) error {
	if err := a.action(defaults.Namespace, services.KindReverseTunnel, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertReverseTunnel(r, ttl)
}

func (a *AuthWithRoles) GetReverseTunnels() ([]services.ReverseTunnel, error) {
	if err := a.action(defaults.Namespace, services.KindReverseTunnel, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetReverseTunnels()
}

func (a *AuthWithRoles) DeleteReverseTunnel(domainName string) error {
	if err := a.action(defaults.Namespace, services.KindReverseTunnel, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteReverseTunnel(domainName)
}

func (a *AuthWithRoles) DeleteToken(token string) error {
	if err := a.action(defaults.Namespace, services.KindToken, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteToken(token)
}

func (a *AuthWithRoles) GetTokens() ([]services.ProvisionToken, error) {
	if err := a.action(defaults.Namespace, services.KindToken, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetTokens()
}

func (a *AuthWithRoles) GetToken(token string) (*services.ProvisionToken, error) {
	if err := a.action(defaults.Namespace, services.KindToken, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetToken(token)
}

func (a *AuthWithRoles) UpsertToken(token string, roles teleport.Roles, ttl time.Duration) error {
	if err := a.action(defaults.Namespace, services.KindToken, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertToken(token, roles, ttl)
}

func (a *AuthWithRoles) UpsertPassword(user string, password []byte) error {
	if err := a.currentUserAction(user); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertPassword(user, password)
}

func (a *AuthWithRoles) CheckPassword(user string, password []byte, otpToken string) error {
	if err := a.currentUserAction(user); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CheckPassword(user, password, otpToken)
}

func (a *AuthWithRoles) UpsertTOTP(user string, otpSecret string) error {
	if err := a.currentUserAction(user); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertTOTP(user, otpSecret)
}

func (a *AuthWithRoles) GetOTPData(user string) (string, []byte, error) {
	if err := a.currentUserAction(user); err != nil {
		return "", nil, trace.Wrap(err)
	}
	return a.authServer.GetOTPData(user)
}

func (a *AuthWithRoles) SignIn(user string, password []byte) (services.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.SignIn(user, password)
}

func (a *AuthWithRoles) PreAuthenticatedSignIn(user string) (services.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.PreAuthenticatedSignIn(user)
}

func (a *AuthWithRoles) GetU2FSignRequest(user string, password []byte) (*u2f.SignRequest, error) {
	// we are already checking password here, no need to extra permission check
	// anyone who has user's password can generate sign request
	return a.authServer.U2FSignRequest(user, password)
}

func (a *AuthWithRoles) CreateWebSession(user string) (services.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateWebSession(user)
}

func (a *AuthWithRoles) ExtendWebSession(user, prevSessionID string) (services.WebSession, error) {
	if err := a.action(defaults.Namespace, services.KindWebSession, services.ActionWrite); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.ExtendWebSession(user, prevSessionID)
}

func (a *AuthWithRoles) GetWebSessionInfo(user string, sid string) (services.WebSession, error) {
	if err := a.action(defaults.Namespace, services.KindWebSession, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetWebSessionInfo(user, sid)
}

func (a *AuthWithRoles) DeleteWebSession(user string, sid string) error {
	if err := a.action(defaults.Namespace, services.KindWebSession, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteWebSession(user, sid)
}

func (a *AuthWithRoles) GetUsers() ([]services.User, error) {
	if err := a.action(defaults.Namespace, services.KindUser, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetUsers()
}

func (a *AuthWithRoles) GetUser(name string) (services.User, error) {
	if err := a.action(defaults.Namespace, services.KindUser, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Identity.GetUser(name)
}

func (a *AuthWithRoles) DeleteUser(user string) error {
	if err := a.action(defaults.Namespace, services.KindUser, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteUser(user)
}

func (a *AuthWithRoles) GenerateKeyPair(pass string) ([]byte, []byte, error) {
	if err := a.action(defaults.Namespace, services.KindKeyPair, services.ActionWrite); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return a.authServer.GenerateKeyPair(pass)
}

func (a *AuthWithRoles) GenerateHostCert(
	key []byte, hostID, nodeName, clusterName string, roles teleport.Roles,
	ttl time.Duration) ([]byte, error) {

	if err := a.action(defaults.Namespace, services.KindHostCert, services.ActionWrite); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GenerateHostCert(key, hostID, nodeName, clusterName, roles, ttl)
}

func (a *AuthWithRoles) GenerateUserCert(key []byte, username string, ttl time.Duration) ([]byte, error) {
	if err := a.currentUserAction(username); err != nil {
		return nil, trace.AccessDenied("%v cannot request a certificate for %v", a.user, username)
	}
	// notice that user requesting the certificate and the user currently
	// authenticated may differ (e.g. admin generates certificate for the user scenario)
	// so we fetch user's permissions
	checker := a.checker
	if a.user != username {
		user, err := a.GetUser(username)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		checker, err = services.FetchRoles(user.GetRoles(), a.authServer)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	// check signing TTL and return a list of allowed logins
	allowedLogins, err := checker.CheckLogins(ttl)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GenerateUserCert(key, username, allowedLogins, ttl)
}

func (a *AuthWithRoles) CreateSignupToken(user services.UserV1) (token string, e error) {
	if err := a.action(defaults.Namespace, services.KindUser, services.ActionWrite); err != nil {
		return "", trace.Wrap(err)
	}
	return a.authServer.CreateSignupToken(user)
}

func (a *AuthWithRoles) GetSignupTokenData(token string) (user string, otpQRCode []byte, err error) {
	// signup token are their own authz resource
	return a.authServer.GetSignupTokenData(token)
}

func (a *AuthWithRoles) GetSignupToken(token string) (*services.SignupToken, error) {
	// signup token are their own authz resource
	return a.authServer.GetSignupToken(token)
}

func (a *AuthWithRoles) GetSignupU2FRegisterRequest(token string) (u2fRegisterRequest *u2f.RegisterRequest, e error) {
	// signup token are their own authz resource
	return a.authServer.CreateSignupU2FRegisterRequest(token)
}

func (a *AuthWithRoles) CreateUserWithToken(token, password, hotpToken string) (services.WebSession, error) {
	// tokens are their own authz mechanism, no need to double check
	return a.authServer.CreateUserWithToken(token, password, hotpToken)
}

func (a *AuthWithRoles) CreateUserWithU2FToken(token string, password string, u2fRegisterResponse u2f.RegisterResponse) (services.WebSession, error) {
	// signup tokens are their own authz resource
	return a.authServer.CreateUserWithU2FToken(token, password, u2fRegisterResponse)
}

func (a *AuthWithRoles) UpsertUser(u services.User) error {
	if err := a.action(defaults.Namespace, services.KindUser, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	createdBy := u.GetCreatedBy()
	if createdBy.IsEmpty() {
		u.SetCreatedBy(services.CreatedBy{
			User: services.UserRef{Name: a.user},
		})
	}
	return a.authServer.UpsertUser(u)
}

func (a *AuthWithRoles) UpsertOIDCConnector(connector services.OIDCConnector, ttl time.Duration) error {
	if err := a.action(defaults.Namespace, services.KindOIDC, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertOIDCConnector(connector, ttl)
}

func (a *AuthWithRoles) GetOIDCConnector(id string, withSecrets bool) (services.OIDCConnector, error) {
	if withSecrets {
		if err := a.action(defaults.Namespace, services.KindOIDC, services.ActionWrite); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := a.action(defaults.Namespace, services.KindOIDC, services.ActionRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Identity.GetOIDCConnector(id, withSecrets)
}

func (a *AuthWithRoles) GetOIDCConnectors(withSecrets bool) ([]services.OIDCConnector, error) {
	if withSecrets {
		if err := a.action(defaults.Namespace, services.KindOIDC, services.ActionWrite); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := a.action(defaults.Namespace, services.KindOIDC, services.ActionRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Identity.GetOIDCConnectors(withSecrets)
}

func (a *AuthWithRoles) CreateOIDCAuthRequest(req services.OIDCAuthRequest) (*services.OIDCAuthRequest, error) {
	if err := a.action(defaults.Namespace, services.KindOIDCRequest, services.ActionWrite); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateOIDCAuthRequest(req)
}

func (a *AuthWithRoles) ValidateOIDCAuthCallback(q url.Values) (*OIDCAuthResponse, error) {
	// auth callback is it's own authz, no need to check extra permissions
	return a.authServer.ValidateOIDCAuthCallback(q)
}

func (a *AuthWithRoles) DeleteOIDCConnector(connectorID string) error {
	if err := a.action(defaults.Namespace, services.KindOIDC, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteOIDCConnector(connectorID)
}

func (a *AuthWithRoles) EmitAuditEvent(eventType string, fields events.EventFields) error {
	if err := a.action(defaults.Namespace, services.KindEvent, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.alog.EmitAuditEvent(eventType, fields)
}

func (a *AuthWithRoles) PostSessionChunk(namespace string, sid session.ID, reader io.Reader) error {
	if err := a.action(namespace, services.KindSession, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.alog.PostSessionChunk(namespace, sid, reader)
}

func (a *AuthWithRoles) GetSessionChunk(namespace string, sid session.ID, offsetBytes, maxBytes int) ([]byte, error) {
	if err := a.action(namespace, services.KindSession, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.alog.GetSessionChunk(namespace, sid, offsetBytes, maxBytes)
}

func (a *AuthWithRoles) GetSessionEvents(namespace string, sid session.ID, afterN int) ([]events.EventFields, error) {
	if err := a.action(namespace, services.KindSession, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.alog.GetSessionEvents(namespace, sid, afterN)
}

func (a *AuthWithRoles) SearchEvents(from, to time.Time, query string) ([]events.EventFields, error) {
	if err := a.action(defaults.Namespace, services.KindEvent, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.alog.SearchEvents(from, to, query)
}

// GetNamespaces returns a list of namespaces
func (a *AuthWithRoles) GetNamespaces() ([]services.Namespace, error) {
	if err := a.action(defaults.Namespace, services.KindNamespace, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNamespaces()
}

// GetNamespace returns namespace by name
func (a *AuthWithRoles) GetNamespace(name string) (*services.Namespace, error) {
	if err := a.action(defaults.Namespace, services.KindNamespace, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNamespace(name)
}

// UpsertNamespace upserts namespace
func (a *AuthWithRoles) UpsertNamespace(ns services.Namespace) error {
	if err := a.action(defaults.Namespace, services.KindNamespace, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertNamespace(ns)
}

// DeleteNamespace deletes namespace by name
func (a *AuthWithRoles) DeleteNamespace(name string) error {
	if err := a.action(defaults.Namespace, services.KindNamespace, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteNamespace(name)
}

// GetRoles returns a list of roles
func (a *AuthWithRoles) GetRoles() ([]services.Role, error) {
	if err := a.action(defaults.Namespace, services.KindRole, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetRoles()
}

// UpsertRole creates or updates role
func (a *AuthWithRoles) UpsertRole(role services.Role) error {
	if err := a.action(defaults.Namespace, services.KindRole, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertRole(role)
}

// GetRole returns role by name
func (a *AuthWithRoles) GetRole(name string) (services.Role, error) {
	if err := a.action(defaults.Namespace, services.KindRole, services.ActionRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetRole(name)
}

// DeleteRole deletes role by name
func (a *AuthWithRoles) DeleteRole(name string) error {
	if err := a.action(defaults.Namespace, services.KindRole, services.ActionWrite); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteRole(name)
}

func (a *AuthWithRoles) GetClusterAuthPreference() (services.AuthPreference, error) {
	err := a.action(defaults.Namespace, services.KindClusterAuthPreference, services.ActionRead)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.GetClusterAuthPreference()
}

func (a *AuthWithRoles) SetClusterAuthPreference(cap services.AuthPreference) error {
	err := a.action(defaults.Namespace, services.KindClusterAuthPreference, services.ActionWrite)
	if err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.SetClusterAuthPreference(cap)
}

func (a *AuthWithRoles) GetUniversalSecondFactor() (services.UniversalSecondFactor, error) {
	err := a.action(defaults.Namespace, services.KindUniversalSecondFactor, services.ActionRead)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.GetUniversalSecondFactor()
}

func (a *AuthWithRoles) SetUniversalSecondFactor(u2f services.UniversalSecondFactor) error {
	err := a.action(defaults.Namespace, services.KindUniversalSecondFactor, services.ActionWrite)
	if err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.SetUniversalSecondFactor(u2f)
}

func (a *AuthWithRoles) UpsertTrustedCluster(tc services.TrustedCluster) error {
	err := a.action(defaults.Namespace, services.KindTrustedCluster, services.ActionWrite)
	if err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.UpsertTrustedCluster(tc)
}

func (a *AuthWithRoles) GetTrustedCluster(name string) (services.TrustedCluster, error) {
	err := a.action(defaults.Namespace, services.KindTrustedCluster, services.ActionRead)
	if err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.GetTrustedCluster(name)
}

func (a *AuthWithRoles) GetTrustedClusters() ([]services.TrustedCluster, error) {
	err := a.action(defaults.Namespace, services.KindTrustedCluster, services.ActionRead)
	if err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.GetTrustedClusters()
}

func (a *AuthWithRoles) DeleteTrustedCluster(name string) error {
	err := a.action(defaults.Namespace, services.KindTrustedCluster, services.ActionWrite)
	if err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.DeleteTrustedCluster(name)
}

// NewAuthWithRoles creates new auth server with access control
func NewAuthWithRoles(authServer *AuthServer,
	checker services.AccessChecker,
	user string,
	sessions session.Service,
	alog events.IAuditLog) *AuthWithRoles {
	return &AuthWithRoles{
		authServer: authServer,
		checker:    checker,
		sessions:   sessions,
		user:       user,
		alog:       alog,
	}
}
