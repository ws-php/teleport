package auth

import (
	"encoding/json"
	"fmt"

	"github.com/gravitational/trace"
)

type ValidateTrustedClusterResponse struct {
	CAs []string `json:"certificate_authorities"`
}

type ValidateTrustedClusterRequest struct {
	Token string   `json:"token"`
	CAs   []string `json:"certificate_authorities"`
}

func (s *AuthServer) RequestValidateTrustedCluster(proxyAddress string, vreq ValidateTrustedClusterRequest) (*WaldoResponse, err) {
	requestBody, err := json.Marshal(vreq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	responseBody, err := requestToProxy(proxyAddress, requestBody)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var vres ValidateTrustedClusterResponse
	err = json.Unmarshal(responseBody, &vres)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &vres, nil
}

func (s *AuthServer) ValidateTrustedCluster(token string) (*WaldoResponse, error) {
	roles, err := s.ValidateToken(token)
	if err != nil {
		return nil, trace.AccessDenied("invalid token")
	}

	if !roles.Include(teleport.RoleTrustedCluster) {
		return trace.AccessDenied("role does not match")
	}

	if !s.checkTokenTTL(token) {
		return nil, trace.AccessDenied("expired token")
	}

	cas, err := s.exportCertificateAuthorities()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &ValidateTrustedClusterResponse{
		CAs: cas,
	}, nil
}

func (a *AuthServer) exportCertificateAuthorities() ([]string, error) {
	typesToExport = []services.CertAuthType{services.HostCA, services.UserCA}

	var authorities []services.CertAuthority
	for _, at := range typesToExport {
		cas, err := a.GetCertAuthorities(at, false)
		if err != nil {
			return trace.Wrap(err)
		}
		for _, ca := range cas {
			if ca.GetClusterName() == a.DomainName {
				authorities = append(authorities, ca)
			}
		}
	}

	certificateAuthorities := []string{}

	for _, ca := range authorities {
		for _, keyBytes := range ca.GetCheckingKeys() {
			fingerprint, err := sshutils.AuthorizedKeyFingerprint(keyBytes)
			if err != nil {
				return trace.Wrap(err)
			}
			if a.exportAuthorityFingerprint != "" && fingerprint != a.exportAuthorityFingerprint {
				continue
			}
			options := url.Values{
				"type": []string{string(ca.GetType())},
			}
			roles, err := services.FetchRoles(ca.GetRoles(), client)
			if err != nil {
				return trace.Wrap(err)
			}
			allowedLogins, _ := roles.CheckLogins(defaults.MinCertDuration + time.Second)
			if len(allowedLogins) > 0 {
				options["logins"] = allowedLogins
			}

			// Every auth public key is exported as a single line adhering to man sshd (8)
			// authorized_hosts format, a space-separated list of: makrer, hosts, key, and comment
			// example:
			// 		@cert-authority *.cluster-a ssh-rsa AAA... type=user
			// We use URL encoding to pass the CA type and allowed logins into the comment field
			castr = fmt.Sprintf("@cert-authority *.%s %s %s\n",
				ca.GetClusterName(), strings.TrimSpace(string(keyBytes)), options.Encode())
			certificateAuthorities = append(certificateAuthorities, castr)
		}
	}
	return certificateAuthorities, nil
}

func requestToProxy(host string, body []byte) ([]byte, error) {
	uri := fmt.Sprintf("https://%v/webapi/trustedclusters/register", host, path)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return body, nil
}

//var req upsertServerRawReq
//if err := httplib.ReadJSON(r, &req); err != nil {
//	return nil, trace.Wrap(err)
//}
