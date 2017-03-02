/*
Copyright 2017 Gravitational, Inc.

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

package services

import (
	"fmt"

	"github.com/gravitational/trace"
)

type TrustedClusterCRUD interface {
	CreateCluster(TrustedCluster) error
	ReadCluster(string) TrustedCluster
	UpdateCluster(TrustedCluster) error
	DeleteCluster(string) error
}

type TrustedCluster interface {
	GetEnabled() bool
	SetEnabled(bool)
	GetRoles() []string
	SetRoles([]string)
	GetToken() string
	SetToken(string)
	GetProxyAddress() string
	SetProxyAddress(string)
	GetReverseTunnelAddress() string
	SetReverseTunnelAddress(string)
}

// NewTrustedCluster is a convenience wa to create a TrustedCluster resource.
func NewTrustedCluster(name string, spec TrustedClusterSpecV2) (TrustedCluster, error) {
	return &AuthPreferenceV2{
		Kind:    KindTrustedCluster,
		Version: V2,
		Metadata: Metadata{
			Name:      name,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}, nil
}

// TrustedClusterV2 implements TrustedCluster.
type TrustedClusterV2 struct {
	// Kind is a resource kind - always resource.
	Kind string `json:"kind"`

	// Version is a resource version.
	Version string `json:"version"`

	// Metadata is metadata about the resource.
	Metadata Metadata `json:"metadata"`

	// Spec is the specification of the resource.
	Spec TrustedClusterSpecV2 `json:"spec"`
}

// TrustedClusterSpecV2 is the actual data we care about for TrustedClusterSpecV2.
type TrustedClusterSpecV2 struct {
	// Enabled is a bool that indicates if the TrustedCluster is enabled or disabled.
	// Setting Enabled to false has a side effect of deleting the user and host
	// certificate authority (CA).
	Enabled bool

	// Roles is a list of roles that users will be assuming when connecting to this cluster.
	Roles []string

	// Token is the authorization token provided by another cluster needed by
	// this cluster to join.
	Token string

	// ProxyAddress is the address of the SSH proxy server of the cluster to join. If not set,
	// it is derived from <metadata.name>:<default proxy server port>.
	ProxyAddress string

	// TODO(russjones): What service listens for reverse tunnels, auth or proxy?
	// ReverseTunnelAddress is the address of the SSH ??? server of the cluster to join. If
	// not set, it is derived from <metadata.name>:<default reverse tunnel port>.
	ReverseTunnelAddress string
}

func (c *TrustedClusterV2) GetEnabled() bool {
	return c.Spec.Enabled
}

func (c *TrustedClusterV2) SetEnabled(e bool) {
	c.Spec.Enabled = e
}

//	GetEnabled() bool
//	SetEnabled(bool)
//	GetRoles() []string
//	SetRoles([]string)
//	GetToken() string
//	SetToken(string)
//	GetProxyAddress() string
//	SetProxyAddress(string)
//	GetReverseTunnelAddress() string
//	SetReverseTunnelAddress(string)

//// SetType sets the type of authentication.
//func (c *AuthPreferenceV2) SetType(s string) {
//	c.Spec.Type = s
//}
//
//// GetSecondFactor returns the type of second factor.
//func (c *AuthPreferenceV2) GetSecondFactor() string {
//	return c.Spec.SecondFactor
//}
//
//// SetSecondFactor sets the type of second factor.
//func (c *AuthPreferenceV2) SetSecondFactor(s string) {
//	c.Spec.SecondFactor = s
//}
//
//// CheckAndSetDefaults verifies the constraints for AuthPreference.
//func (c *AuthPreferenceV2) CheckAndSetDefaults() error {
//	// if nothing is passed in, set defaults
//	if c.Spec.Type == "" {
//		c.Spec.Type = teleport.Local
//	}
//	if c.Spec.SecondFactor == "" && c.Spec.Type == teleport.Local {
//		c.Spec.SecondFactor = teleport.OTP
//	}
//
//	// make sure whatever was passed in was sane
//	switch c.Spec.Type {
//	case teleport.Local:
//		if c.Spec.SecondFactor != teleport.OFF && c.Spec.SecondFactor != teleport.OTP && c.Spec.SecondFactor != teleport.U2F {
//			return trace.BadParameter("second factor type %q not supported", c.Spec.SecondFactor)
//		}
//	case teleport.OIDC:
//		if c.Spec.SecondFactor != "" {
//			return trace.BadParameter("second factor [%q] not supported with oidc connector")
//		}
//	default:
//		return trace.BadParameter("unsupported type %q", c.Spec.Type)
//	}
//
//	return nil
//}
//
//// String represents a human readable version of authentication settings.
//func (c *AuthPreferenceV2) String() string {
//	return fmt.Sprintf("AuthPreference(Type=%q,SecondFactor=%q)", c.Spec.Type, c.Spec.SecondFactor)
//}
