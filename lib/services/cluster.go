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
	"encoding/json"
	"fmt"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

type TrustedClusterCRUD interface {
	UpsertCluster(TrustedCluster) error
	GetCluster(string) (TrustedCluster, error)
	GetClusters() ([]TrustedCluster, error)
	DeleteCluster(string) error
}

type TrustedCluster interface {
	GetName() string
	SetName(string)
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
	return &TrustedClusterV2{
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
	Enabled bool `json:"enabled"`

	// Roles is a list of roles that users will be assuming when connecting to this cluster.
	Roles []string `json:"roles"`

	// Token is the authorization token provided by another cluster needed by
	// this cluster to join.
	Token string `json:"token"`

	// ProxyAddress is the address of the SSH proxy server of the cluster to join. If not set,
	// it is derived from <metadata.name>:<default proxy server port>.
	ProxyAddress string `json:"ssh_proxy_addr"`

	// TODO(russjones): What service listens for reverse tunnels, auth or proxy?
	// ReverseTunnelAddress is the address of the SSH ??? server of the cluster to join. If
	// not set, it is derived from <metadata.name>:<default reverse tunnel port>.
	ReverseTunnelAddress string `json:"ssh_reverse_tunnel_addr"`
}

func (c *TrustedClusterV2) GetName() string {
	return c.Metadata.Name
}

func (c *TrustedClusterV2) SetName(e string) {
	c.Metadata.Name = e
}

func (c *TrustedClusterV2) GetEnabled() bool {
	return c.Spec.Enabled
}

func (c *TrustedClusterV2) SetEnabled(e bool) {
	c.Spec.Enabled = e
}

func (c *TrustedClusterV2) GetRoles() []string {
	return c.Spec.Roles
}

func (c *TrustedClusterV2) SetRoles(e []string) {
	c.Spec.Roles = e
}

func (c *TrustedClusterV2) GetToken() string {
	return c.Spec.Token
}

func (c *TrustedClusterV2) SetToken(e string) {
	c.Spec.Token = e
}

func (c *TrustedClusterV2) GetProxyAddress() string {
	return c.Spec.ProxyAddress
}

func (c *TrustedClusterV2) SetProxyAddress(e string) {
	c.Spec.ProxyAddress = e
}

func (c *TrustedClusterV2) GetReverseTunnelAddress() string {
	return c.Spec.ReverseTunnelAddress
}

func (c *TrustedClusterV2) SetReverseTunnelAddress(e string) {
	c.Spec.ReverseTunnelAddress = e
}

func (c *TrustedClusterV2) Check() error {
	return nil
}

// String represents a human readable version of trusted cluster settings.
func (c *TrustedClusterV2) String() string {
	return fmt.Sprintf("TrustedCluster(Enabled=%v,Roles=%v,Token=%v,ProxyAddress=%v,ReverseTunnelAddress=%v)",
		c.Spec.Enabled, c.Spec.Roles, c.Spec.Token, c.Spec.ProxyAddress, c.Spec.ReverseTunnelAddress)
}

const TrustedClusterSpecSchemaTemplate = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "enabled": {"type": "bool"},
    "roles": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "token": {"type": "string"},
    "ssh_proxy_addr": {"type": "string"},
    "ssh_reverse_tunnel_addr": {"type": "string"}%v
  }
}`

// GetTrustedClusterSchema returns the schema with optionally injected
// schema for extensions.
func GetTrustedClusterSchema(extensionSchema string) string {
	var trustedClusterSchema string
	if trustedClusterSchema == "" {
		trustedClusterSchema = fmt.Sprintf(TrustedClusterSpecSchemaTemplate, "")
	} else {
		trustedClusterSchema = fmt.Sprintf(TrustedClusterSpecSchemaTemplate, ","+extensionSchema)
	}
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, trustedClusterSchema)
}

// TrustedClusterMarshaler implements marshal/unmarshal of TrustedCluster implementations
// mostly adds support for extended versions.
type TrustedClusterMarshaler interface {
	Marshal(c TrustedCluster, opts ...MarshalOption) ([]byte, error)
	Unmarshal(bytes []byte) (TrustedCluster, error)
}

var trustedClusterMarshaler TrustedClusterMarshaler = &TeleportTrustedClusterMarshaler{}

func SetTrustedClusterMarshaler(m TrustedClusterMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	trustedClusterMarshaler = m
}

func GetTrustedClusterMarshaler() TrustedClusterMarshaler {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	return trustedClusterMarshaler
}

type TeleportTrustedClusterMarshaler struct{}

// Unmarshal unmarshals role from JSON or YAML.
func (t *TeleportTrustedClusterMarshaler) Unmarshal(bytes []byte) (TrustedCluster, error) {
	var trustedCluster TrustedClusterV2

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	err := utils.UnmarshalWithSchema(GetTrustedClusterSchema(""), &trustedCluster, bytes)
	if err != nil {
		return nil, trace.BadParameter(err.Error())
	}

	return &trustedCluster, nil
}

// Marshal marshals role to JSON or YAML.
func (t *TeleportTrustedClusterMarshaler) Marshal(c TrustedCluster, opts ...MarshalOption) ([]byte, error) {
	return json.Marshal(c)
}
