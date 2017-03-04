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

package local

import (
	"sort"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// TrustedClusterBackendService is responsible for managing trusted cluster resources.
type TrustedClusterBackendService struct {
	backend.Backend
}

// NewTrustedClusterBackendService returns a new TrustedClusterBackendService.
func NewTrustedClusterBackendService(backend backend.Backend) *TrustedClusterBackendService {
	return &TrustedClusterBackendService{
		Backend: backend,
	}
}

func (s *TrustedClusterBackendService) UpsertTrustedCluster(trustedCluster services.TrustedCluster) error {
	data, err := services.GetTrustedClusterMarshaler().Marshal(trustedCluster)
	if err != nil {
		return trace.Wrap(err)
	}

	err = s.UpsertVal([]string{"trustedclusters"}, trustedCluster.GetName(), []byte(data), backend.Forever)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (s *TrustedClusterBackendService) GetTrustedCluster(name string) (services.TrustedCluster, error) {
	data, err := s.GetVal([]string{"trustedclusters"}, name)
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("trusted cluster not found")
		}
		return nil, trace.Wrap(err)
	}

	return services.GetTrustedClusterMarshaler().Unmarshal(data)
}

func (s *TrustedClusterBackendService) GetTrustedClusters() ([]services.TrustedCluster, error) {
	keys, err := s.GetKeys([]string{"trustedclusters"})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	out := make([]services.TrustedCluster, len(keys))
	for i, name := range keys {
		tc, err := s.GetTrustedCluster(name)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out[i] = tc
	}

	sort.Sort(services.SortedTrustedCluster(out))
	return out, nil
}

func (s *TrustedClusterBackendService) DeleteTrustedCluster(name string) error {
	err := s.DeleteKey([]string{"trustedclusters"}, name)
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("trusted cluster %q not found", name)
		}
	}

	return trace.Wrap(err)
}
