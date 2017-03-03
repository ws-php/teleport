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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/boltbk"
	//"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"gopkg.in/check.v1"
)

type TrustedClusterSuite struct {
	bk      backend.Backend
	tempDir string
}

var _ = check.Suite(&TrustedClusterSuite{})
var _ = fmt.Printf

func (s *TrustedClusterSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()
}

func (s *TrustedClusterSuite) TearDownSuite(c *check.C) {
}

func (s *TrustedClusterSuite) SetUpTest(c *check.C) {
	var err error

	s.tempDir, err = ioutil.TempDir("", "trusted-clusters-")
	c.Assert(err, check.IsNil)

	s.bk, err = boltbk.New(backend.Params{"path": s.tempDir})
	c.Assert(err, check.IsNil)
}

func (s *TrustedClusterSuite) TearDownTest(c *check.C) {
	var err error

	c.Assert(s.bk.Close(), check.IsNil)

	err = os.RemoveAll(s.tempDir)
	c.Assert(err, check.IsNil)
}

func (s *TrustedClusterSuite) TestTrustedClusterCRUD(c *check.C) {
}
