// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"testing"
)

func TestOpensslVersion(t *testing.T) {
	ver := OpensslVersion()
	if len(ver) <= 0 {
		t.Fatalf("Couldn't retrieve openssl version")
	}
}

func TestSSLLibVersion(t *testing.T) {
	ver := SSLLibVersion()
	if len(ver) <= 0 {
		t.Fatalf("Couldn't retrieve openssl share library version")
	}
}
