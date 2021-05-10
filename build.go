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

// #cgo linux darwin CFLAGS: -I/usr/local/openssl/include -I/usr/local/openssl -Wno-deprecated-declarations
// #cgo linux darwin LDFLAGS: /usr/local/openssl/lib/libssl.a /usr/local/openssl/lib/libcrypto.a -ldl
// #cgo windows CFLAGS: -IC:/msys64/usr/local/openssl/include -IC:/msys64/usr/local/openssl -Wno-deprecated-declarations
// #cgo windows LDFLAGS: C:/msys64/usr/local/openssl/lib/libssl.a C:/msys64/usr/local/openssl/lib/libcrypto.a -ldl -lws2_32
import "C"
