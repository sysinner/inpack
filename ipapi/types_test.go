// Copyright 2016 Eryx <evorui аt gmаil dοt cοm>, All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipapi // import "github.com/sysinner/inpack/ipapi"

import (
	"testing"
)

type valid_pkgname_entry struct {
	v  string
	ok bool
}

func TestPackageNameRe(t *testing.T) {
	vs := []valid_pkgname_entry{
		{"name", true},
		{"Name", true},
		{"name-name", true},
		{"name_name", true},
		{"nna", true},
		{"nn", false},
		{"0name", false},
		{"name.", false},
		{"...", false},
	}
	for _, v := range vs {
		if PackageNameRe.MatchString(v.v) != v.ok {
			t.Fatal("Failed on Valid " + v.v)
		}
	}
}
