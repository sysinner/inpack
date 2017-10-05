// Copyright 2016 lessos Authors, All rights reserved.
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

package v1 // import "github.com/sysinner/inpack/websrv/v1"

import (
	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
)

type Group struct {
	*httpsrv.Controller
}

func (c Group) ListAction() {

	ls := ipapi.PackageGroupList{
		TypeMeta: types.TypeMeta{
			Kind: "PackageGroupList",
		},
		Items: ipapi.PackageGroups,
	}

	c.Response.Out.Header().Set("Access-Control-Allow-Origin", "*")

	c.RenderJson(ls)
}
