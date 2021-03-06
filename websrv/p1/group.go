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

package p1

import (
	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
)

type Group struct {
	*httpsrv.Controller
}

func (c Group) ListAction() {

	ls := ipapi.PackGroupList{
		TypeMeta: types.TypeMeta{
			Kind: "PackGroupList",
		},
		Items: ipapi.PackGroups,
	}

	c.Response.Out.Header().Set("Access-Control-Allow-Origin", "*")

	c.RenderJson(ls)
}
