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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/data"
)

var (
	pkgInfoTTL     = int64(600)
	pkgInfoMu      sync.RWMutex
	pkgInfoItems   []*ipapi.PackInfo
	pkgInfoUpdated int64
)

func pkgInfoRefresh() {

	tn := time.Now().Unix()

	if (pkgInfoUpdated + pkgInfoTTL) > tn {
		return
	}

	pkgInfoMu.Lock()
	defer pkgInfoMu.Unlock()

	var (
		rs = data.Data.NewReader(nil).KeyRangeSet(
			ipapi.DataInfoKey(""), ipapi.DataInfoKey("")).LimitNumSet(10000).Query()
		items = []*ipapi.PackInfo{}
	)

	for _, v := range rs.Items {

		var item ipapi.PackInfo
		if err := v.Decode(&item); err != nil {
			continue
		}

		items = append(items, &item)
	}

	pkgInfoUpdated = tn

	if len(items) > 0 {

		sort.Slice(items, func(i, j int) bool {
			return items[i].Meta.Updated > items[j].Meta.Updated
		})

		pkgInfoItems = items

	} else {
		pkgInfoUpdated -= (pkgInfoTTL - 10)
	}
}

type PkgInfo struct {
	*httpsrv.Controller
}

func (c PkgInfo) ListAction() {

	sets := ipapi.PackInfoList{}
	defer c.RenderJson(&sets)

	var (
		q_text  = c.Params.Get("q")
		q_group = c.Params.Get("group")
		limit   = 200
	)

	pkgInfoRefresh()

	for _, set := range pkgInfoItems {

		if len(sets.Items) > limit {
			break
		}

		if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
			continue
		}

		if q_group != "" && !set.Groups.Has(q_group) {
			continue
		}

		sets.Items = append(sets.Items, ipapi.PackInfo{
			Meta: types.InnerObjectMeta{
				Name: set.Meta.Name,
			},
			LastVersion: set.LastVersion,
		})
	}

	sets.Kind = "PackInfoList"
}

func (c PkgInfo) EntryAction() {

	set := ipapi.PackInfo{}
	defer c.RenderJson(&set)

	name := c.Params.Get("name")
	if !ipapi.PackNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("404", "Invalid Pack Name")
		return
	}

	pkgInfoRefresh()

	for _, v := range pkgInfoItems {
		if v.Meta.Name == name {
			set = *v
			break
		}
	}

	if set.Meta.Name != name {
		set.Error = types.NewErrorMeta("404", "PackInfo Not Found")
		return
	}

	// set.Meta.User = ""
	set.Meta.Created = 0
	set.Meta.Updated = 0

	set.Kind = "PackInfo"
}
