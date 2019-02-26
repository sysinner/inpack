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
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/data"
)

type Channel struct {
	*httpsrv.Controller
}

var (
	allow_roles = []uint32{100, 101}
)

func (c Channel) ListAction() {

	sets := ipapi.PackageChannelList{}
	defer c.RenderJson(&sets)

	if rs := data.Data.KvScan(ipapi.DataChannelKey(""), ipapi.DataChannelKey(""), 100); rs.OK() {

		rs.KvEach(func(entry *skv.ResultEntry) int {

			var set ipapi.PackageChannel
			if err := entry.Decode(&set); err == nil {
				if set.Roles != nil && set.Roles.Read.MatchAny(allow_roles) {
					set.Roles = nil
					sets.Items = append(sets.Items, set)
				}
			}

			return 0
		})
	}

	sets.Kind = "PackageChannelList"
}

func (c Channel) EntryAction() {

	var set ipapi.PackageChannel
	defer c.RenderJson(&set)

	name := c.Params.Get("name")
	if !ipapi.ChannelNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("400", "Invalid Channel Name")
		return
	}

	rs := data.Data.KvGet(ipapi.DataChannelKey(name))
	if !rs.OK() {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
		return
	}

	set.Kind = "PackageChannel"
}
