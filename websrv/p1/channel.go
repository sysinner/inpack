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

type Channel struct {
	*httpsrv.Controller
}

var (
	allowRoles     = []uint32{100, 101}
	channelMu      sync.RWMutex
	channelTTL     = int64(600)
	channelList    ipapi.PackChannelList
	channelUpdated int64
)

func channelRefresh() {

	tn := time.Now().Unix()

	if (channelUpdated + channelTTL) > tn {
		return
	}

	channelMu.Lock()
	defer channelMu.Unlock()

	var (
		rs = data.Data.NewReader(nil).KeyRangeSet(
			ipapi.DataChannelKey(""), ipapi.DataChannelKey("")).
			LimitNumSet(100).Query()
		items []*ipapi.PackChannel
	)

	for _, v := range rs.Items {

		var item ipapi.PackChannel
		if err := v.Decode(&item); err != nil {
			continue
		}

		items = append(items, &item)
	}

	channelUpdated = tn

	if len(items) > 0 {

		sort.Slice(items, func(i, j int) bool {
			return strings.Compare(items[i].Meta.Name, items[j].Meta.Name) > 0
		})

		channelList.Items = items

	} else {
		channelUpdated -= (channelTTL - 10)
	}
}

func (c Channel) ListAction() {

	channelRefresh()

	rep := ipapi.PackChannelList{}

	for _, v := range channelList.Items {
		if v.Roles.Read.MatchAny(allowRoles) {
			rep.Items = append(rep.Items, v)
		}
	}

	rep.Kind = "PackChannelList"
	c.RenderJson(rep)
}

func (c Channel) EntryAction() {

	var set ipapi.PackChannel
	defer c.RenderJson(&set)

	name := c.Params.Get("name")
	if !ipapi.ChannelNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("400", "Invalid Channel Name")
		return
	}

	channelRefresh()
	for _, v := range channelList.Items {
		if v.Meta.Name == name {
			set = *v
			break
		}
	}

	if set.Meta.Name != name {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
	} else {
		set.Kind = "PackChannel"
	}
}
