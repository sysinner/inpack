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

package v1 // import "github.com/sysinner/inpack/websrv/v1"

import (
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/data"
)

type Channel struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Channel) Init() int {
	c.us, _ = iamclient.SessionInstance(c.Session)
	return 0
}

func (c Channel) ListAction() {

	sets := ipapi.PackChannelList{}
	defer c.RenderJson(&sets)

	if rs := data.Data.NewReader(nil).KeyRangeSet(
		ipapi.DataChannelKey(""), ipapi.DataChannelKey("")).LimitNumSet(100).Query(); rs.OK() {

		for _, entry := range rs.Items {

			var set ipapi.PackChannel
			if err := entry.Decode(&set); err == nil {
				if c.us.UserName == "sysadmin" ||
					c.us.UserName == set.Meta.User ||
					(set.Roles != nil && set.Roles.Read.MatchAny(c.us.Roles)) {
					sets.Items = append(sets.Items, set)
				}
			}
		}
	}

	sets.Kind = "PackChannelList"
}

func (c Channel) EntryAction() {

	var set ipapi.PackChannel
	defer c.RenderJson(&set)

	name := c.Params.Get("name")
	if !ipapi.ChannelNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("400", "Invalid Channel Name")
		return
	}

	rs := data.Data.NewReader(ipapi.DataChannelKey(name)).Query()
	if !rs.OK() {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
		return
	}

	set.Kind = "PackChannel"
}

func (c Channel) SetAction() {

	set := ipapi.PackChannel{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if !ipapi.ChannelNameRe.MatchString(set.Meta.Name) {
		set.Error = types.NewErrorMeta("400", "Invalid Channel Name")
		return
	}

	if !ipapi.ChannelVendorRe.MatchString(set.VendorName) {
		set.Error = types.NewErrorMeta("400", "Invalid Vendor Name")
		return
	}

	if !c.us.IsLogin() || c.us.UserName != "sysadmin" {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if rs := data.Data.NewReader(ipapi.DataChannelKey(set.Meta.Name)).Query(); rs.OK() {

		var prev ipapi.PackChannel

		if err := rs.Decode(&prev); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error "+err.Error())
			return
		}

		prev.VendorName = set.VendorName
		prev.VendorAPI = set.VendorAPI
		prev.VendorSite = set.VendorSite
		prev.Roles = set.Roles

		prev.Kind = ""

		if prev.Meta.User == "" {
			prev.Meta.User = "sysadmin"
		}

		set = prev

	} else {

		set.Meta.User = c.us.UserName
		set.Meta.Created = types.MetaTimeNow()

		if set.Roles == nil {
			set.Roles = &ipapi.PackChannelRoles{}
			set.Roles.Read.Set(100)
		}
	}

	set.Meta.Updated = types.MetaTimeNow()
	set.Kind = ""

	if rs := data.Data.NewWriter(ipapi.DataChannelKey(set.Meta.Name), set).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database: "+rs.Message)
		return
	}

	set.Kind = "PackChannel"
}

func (c Channel) DeleteAction() {

	set := ipapi.PackChannel{}
	defer c.RenderJson(&set)

	if !c.us.IsLogin() || c.us.UserName != "sysadmin" {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	name := c.Params.Get("name")
	if !ipapi.ChannelNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("400", "Invalid Channel Name")
		return
	}

	rs := data.Data.NewReader(ipapi.DataChannelKey(name)).Query()
	if !rs.OK() {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = types.NewErrorMeta("404", "Channel Not Found")
		return
	}

	if set.StatNum > 0 {
		set.Error = types.NewErrorMeta("400", "Can not delete non-empty Channel")
		return
	}

	if rs := data.Data.NewWriter(ipapi.DataChannelKey(name), nil).
		ModeDeleteSet(true).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	set.Kind = "PackChannel"
}
