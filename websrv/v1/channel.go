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

package v1 // import "code.hooto.com/lessos/lospack/websrv/v1"

import (
	"regexp"

	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/httpsrv"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/lospack/lpapi"
	"code.hooto.com/lessos/lospack/server/data"
	"code.hooto.com/lynkdb/iomix/skv"
)

var (
	channel_id_re     = regexp.MustCompile("^[a-f0-9]{8,16}$")
	channel_vendor_re = regexp.MustCompile("^[a-zA-Z]{1}[a-zA-Z0-9.]{2,49}$")
)

type Channel struct {
	*httpsrv.Controller
}

func (c Channel) ListAction() {

	sets := lpapi.PackageChannelList{}
	defer c.RenderJson(&sets)

	if rs := data.Data.PvScan("channel/", "", "", 100); rs.OK() {

		rs.KvEach(func(entry *skv.ResultEntry) int {

			var set lpapi.PackageChannel
			if err := entry.Decode(&set); err == nil {
				sets.Items = append(sets.Items, set)
			}

			return 0
		})
	}

	sets.Kind = "PackageChannelList"
}

func (c Channel) EntryAction() {

	set := lpapi.PackageChannel{}
	defer c.RenderJson(&set)

	if c.Params.Get("id") == "" {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Channel Not Found",
		}
		return
	}

	rs := data.Data.PvGet("channel/" + c.Params.Get("id"))
	if !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Channel Not Found",
		}
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Channel Not Found",
		}
		return
	}

	set.Kind = "PackageChannel"
}

func (c Channel) SetAction() {

	set := lpapi.PackageChannel{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: err.Error(),
		}
		return
	}

	if !channel_id_re.MatchString(set.Meta.ID) {
		set.Meta.ID = idhash.RandHexString(8)
	}

	if !channel_vendor_re.MatchString(set.VendorName) {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Bad Request: Invalid VendorName",
		}
		return
	}

	if rs := data.Data.PvGet("channel/" + set.Meta.ID); rs.OK() {

		var prev lpapi.PackageChannel

		if err := rs.Decode(&prev); err != nil {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Server Error",
			}
			return
		}

		prev.VendorName = set.VendorName
		prev.VendorAPI = set.VendorAPI
		prev.VendorSite = set.VendorSite
		prev.Meta.Updated = types.MetaTimeNow()
		prev.Kind = ""

		if rs := data.Data.PvPut("channel/"+set.Meta.ID, prev, nil); !rs.OK() {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Can not write to database: " + rs.Bytex().String(),
			}
			return
		}

	} else {

		set.Meta.Created = types.MetaTimeNow()
		set.Meta.Updated = types.MetaTimeNow()
		set.Kind = ""

		if rs := data.Data.PvPut("channel/"+set.Meta.ID, set, nil); !rs.OK() {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Can not write to database: " + rs.Bytex().String(),
			}
			return
		}
	}

	set.Kind = "PackageChannel"
}

func (c Channel) DeleteAction() {

	set := lpapi.PackageChannel{}
	defer c.RenderJson(&set)

	rs := data.Data.PvGet("channel/" + c.Params.Get("id"))
	if !rs.OK() {

		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Channel Not Found",
		}
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Channel Not Found",
		}
		return
	}

	if set.Packages > 0 {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Can not delete non-empty Channel",
		}
		return
	}

	if rs := data.Data.PvDel("channel/"+c.Params.Get("id"), nil); !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Server Error",
		}
		return
	}

	set.Kind = "PackageChannel"
}
