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
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/config"
	"github.com/sysinner/inpack/server/data"
)

type Pkg struct {
	*httpsrv.Controller
}

func (c Pkg) DlAction() {

	c.AutoRender = false

	file := filepath.Clean(c.Request.RequestPath)

	if !strings.HasPrefix(file, "ips/v1/pkg/dl/") {
		c.RenderError(400, "Bad Request")
		return
	}

	// TODO auth
	opts := config.Config.IoConnectors.Options("inpack_storage")
	if opts == nil {
		c.RenderError(400, "Bad Request")
		return
	}
	fs_dir := opts.Value("data_dir")
	if fs_dir == "" {
		c.RenderError(400, "Bad Request")
		return
	}

	http.ServeFile(
		c.Response.Out,
		c.Request.Request,
		fs_dir+file[len("ips/v1/pkg/dl"):],
	)
}

func (c Pkg) ListAction() {

	ls := ipapi.PackageList{}
	defer c.RenderJson(&ls)

	var (
		q_name    = c.Params.Get("name")
		q_channel = c.Params.Get("channel")
		q_text    = c.Params.Get("q")
		limit     = int(c.Params.Int64("limit"))
	)

	if !ipapi.PackageNameRe.MatchString(q_name) {
		ls.Error = types.NewErrorMeta("400", "Invalid Package Name")
		return
	}

	if limit < 1 {
		limit = 100
	} else if limit > 200 {
		limit = 200
	}

	rs := data.Data.ProgScan(ipapi.DataPackKey(""), ipapi.DataPackKey(""), 1000)
	if !rs.OK() {
		ls.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	rs.KvEach(func(entry *skv.ResultEntry) int {

		if len(ls.Items) >= limit {
			// TOPO return 0
		}

		var set ipapi.Package
		if err := entry.Decode(&set); err == nil {

			if q_name != "" && q_name != set.Meta.Name {
				return 0
			}

			if q_channel != "" && q_channel != set.Channel {
				return 0
			}

			if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
				return 0
			}

			if ipapi.OpPermAllow(set.OpPerm, ipapi.OpPermOff) {
				return 0
			}

			if us.IsLogin() && (us.UserName == set.Meta.User || us.UserName == "sysadmin") {
				set.OpPerm = ipapi.OpPermRead | ipapi.OpPermWrite
			} else {
				set.OpPerm = ipapi.OpPermRead
			}

			ls.Items = append(ls.Items, set)
		}

		return 0
	})

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].Meta.Updated > ls.Items[j].Meta.Updated
	})

	if len(ls.Items) > limit {
		ls.Items = ls.Items[:limit]
	}

	ls.Kind = "PackageList"
}

func (c Pkg) EntryAction() {

	var set struct {
		types.TypeMeta
		ipapi.Package
	}
	defer c.RenderJson(&set)

	var (
		id   = c.Params.Get("id")
		name = c.Params.Get("name")
	)

	if id == "" && name == "" {
		set.Error = types.NewErrorMeta("400", "Package ID or Name Not Found")
		return
	} else if name != "" {

		if !ipapi.PackageNameRe.MatchString(name) {
			set.Error = types.NewErrorMeta("400", "Invalid Package Name")
			return
		}

		version := ipapi.PackageVersion{
			Version: types.Version(c.Params.Get("version")),
			Release: types.Version(c.Params.Get("release")),
			Dist:    c.Params.Get("dist"),
			Arch:    c.Params.Get("arch"),
		}
		if err := version.Valid(); err != nil {
			set.Error = types.NewErrorMeta("400", err.Error())
			return
		}
		id = ipapi.PackageMetaId(name, version)
	}

	if id != "" {

		if rs := data.Data.ProgGet(ipapi.DataPackKey(id)); rs.OK() {
			rs.Decode(&set.Package)
		} else if name != "" {
			// TODO
		} else {

		}
	}

	if set.Meta.Name == "" {
		set.Error = types.NewErrorMeta("404", "Package Not Found")
	} else {
		set.Kind = "Package"
	}
}

func (c Pkg) SetAction() {

	var set struct {
		types.TypeMeta
		ipapi.Package
	}
	defer c.RenderJson(&set)

	//
	if err := c.Request.JsonDecode(&set.Package); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if set.Meta.ID == "" { // TODO
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	rs := data.Data.ProgGet(ipapi.DataPackKey(set.Meta.ID))
	if !rs.OK() {
		set.Error = types.NewErrorMeta("400", "No Package Found")
		return
	}

	var prev ipapi.Package
	if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("500", "Server Error 1")
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)
	if !us.IsLogin() || (us.UserName != prev.Meta.User && us.UserName != "sysadmin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if ipapi.OpPermAllow(prev.OpPerm, ipapi.OpPermOff) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	var (
		setChannel ipapi.PackageChannel
		preChannel ipapi.PackageChannel
	)

	if ipapi.OpPermAllow(set.OpPerm, ipapi.OpPermOff) &&
		!ipapi.OpPermAllow(prev.OpPerm, ipapi.OpPermOff) {

		if rs := data.Data.ProgGet(ipapi.DataChannelKey(set.Channel)); !rs.OK() ||
			rs.Decode(&setChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error 2")
			return
		}

		prev.OpPerm = prev.OpPerm | ipapi.OpPermOff

		setChannel.StatNumOff++
		setChannel.StatSizeOff += prev.Size

		if prev.Channel == set.Channel {
			setChannel.StatNum--
			setChannel.StatSize -= prev.Size
		} else {

			if rs := data.Data.ProgGet(ipapi.DataChannelKey(prev.Channel)); !rs.OK() ||
				rs.Decode(&preChannel) != nil {
				set.Error = types.NewErrorMeta("500", "Server Error 3")
				return
			}

			preChannel.StatNum--
			preChannel.StatSize -= prev.Size

			prev.Channel = set.Channel
		}

		var info ipapi.PackageInfo
		name_lower := strings.ToLower(prev.Meta.Name)

		if rs := data.Data.ProgGet(ipapi.DataInfoKey(name_lower)); !rs.OK() ||
			rs.Decode(&info) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error 3.1")
			return
		}

		info.StatNum--
		info.StatSize -= prev.Size
		if info.StatNum < 0 {
			info.StatNum = 0
		}
		if info.StatSize < 0 {
			info.StatSize = 0
		}

		info.StatNumOff++
		info.StatSizeOff += prev.Size

		if rs := data.Data.ProgPut(ipapi.DataInfoKey(name_lower), skv.NewValueObject(info), nil); !rs.OK() {
			set.Error = types.NewErrorMeta("500", "Server Error 3.1")
			return
		}

	} else if prev.Channel != set.Channel {

		if rs := data.Data.ProgGet(ipapi.DataChannelKey(set.Channel)); !rs.OK() ||
			rs.Decode(&setChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error 4")
			return
		}

		if rs := data.Data.ProgGet(ipapi.DataChannelKey(prev.Channel)); !rs.OK() ||
			rs.Decode(&preChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error 5")
			return
		}

		preChannel.StatNum--
		preChannel.StatSize -= prev.Size

		setChannel.StatNum++
		setChannel.StatSize += prev.Size

		prev.Channel = set.Channel
	}

	if setChannel.Meta.Name != "" {

		if setChannel.StatNum < 0 {
			setChannel.StatNum = 0
		}

		if setChannel.StatSize < 0 {
			setChannel.StatSize = 0
		}

		data.Data.ProgPut(ipapi.DataChannelKey(setChannel.Meta.Name), skv.NewValueObject(setChannel), nil)
	}

	if preChannel.Meta.Name != "" {

		if preChannel.StatNum < 0 {
			preChannel.StatNum = 0
		}

		if preChannel.StatSize < 0 {
			preChannel.StatSize = 0
		}

		data.Data.ProgPut(ipapi.DataChannelKey(preChannel.Meta.Name), skv.NewValueObject(preChannel), nil)
	}

	prev.Meta.Updated = types.MetaTimeNow()
	data.Data.ProgPut(ipapi.DataPackKey(set.Meta.ID), skv.NewValueObject(prev), nil)

	set.Kind = "Package"
}

func channelList() []ipapi.PackageChannel {

	sets := []ipapi.PackageChannel{}

	rs := data.Data.ProgScan(ipapi.DataChannelKey(""), ipapi.DataChannelKey(""), 100)
	if !rs.OK() {
		return sets
	}

	rs.KvEach(func(entry *skv.ResultEntry) int {

		var set ipapi.PackageChannel
		if err := entry.Decode(&set); err == nil {
			sets = append(sets, set)
		}

		return 0
	})

	return sets
}
