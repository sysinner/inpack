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
	"time"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
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
	fop, err := data.Storage.FoFileOpen("/ips" + file[len("ips/v1/pkg/dl"):])
	if err != nil {
		c.RenderError(404, "File Not Found")
		return
	}

	_, filename := filepath.Split(file)

	c.Response.Out.Header().Set("Cache-Control", "max-age=86400")
	http.ServeContent(c.Response.Out, c.Request.Request, filename, time.Now(), fop)
}

func (c Pkg) ListAction() {

	ls := ipapi.PackList{}
	defer c.RenderJson(&ls)

	var (
		q_name    = c.Params.Get("name")
		q_channel = c.Params.Get("channel")
		q_text    = c.Params.Get("q")
		limit     = int(c.Params.Int64("limit"))
	)

	if !ipapi.PackNameRe.MatchString(q_name) {
		ls.Error = types.NewErrorMeta("400", "Invalid Pack Name")
		return
	}

	if limit < 1 {
		limit = 100
	} else if limit > 200 {
		limit = 200
	}

	rs := data.Data.NewReader(nil).KeyRangeSet(
		ipapi.DataPackKey(""), ipapi.DataPackKey("")).LimitNumSet(1000).Query()
	if !rs.OK() {
		ls.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	for _, entry := range rs.Items {

		if len(ls.Items) >= limit {
			// TOPO return 0
		}

		var set ipapi.Pack
		if err := entry.Decode(&set); err != nil {
			continue
		}

		if q_name != "" && q_name != set.Meta.Name {
			continue
		}

		if q_channel != "" && q_channel != set.Channel {
			continue
		}

		if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
			continue
		}

		if ipapi.OpPermAllow(set.OpPerm, ipapi.OpPermOff) {
			continue
		}

		if us.IsLogin() && (us.UserName == set.Meta.User || us.UserName == "sysadmin") {
			set.OpPerm = ipapi.OpPermRead | ipapi.OpPermWrite
		} else {
			set.OpPerm = ipapi.OpPermRead
		}

		ls.Items = append(ls.Items, set)
	}

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].Meta.Updated > ls.Items[j].Meta.Updated
	})

	if len(ls.Items) > limit {
		ls.Items = ls.Items[:limit]
	}

	ls.Kind = "PackList"
}

func (c Pkg) EntryAction() {

	var set struct {
		types.TypeMeta
		ipapi.Pack
	}
	defer c.RenderJson(&set)

	var (
		id   = c.Params.Get("id")
		name = c.Params.Get("name")
	)

	if id == "" && name == "" {
		set.Error = types.NewErrorMeta("400", "Pack ID or Name Not Found")
		return
	} else if name != "" {

		if !ipapi.PackNameRe.MatchString(name) {
			set.Error = types.NewErrorMeta("400", "Invalid Pack Name")
			return
		}

		version := ipapi.PackVersion{
			Version: types.Version(c.Params.Get("version")),
			Release: types.Version(c.Params.Get("release")),
			Dist:    c.Params.Get("dist"),
			Arch:    c.Params.Get("arch"),
		}
		if err := version.Valid(); err != nil {
			set.Error = types.NewErrorMeta("400", err.Error())
			return
		}
		id = ipapi.PackFilenameKey(name, version)
	}

	if id != "" {

		if rs := data.Data.NewReader(ipapi.DataPackKey(id)).Query(); rs.OK() {
			rs.Decode(&set.Pack)
		} else if name != "" {
			// TODO
		} else {

		}
	}

	if set.Meta.Name == "" {
		set.Error = types.NewErrorMeta("404", "Pack Not Found")
	} else {
		set.Kind = "Pack"
	}
}

func (c Pkg) SetAction() {

	var set struct {
		types.TypeMeta
		ipapi.Pack
	}
	defer c.RenderJson(&set)

	//
	if err := c.Request.JsonDecode(&set.Pack); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if set.Meta.ID == "" { // TODO
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	rs := data.Data.NewReader(ipapi.DataPackKey(set.Meta.ID)).Query()
	if !rs.OK() {
		set.Error = types.NewErrorMeta("400", "No Pack Found")
		return
	}

	var prev ipapi.Pack
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
		setChannel ipapi.PackChannel
		preChannel ipapi.PackChannel
	)

	if ipapi.OpPermAllow(set.OpPerm, ipapi.OpPermOff) &&
		!ipapi.OpPermAllow(prev.OpPerm, ipapi.OpPermOff) {

		if rs := data.Data.NewReader(ipapi.DataChannelKey(set.Channel)).Query(); !rs.OK() ||
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

			if rs := data.Data.NewReader(ipapi.DataChannelKey(prev.Channel)).Query(); !rs.OK() ||
				rs.Decode(&preChannel) != nil {
				set.Error = types.NewErrorMeta("500", "Server Error 3")
				return
			}

			preChannel.StatNum--
			preChannel.StatSize -= prev.Size

			prev.Channel = set.Channel
		}

		var info ipapi.PackInfo
		name_lower := strings.ToLower(prev.Meta.Name)

		if rs := data.Data.NewReader(ipapi.DataInfoKey(name_lower)).Query(); !rs.OK() ||
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

		if rs := data.Data.NewWriter(ipapi.DataInfoKey(name_lower), info).Commit(); !rs.OK() {
			set.Error = types.NewErrorMeta("500", "Server Error 3.1")
			return
		}

	} else if prev.Channel != set.Channel {

		if rs := data.Data.NewReader(ipapi.DataChannelKey(set.Channel)).Query(); !rs.OK() ||
			rs.Decode(&setChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error 4")
			return
		}

		if rs := data.Data.NewReader(ipapi.DataChannelKey(prev.Channel)).Query(); !rs.OK() ||
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

		data.Data.NewWriter(ipapi.DataChannelKey(setChannel.Meta.Name), setChannel).Commit()
	}

	if preChannel.Meta.Name != "" {

		if preChannel.StatNum < 0 {
			preChannel.StatNum = 0
		}

		if preChannel.StatSize < 0 {
			preChannel.StatSize = 0
		}

		data.Data.NewWriter(ipapi.DataChannelKey(preChannel.Meta.Name), preChannel).Commit()
	}

	prev.Meta.Updated = types.MetaTimeNow()
	data.Data.NewWriter(ipapi.DataPackKey(set.Meta.ID), prev).Commit()

	set.Kind = "Pack"
}

func channelList() []ipapi.PackChannel {

	sets := []ipapi.PackChannel{}

	rs := data.Data.NewReader(nil).KeyRangeSet(
		ipapi.DataChannelKey(""), ipapi.DataChannelKey("")).LimitNumSet(100).Query()
	if !rs.OK() {
		return sets
	}

	for _, entry := range rs.Items {
		var set ipapi.PackChannel
		if err := entry.Decode(&set); err == nil {
			sets = append(sets, set)
		}
	}

	return sets
}
