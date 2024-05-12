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
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
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

	file := filepath.Clean(c.Request.UrlPath())

	if !strings.HasPrefix(file, "/ips/v1/pkg/dl/") {
		c.RenderError(400, "Bad Request")
		return
	}

	// TODO auth
	fop, err := data.Storage.Open("/ips" + file[len("/ips/v1/pkg/dl"):])
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
		q_name    = c.Params.Value("name")
		q_channel = c.Params.Value("channel")
		q_text    = c.Params.Value("q")
		limit     = int(c.Params.IntValue("limit"))
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

	rs := data.Data.NewRanger(
		ipapi.DataPackKey(""), ipapi.DataPackKey("")).SetLimit(1000).Exec()
	if !rs.OK() {
		ls.Error = types.NewErrorMeta("500", rs.ErrorMessage())
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	for _, entry := range rs.Items {

		if len(ls.Items) >= limit {
			// TOPO return 0
		}

		var set ipapi.Pack
		if err := entry.JsonDecode(&set); err != nil {
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

		ls.Items = append(ls.Items, &set)
	}

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].Meta.Updated > ls.Items[j].Meta.Updated
	})

	if len(ls.Items) > limit {
		ls.Items = ls.Items[:limit]
	}

	ls.Kind = "PackList"
}

type pkgCacheList struct {
	mu    sync.RWMutex
	items map[string]*pkgCacheEntry
}

type pkgCacheVersion struct {
	version types.Version
	release types.Version
	dist    string
	arch    string
}

type pkgCacheEntry struct {
	mu      sync.RWMutex
	name    string
	logId   uint64
	items   []*pkgCacheVersion
	imap    map[string]bool
	updated int64
}

func (it *pkgCacheEntry) Find(vers, dist, arch string) *pkgCacheVersion {
	var (
		vr = types.Version(vers)
		rs = []*pkgCacheVersion{}
	)
	for _, v := range it.items {
		if vr.Compare(v.version) > 0 {
			continue
		}
		if v.dist != dist && (v.dist != "linux" && v.dist != "all") {
			continue
		}
		if v.arch != arch && v.arch != "src" {
			continue
		}
		rs = append(rs, v)
	}
	if len(rs) < 1 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool {
		k := rs[i].version.Compare(rs[j].version)
		if k == 0 {
			return rs[i].release.Compare(rs[j].release) > 0
		}
		return k > 0
	})
	return rs[0]
}

func (it *pkgCacheList) Entry(name string) *pkgCacheEntry {
	it.mu.Lock()
	defer it.mu.Unlock()
	p, ok := it.items[name]
	if ok {
		return p
	}
	p = &pkgCacheEntry{
		name:  strings.ToLower(name),
		logId: 0,
		imap:  map[string]bool{},
	}
	it.items[name] = p
	return p
}

var (
	pkgCache = pkgCacheList{
		items: map[string]*pkgCacheEntry{},
	}
)

func (c Pkg) EntryAction() {

	var set struct {
		types.TypeMeta
		ipapi.Pack
	}
	defer c.RenderJson(&set)

	var (
		id   = c.Params.Value("id")
		name = c.Params.Value("name")
		vers = c.Params.Value("version")
	)

	if id == "" && name == "" {
		set.Error = types.NewErrorMeta("400", "Pack ID or Name Not Found")
		return
	} else if name != "" {

		if !ipapi.PackNameRe.MatchString(name) {
			set.Error = types.NewErrorMeta("400", "Invalid Pack Name")
			return
		}

		t := time.Now().Unix()
		p := pkgCache.Entry(name)
		if (p.updated + 10) < t {

			// TODO
			rs := data.Data.NewRanger(
				ipapi.DataPackKey(fmt.Sprintf("%s-%s", name, vers)),
				ipapi.DataPackKey(fmt.Sprintf("%s-%sz", name, vers)),
			).SetRevert(true).SetLimit(100).Exec()

			hlog.Printf("debug", "package entry find %s, ver %s, num %d",
				name, vers, len(rs.Items))

			if !rs.OK() {
				set.Error = types.NewErrorMeta("400", "Pack ID or Name Not Found")
				return
			}

			p.mu.Lock()
			for _, v := range rs.Items {
				var item ipapi.Pack
				if err := v.JsonDecode(&item); err != nil {
					continue
				}

				if _, ok := p.imap[item.Version.HashString()]; ok {
					continue
				}

				p.items = append(p.items, &pkgCacheVersion{
					version: types.Version(item.Version.Version),
					release: types.Version(item.Version.Release),
					dist:    item.Version.Dist,
					arch:    item.Version.Arch,
				})
				p.imap[item.Version.HashString()] = true
			}
			p.mu.Unlock()

			p.updated = time.Now().Unix()
		}

		version := p.Find(vers, c.Params.Value("dist"), c.Params.Value("arch"))
		if version == nil {
			set.Error = types.NewErrorMeta("400", "Package not found")
			return
		}

		/**
		version := ipapi.PackVersion{
			Version: string(c.Params.Value("version")),
			Release: string(c.Params.Value("release")),
			Dist:    c.Params.Value("dist"),
			Arch:    c.Params.Value("arch"),
		}
		if err := version.Valid(); err != nil {
			set.Error = types.NewErrorMeta("400", err.Error())
			return
		}
		*/
		id = ipapi.PackFilenameKey(name, ipapi.PackVersion{
			Version: version.version,
			Release: version.release,
			Dist:    version.dist,
			Arch:    version.arch,
		})
	}

	if id != "" {

		if rs := data.Data.NewReader(ipapi.DataPackKey(id)).Exec(); rs.OK() {
			rs.Item().JsonDecode(&set.Pack)
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

	rs := data.Data.NewReader(ipapi.DataPackKey(set.Meta.ID)).Exec()
	if !rs.OK() {
		set.Error = types.NewErrorMeta("400", "No Pack Found")
		return
	}

	var prev ipapi.Pack
	if err := rs.Item().JsonDecode(&prev); err != nil {
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

		if rs := data.Data.NewReader(ipapi.DataChannelKey(set.Channel)).Exec(); !rs.OK() ||
			rs.Item().JsonDecode(&setChannel) != nil {
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

			if rs := data.Data.NewReader(ipapi.DataChannelKey(prev.Channel)).Exec(); !rs.OK() ||
				rs.Item().JsonDecode(&preChannel) != nil {
				set.Error = types.NewErrorMeta("500", "Server Error 3")
				return
			}

			preChannel.StatNum--
			preChannel.StatSize -= prev.Size

			prev.Channel = set.Channel
		}

		var info ipapi.PackInfo
		name_lower := strings.ToLower(prev.Meta.Name)

		if rs := data.Data.NewReader(ipapi.DataInfoKey(name_lower)).Exec(); !rs.OK() ||
			rs.Item().JsonDecode(&info) != nil {
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

		if rs := data.Data.NewWriter(ipapi.DataInfoKey(name_lower), info).Exec(); !rs.OK() {
			set.Error = types.NewErrorMeta("500", "Server Error 3.1")
			return
		}

	} else if prev.Channel != set.Channel {

		if rs := data.Data.NewReader(ipapi.DataChannelKey(set.Channel)).Exec(); !rs.OK() ||
			rs.Item().JsonDecode(&setChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error 4")
			return
		}

		if rs := data.Data.NewReader(ipapi.DataChannelKey(prev.Channel)).Exec(); !rs.OK() ||
			rs.Item().JsonDecode(&preChannel) != nil {
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

		data.Data.NewWriter(ipapi.DataChannelKey(setChannel.Meta.Name), setChannel).Exec()
	}

	if preChannel.Meta.Name != "" {

		if preChannel.StatNum < 0 {
			preChannel.StatNum = 0
		}

		if preChannel.StatSize < 0 {
			preChannel.StatSize = 0
		}

		data.Data.NewWriter(ipapi.DataChannelKey(preChannel.Meta.Name), preChannel).Exec()
	}

	prev.Meta.Updated = types.MetaTimeNow()
	data.Data.NewWriter(ipapi.DataPackKey(set.Meta.ID), prev).Exec()

	set.Kind = "Pack"
}

func channelList() []ipapi.PackChannel {

	sets := []ipapi.PackChannel{}

	rs := data.Data.NewRanger(
		ipapi.DataChannelKey(""), ipapi.DataChannelKey("")).SetLimit(100).Exec()
	if !rs.OK() {
		return sets
	}

	for _, entry := range rs.Items {
		var set ipapi.PackChannel
		if err := entry.JsonDecode(&set); err == nil {
			sets = append(sets, set)
		}
	}

	return sets
}
