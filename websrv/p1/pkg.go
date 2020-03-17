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

package p1 // import "github.com/sysinner/inpack/websrv/p1"

import (
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hooto/httpsrv"
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

	if !strings.HasPrefix(file, "ips/p1/pkg/dl/") {
		c.RenderError(400, "Bad Request")
		return
	}

	fop, err := data.Storage.FoFileOpen("/ips" + file[len("ips/p1/pkg/dl"):])
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

	var (
		offset = ipapi.DataPackKey(q_name)
		cutset = ipapi.DataPackKey(q_name)
	)

	rs := data.Data.NewReader(nil).KeyRangeSet(offset, cutset).LimitNumSet(1000).Query()
	if !rs.OK() {
		ls.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

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
