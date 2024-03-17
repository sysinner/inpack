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
	"sync"
	"time"

	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/data"
)

var (
	pkgMu  sync.RWMutex
	pkgTTL = int64(600)
	items  = map[string]*pkgFeed{}
)

type pkgFeed struct {
	updated int64
	items   []*ipapi.Pack
}

func pkgRefresh(pkgname string) *pkgFeed {

	tn := time.Now().Unix()

	pkgMu.Lock()
	defer pkgMu.Unlock()

	feed, ok := items[pkgname]

	if ok && (feed.updated+pkgTTL) > tn {
		return feed
	}
	if !ok {
		feed = &pkgFeed{}
		items[pkgname] = feed
	}

	var (
		offset = ipapi.DataPackKey(pkgname)
		items  []*ipapi.Pack
	)

	rs := data.Data.NewReader(nil).ModeRevRangeSet(true).
		KeyRangeSet(append(offset, 0xff), offset).LimitNumSet(100).Query()

	for _, v := range rs.Items {

		var item ipapi.Pack
		if err := v.Decode(&item); err != nil {
			continue
		}

		items = append(items, &item)
	}

	feed.updated = tn

	if len(items) > 0 {

		sort.Slice(items, func(i, j int) bool {
			return items[i].Meta.Updated > items[j].Meta.Updated
		})

		for _, item := range items {
			item.Meta.Created = 0
			item.Meta.Updated = 0
			item.Built = 0
		}

		feed.items = items

	} else {
		feed.updated -= (pkgTTL - 10)
	}

	return feed
}

type Pkg struct {
	*httpsrv.Controller
}

func (c Pkg) DlAction() {

	c.AutoRender = false

	file := filepath.Clean(c.Request.UrlPath())

	if !strings.HasPrefix(file, "/ips/p1/pkg/dl/") {
		c.RenderError(400, "Bad Request")
		return
	}

	fop, err := data.Storage.FoFileOpen("/ips" + file[len("/ips/p1/pkg/dl"):])
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

	var (
		feed = pkgRefresh(q_name)
	)

	for _, set := range feed.items {

		if len(ls.Items) >= limit {
			break
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

	ls.Kind = "PackList"
}

func (c Pkg) EntryAction() {

	var set struct {
		types.TypeMeta
		ipapi.Pack
	}
	defer c.RenderJson(&set)

	var (
		name = c.Params.Value("name")
	)

	if !ipapi.PackNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("400", "Invalid Pack Name")
		return
	}

	feed := pkgRefresh(name)
	if len(feed.items) == 0 {
		set.Error = types.NewErrorMeta("404", "Pack Not Found")
	} else {
		set.Pack = *feed.items[0]
		set.Kind = "Pack"
	}
}
