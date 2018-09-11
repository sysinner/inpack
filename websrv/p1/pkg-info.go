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
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"sort"
	"strings"

	"github.com/eryx/imaging"
	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/data"
)

var (
	pkg_info_icon21_def = []byte(`<svg width="512" height="256" xmlns="http://www.w3.org/2000/svg" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M200 30L255.4256258432 62L255.4256258432 126L200 158L144.5743741568 126L144.5743741568 62L200 30Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.7" stroke="#cccccc" stroke-width="6"></path>
  <path d="M275 137.5L309.641016152 157.5L309.641016152 197.5L275 217.5L240.358983848 197.5L240.358983848 157.5L275 137.5Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.8" stroke="#cccccc" stroke-width="6"></path>
  <path d="M320 75L347.7128129216 91L347.7128129216 123L320 139L292.2871870784 123L292.2871870784 91L320 75Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.9" stroke="#cccccc" stroke-width="6"></path>
</svg>`)
	pkg_info_icon11_def = []byte(`<svg width="256" height="256" xmlns="http://www.w3.org/2000/svg" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M128 32 L211.13843876480001 80L211.13843876480001 176L128 224L44.8615612352 176L44.8615612352 80L128 32Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.7" stroke="#cccccc" stroke-width="10"></path>
</svg>`)
)

type PkgInfo struct {
	*httpsrv.Controller
}

func (c PkgInfo) ListAction() {

	sets := ipapi.PackageInfoList{}
	defer c.RenderJson(&sets)

	var (
		q_text  = c.Params.Get("q")
		q_group = c.Params.Get("group")
		limit   = 200
	)

	rs := data.Data.KvProgScan(ipapi.DataInfoKey(""), ipapi.DataInfoKey(""), 10000)
	if !rs.OK() {
		sets.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	rs.KvEach(func(entry *skv.ResultEntry) int {

		if len(sets.Items) > limit {
			return -1
		}

		var set ipapi.PackageInfo
		if err := entry.Decode(&set); err == nil {

			if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
				return 0
			}

			if q_group != "" && !set.Groups.Has(q_group) {
				return 0
			}

			sets.Items = append(sets.Items, ipapi.PackageInfo{
				Meta: types.InnerObjectMeta{
					Name:    set.Meta.Name,
					Updated: set.Meta.Updated,
				},
				LastVersion: set.LastVersion,
			})
		}

		return 0
	})

	sort.Slice(sets.Items, func(i, j int) bool {
		return sets.Items[i].Meta.Updated > sets.Items[j].Meta.Updated
	})

	sets.Kind = "PackageInfoList"
}

func (c PkgInfo) EntryAction() {

	set := ipapi.PackageInfo{}
	defer c.RenderJson(&set)

	name := c.Params.Get("name")
	if !ipapi.PackageNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("404", "Invalid Package Name")
		return
	}

	rs := data.Data.KvProgGet(ipapi.DataInfoKey(strings.ToLower(name)))
	if !rs.OK() {
		set.Error = types.NewErrorMeta("404", "PackageInfo Not Found")
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = types.NewErrorMeta("404", "PackageInfo Not Found")
		return
	}

	set.Kind = "PackageInfo"
}

func (c PkgInfo) IconAction() {

	c.AutoRender = false

	var (
		name      = c.Params.Get("name")
		icon_type = c.Params.Get("type")
		icon_size = int(c.Params.Int64("size"))
	)

	if !ipapi.PackageNameRe.MatchString(name) {
		return
	}
	name = strings.ToLower(name)

	if icon_type != "11" && icon_type != "21" {
		icon_type = "11"
	}

	if icon_type == "21" && icon_size > 512 {
		icon_size = 512
	} else if icon_size > 256 {
		icon_size = 256
	} else if icon_size < 64 {
		icon_size = 64
	}
	icon_size -= (icon_size % 64)
	icon_sw, icon_sh := icon_size, icon_size
	if icon_type == "21" {
		icon_sh = icon_sh / 2
	}

	var icon ipapi.PackageInfoIcon
	if rs := data.Data.KvProgGet(ipapi.DataIconKey(name, icon_type)); rs.OK() {
		rs.Decode(&icon)
		if len(icon.Data) > 10 {

			if bs, err := base64.StdEncoding.DecodeString(icon.Data); err == nil {

				//
				imgsrc, _, err := image.Decode(bytes.NewReader(bs))
				if err != nil {
					return
				}

				var (
					imgnew = imaging.Thumbnail(imgsrc, icon_sw, icon_sh, imaging.CatmullRom)
					imgbuf bytes.Buffer
				)
				if err = png.Encode(&imgbuf, imgnew); err == nil {
					c.Response.Out.Header().Set("Content-Type", icon.Mime)
					c.Response.Out.Write(imgbuf.Bytes())
					return
				}
			}
		}
	}

	c.Response.Out.Header().Set("Content-Type", "image/svg+xml")
	if icon_type == "21" {
		c.Response.Out.Write(pkg_info_icon21_def)
	} else {
		c.Response.Out.Write(pkg_info_icon11_def)
	}
}
