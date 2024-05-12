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
	"strings"
	"sync"
	"time"

	"github.com/disintegration/imaging"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/data"
)

var (
	pkgInfoIcon21Def = []byte(`<svg width="512" height="256" xmlns="http://www.w3.org/2000/svg" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M200 30L255.4256258432 62L255.4256258432 126L200 158L144.5743741568 126L144.5743741568 62L200 30Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.7" stroke="#cccccc" stroke-width="6"></path>
  <path d="M275 137.5L309.641016152 157.5L309.641016152 197.5L275 217.5L240.358983848 197.5L240.358983848 157.5L275 137.5Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.8" stroke="#cccccc" stroke-width="6"></path>
  <path d="M320 75L347.7128129216 91L347.7128129216 123L320 139L292.2871870784 123L292.2871870784 91L320 75Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.9" stroke="#cccccc" stroke-width="6"></path>
</svg>`)
	pkgInfoIcon11Def = []byte(`<svg width="256" height="256" xmlns="http://www.w3.org/2000/svg" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M128 32 L211.13843876480001 80L211.13843876480001 176L128 224L44.8615612352 176L44.8615612352 80L128 32Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.7" stroke="#cccccc" stroke-width="10"></path>
</svg>`)
)

type pkgInfoIcon struct {
	updated int64
	data    []byte
	icon    *ipapi.PackInfoIcon
}

var (
	pkgInfoIconTTL   = int64(600)
	pkgInfoIconMu    sync.RWMutex
	pkgInfoIconItems = map[string]*pkgInfoIcon{}
)

func pkgInfoIconRefresh(name, typ string) *pkgInfoIcon {

	tn := time.Now().Unix()
	key := string(ipapi.DataInfoIconKey(name, typ))

	pkgInfoIconMu.Lock()
	defer pkgInfoIconMu.Unlock()

	item, ok := pkgInfoIconItems[key]
	if ok && (item.updated+pkgInfoIconTTL) > tn {
		return item
	}

	if !ok {
		item = &pkgInfoIcon{}
		pkgInfoIconItems[key] = item
	}

	var icon ipapi.PackInfoIcon
	if rs := data.Data.NewReader([]byte(key)).Exec(); rs.OK() {
		rs.Item().JsonDecode(&icon)
		if len(icon.Data) > 10 {
			if bs, err := base64.StdEncoding.DecodeString(icon.Data); err == nil && len(bs) > 10 {
				item.icon = &icon
				item.data = bs
			}
		}
	}

	item.updated = tn

	if len(item.data) < 10 {
		item.updated -= (pkgInfoIconTTL - 10)
	} else if item.icon != nil {
		return item
	}

	return nil
}

func (c PkgInfo) IconAction() {

	c.AutoRender = false

	var (
		name      = c.Params.Value("name")
		icon_type = c.Params.Value("type")
		icon_size = int(c.Params.IntValue("size"))
	)

	if !ipapi.PackNameRe.MatchString(name) {
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

	icon := pkgInfoIconRefresh(name, icon_type)
	if icon != nil {

		imgsrc, _, err := image.Decode(bytes.NewReader(icon.data))
		if err == nil {

			var (
				imgnew = imaging.Thumbnail(imgsrc, icon_sw, icon_sh, imaging.CatmullRom)
				imgbuf bytes.Buffer
			)

			if err = png.Encode(&imgbuf, imgnew); err == nil {
				c.Response.Out.Header().Set("Content-Type", icon.icon.Mime)
				c.Response.Out.Write(imgbuf.Bytes())
				return
			}
		}
	}

	c.Response.Out.Header().Set("Content-Type", "image/svg+xml")
	if icon_type == "21" {
		c.Response.Out.Write(pkgInfoIcon21Def)
	} else {
		c.Response.Out.Write(pkgInfoIcon11Def)
	}
}
