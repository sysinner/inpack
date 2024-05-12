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
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"sort"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/hooto/hauth/go/hauth/v1"
	"github.com/hooto/httpsrv"
	iamdata "github.com/hooto/iam/data"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

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

	sets := ipapi.PackInfoList{}
	defer c.RenderJson(&sets)

	var (
		q_text  = c.Params.Value("q")
		q_group = c.Params.Value("group")
		limit   = 200
	)

	rs := data.Data.NewRanger(
		ipapi.DataInfoKey(""), ipapi.DataInfoKey("")).SetLimit(10000).Exec()
	if !rs.OK() {
		sets.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	for _, entry := range rs.Items {

		if len(sets.Items) > limit {
			break
		}

		var set ipapi.PackInfo
		if err := entry.JsonDecode(&set); err != nil {
			continue
		}

		if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
			continue
		}

		if q_group != "" && !set.Groups.Has(q_group) {
			continue
		}

		if us.IsLogin() && (us.UserName == set.Meta.User || us.UserName == "sysadmin") {
			set.OpPerm = ipapi.OpPermRead | ipapi.OpPermWrite
		} else {
			set.OpPerm = ipapi.OpPermRead
		}

		sets.Items = append(sets.Items, set)

	}

	sort.Slice(sets.Items, func(i, j int) bool {
		return sets.Items[i].Meta.Updated > sets.Items[j].Meta.Updated
	})

	sets.Kind = "PackInfoList"
}

func (c PkgInfo) EntryAction() {

	set := ipapi.PackInfo{}
	defer c.RenderJson(&set)

	name := c.Params.Value("name")
	if !ipapi.PackNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("404", "Invalid Pack Name")
		return
	}

	rs := data.Data.NewReader(ipapi.DataInfoKey(name)).Exec()
	if !rs.OK() {
		set.Error = types.NewErrorMeta("404", "PackInfo Not Found")
		return
	}

	if err := rs.Item().JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("404", "PackInfo Not Found")
		return
	}

	set.Kind = "PackInfo"
}

func (c PkgInfo) SetAction() {

	set := ipapi.PackInfo{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if !ipapi.PackNameRe.MatchString(set.Meta.Name) {
		set.Error = types.NewErrorMeta("404", "PackInfo Not Found")
		return
	}

	if rs := data.Data.NewReader(ipapi.DataInfoKey(set.Meta.Name)).Exec(); !rs.OK() {
		set.Error = types.NewErrorMeta("400", "PackInfo Not Found")
		return
	} else {

		var prev ipapi.PackInfo

		if err := rs.Item().JsonDecode(&prev); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}

		us, _ := iamclient.SessionInstance(c.Session)
		if !us.IsLogin() || (us.UserName != prev.Meta.User && us.UserName != "sysadmin") {
			set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
			return
		}

		if prev.Project.Description != set.Project.Description {
			prev.Project.Description = set.Project.Description
		}

		prev.Kind = ""
		if rs := data.Data.NewWriter(ipapi.DataInfoKey(set.Meta.Name), prev).Exec(); !rs.OK() {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}
	}

	set.Kind = "PackInfo"
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

	var icon ipapi.PackInfoIcon
	if rs := data.Data.NewReader(ipapi.DataInfoIconKey(name, icon_type)).Exec(); rs.OK() {
		rs.Item().JsonDecode(&icon)
		if len(icon.Data) > 10 {
			bs, err := base64.StdEncoding.DecodeString(icon.Data)
			if err == nil {

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

func (c PkgInfo) IconSetAction() {

	var (
		set types.TypeMeta
	)
	defer c.RenderJson(&set)

	var req ipapi.PackInfoIconSet
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "BadArgument")
		return
	}

	if !ipapi.PackNameRe.MatchString(req.Name) {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "Invalid Pack Name")
		return
	}

	if len(req.Data) < 10 {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "Invalid Data")
		return
	}

	//
	img64 := strings.SplitAfter(req.Data, ";base64,")
	if len(img64) != 2 {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "Invalid Data")
		return
	}

	//
	av, err := hauth.NewAppValidatorWithHttpRequest(c.Request.Request, iamdata.KeyMgr)
	if err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized "+err.Error())
		return
	}

	if err := av.SignValid(nil); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, err.Error())
		return
	}

	var info ipapi.PackInfo
	if rs := data.Data.NewReader(ipapi.DataInfoKey(req.Name)).Exec(); rs.OK() {
		rs.Item().JsonDecode(&info)
	}
	if info.Meta.Name != req.Name {
		set.Error = types.NewErrorMeta(types.ErrCodeNotFound, "Pack Not Found")
		return
	}

	if info.Meta.User != av.Key.User {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
			"AccessDenied")
		return
	}

	//
	imgreader := base64.NewDecoder(base64.StdEncoding, strings.NewReader(img64[1]))
	imgsrc, _, err := image.Decode(imgreader)
	if err != nil {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, err.Error())
		return
	}

	var imgnew *image.NRGBA
	if req.Type == "11" {
		imgnew = imaging.Thumbnail(imgsrc, 256, 256, imaging.CatmullRom)
	} else if req.Type == "21" {
		imgnew = imaging.Thumbnail(imgsrc, 512, 256, imaging.CatmullRom)
	} else {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "Invalid Type")
		return
	}

	var imgbuf bytes.Buffer
	err = png.Encode(&imgbuf, imgnew)
	if err != nil {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, err.Error())
		return
	}

	icon := ipapi.PackInfoIcon{
		Mime: "image/png",
		Data: base64.StdEncoding.EncodeToString(imgbuf.Bytes()),
	}

	if rs := data.Data.NewWriter(ipapi.DataInfoIconKey(req.Name, req.Type), icon).Exec(); rs.OK() {
		set.Kind = "PackInfo"

		info.Images.Set(req.Type)
		data.Data.NewWriter(ipapi.DataInfoKey(req.Name), info).Exec()

	} else {
		set.Error = types.NewErrorMeta(types.ErrCodeServerError, "Error "+rs.ErrorMessage())
	}
}
