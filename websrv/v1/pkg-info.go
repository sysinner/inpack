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
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"sort"
	"strings"

	"code.hooto.com/lessos/iam/iamapi"
	"code.hooto.com/lessos/iam/iamclient"
	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/eryx/imaging"
	"github.com/lessos/lessgo/httpsrv"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/lospack/lpapi"
	"code.hooto.com/lessos/lospack/server/config"
	"code.hooto.com/lessos/lospack/server/data"
)

var (
	pkg_info_ico21_def = []byte(`<svg width="512" height="256" xmlns="http://www.w3.org/2000/svg" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M200 30L255.4256258432 62L255.4256258432 126L200 158L144.5743741568 126L144.5743741568 62L200 30Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.7" stroke="#cccccc" stroke-width="6"></path>
  <path d="M275 137.5L309.641016152 157.5L309.641016152 197.5L275 217.5L240.358983848 197.5L240.358983848 157.5L275 137.5Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.8" stroke="#cccccc" stroke-width="6"></path>
  <path d="M320 75L347.7128129216 91L347.7128129216 123L320 139L292.2871870784 123L292.2871870784 91L320 75Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.9" stroke="#cccccc" stroke-width="6"></path>
</svg>`)
	pkg_info_ico11_def = []byte(`<svg width="256" height="256" xmlns="http://www.w3.org/2000/svg" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M128 32 L211.13843876480001 80L211.13843876480001 176L128 224L44.8615612352 176L44.8615612352 80L128 32Z " fill-opacity="0" fill="#ffffff" stroke-opacity="0.7" stroke="#cccccc" stroke-width="10"></path>
</svg>`)
)

type PkgInfo struct {
	*httpsrv.Controller
}

func (c PkgInfo) ListAction() {

	sets := lpapi.PackageInfoList{}
	defer c.RenderJson(&sets)

	var (
		q_text  = c.Params.Get("q")
		q_group = c.Params.Get("group")
		limit   = 100
	)

	rs := data.Data.PvScan("info/", "", "", 10000)
	if !rs.OK() {
		sets.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	rs.KvEach(func(entry *skv.ResultEntry) int {

		if len(sets.Items) > limit {
			return -1
		}

		var set lpapi.PackageInfo
		if err := entry.Decode(&set); err == nil {

			if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
				return 0
			}

			if q_group != "" && !set.Groups.Has(q_group) {
				return 0
			}

			if us.IsLogin() && (us.UserName == set.Meta.User || us.UserName == "sysadmin") {
				set.OpPerm = lpapi.OpPermRead | lpapi.OpPermWrite
			} else {
				set.OpPerm = lpapi.OpPermRead
			}

			sets.Items = append(sets.Items, set)
		}

		return 0
	})

	sort.Slice(sets.Items, func(i, j int) bool {
		return sets.Items[i].Meta.Updated > sets.Items[j].Meta.Updated
	})

	sets.Kind = "PackageInfoList"
}

func (c PkgInfo) EntryAction() {

	set := lpapi.PackageInfo{}
	defer c.RenderJson(&set)

	name := c.Params.Get("name")
	if !lpapi.PackageNameRe.MatchString(name) {
		set.Error = types.NewErrorMeta("404", "Invalid Package Name")
		return
	}

	rs := data.Data.PvGet("info/" + strings.ToLower(name))
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

func (c PkgInfo) SetAction() {

	set := lpapi.PackageInfo{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if !lpapi.PackageNameRe.MatchString(set.Meta.Name) {
		set.Error = types.NewErrorMeta("404", "PackageInfo Not Found")
		return
	}

	if rs := data.Data.PvGet("info/" + strings.ToLower(set.Meta.Name)); !rs.OK() {
		set.Error = types.NewErrorMeta("400", "PackageInfo Not Found")
		return
	} else {

		var prev lpapi.PackageInfo

		if err := rs.Decode(&prev); err != nil {
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
		if rs := data.Data.PvPut("info/"+strings.ToLower(set.Meta.Name), prev, nil); !rs.OK() {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}
	}

	set.Kind = "PackageInfo"
}

func (c PkgInfo) IcoAction() {

	c.AutoRender = false

	var (
		name     = c.Params.Get("name")
		ico_type = c.Params.Get("type")
		ico_size = int(c.Params.Int64("size"))
	)

	if !lpapi.PackageNameRe.MatchString(name) {
		return
	}
	name = strings.ToLower(name)

	if ico_type != "11" && ico_type != "21" {
		ico_type = "11"
	}

	if ico_type == "21" && ico_size > 512 {
		ico_size = 512
	} else if ico_size > 256 {
		ico_size = 256
	} else if ico_size < 64 {
		ico_size = 64
	}
	ico_size -= (ico_size % 64)
	ico_sw, ico_sh := ico_size, ico_size
	if ico_type == "21" {
		ico_sh = ico_sh / 2
	}

	var ico lpapi.PackageInfoIco
	if rs := data.Data.PvGet("ico/" + name + "/" + ico_type); rs.OK() {
		rs.Decode(&ico)
		if len(ico.Data) > 10 {
			bs, err := base64.StdEncoding.DecodeString(ico.Data)
			if err == nil {

				//
				imgsrc, _, err := image.Decode(bytes.NewReader(bs))
				if err != nil {
					return
				}

				var (
					imgnew = imaging.Thumbnail(imgsrc, ico_sw, ico_sh, imaging.CatmullRom)
					imgbuf bytes.Buffer
				)
				if err = png.Encode(&imgbuf, imgnew); err == nil {
					c.Response.Out.Header().Set("Content-Type", ico.Mime)
					c.Response.Out.Write(imgbuf.Bytes())
					return
				}
			}
		}
	}

	c.Response.Out.Header().Set("Content-Type", "image/svg+xml")
	if ico_type == "21" {
		c.Response.Out.Write(pkg_info_ico21_def)
	} else {
		c.Response.Out.Write(pkg_info_ico11_def)
	}
}

func (c PkgInfo) IcoSetAction() {

	var (
		set types.TypeMeta
	)
	defer c.RenderJson(&set)

	var req lpapi.PackageInfoIcoSet
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "BadArgument")
		return
	}

	if !lpapi.PackageNameRe.MatchString(req.Name) {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "Invalid Package Name")
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

	{
		aka, err := iamapi.AccessKeyAuthDecode(c.Session.AuthToken(""))
		if err != nil {
			set.Error = types.NewErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized")
			return
		}

		app_aka, err := config.Config.AccessKeyAuth()
		if err != nil {
			set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, err.Error())
			return
		}

		aksess, err := iamclient.AccessKeySession(app_aka, aka)
		if err != nil {
			set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, err.Error())
			return
		}

		if err := iamclient.AccessKeyAuthValid(aka, aksess.SecretKey); err != nil {
			set.Error = types.NewErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized")
			return
		}
	}

	var info lpapi.PackageInfo
	if rs := data.Data.PvGet("info/" + strings.ToLower(req.Name)); rs.OK() {
		rs.Decode(&info)
	}
	if info.Meta.Name != req.Name {
		set.Error = types.NewErrorMeta(types.ErrCodeNotFound, "Package Not Found")
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

	ico := lpapi.PackageInfoIco{
		Mime: "image/png",
		Data: base64.StdEncoding.EncodeToString(imgbuf.Bytes()),
	}

	if rs := data.Data.PvPut("ico/"+strings.ToLower(req.Name)+"/"+req.Type, ico, &skv.PathWriteOptions{
		Force: true,
	}); rs.OK() {
		set.Kind = "PackageInfo"

		info.Images.Set(req.Type)
		data.Data.PvPut("info/"+req.Name, info, &skv.PathWriteOptions{
			Force: true,
		})

	} else {
		set.Error = types.NewErrorMeta(types.ErrCodeServerError, "Error "+rs.Bytex().String())
	}
}
