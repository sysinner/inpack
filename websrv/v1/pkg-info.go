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

type PkgInfo struct {
	*httpsrv.Controller
}

func (c PkgInfo) ListAction() {

	sets := lpapi.PackageInfoList{}
	defer c.RenderJson(&sets)

	var (
		qry_text = c.Params.Get("qry_text")
		limit    = 100
	)

	rs := data.Data.PvScan("info/", "", "", 10000)
	if !rs.OK() {
		sets.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Server Error",
		}
		return
	}

	rs.KvEach(func(entry *skv.ResultEntry) int {

		if len(sets.Items) > limit {
			return -1
		}

		var set lpapi.PackageInfo
		if err := entry.Decode(&set); err == nil {

			if qry_text != "" && !strings.Contains(set.Meta.Name, qry_text) {
				return 0
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

	if c.Params.Get("name") == "" {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "PackageInfo Not Found",
		}
		return
	}

	rs := data.Data.PvGet("info/" + c.Params.Get("name"))
	if !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "PackageInfo Not Found",
		}
		return
	}

	if err := rs.Decode(&set); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "PackageInfo Not Found",
		}
		return
	}

	set.Kind = "PackageInfo"
}

func (c PkgInfo) SetAction() {

	set := lpapi.PackageInfo{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Bad Request",
		}
		return
	}

	if rs := data.Data.PvGet("info/" + set.Meta.Name); !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "PackageInfo Not Found",
		}
		return
	} else {

		var prev lpapi.PackageInfo

		if err := rs.Decode(&prev); err != nil {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Server Error",
			}
			return
		}

		if prev.Description != set.Description {
			prev.Description = set.Description
		}

		prev.Kind = ""
		if rs := data.Data.PvPut("info/"+set.Meta.Name, prev, nil); !rs.OK() {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Server Error",
			}
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
	)
	if ico_type != "11" && ico_type != "21" {
		return
	}

	var ico lpapi.PackageInfoIco
	if rs := data.Data.PvGet("ico/" + name + "/" + ico_type); rs.OK() {
		rs.Decode(&ico)
		if len(ico.Data) > 10 {
			bs, err := base64.StdEncoding.DecodeString(ico.Data)
			if err == nil {
				c.Response.Out.Header().Set("Content-Type", ico.Mime)
				c.Response.Out.Write(bs)
			}
		}
	}
}

func (c PkgInfo) IcoSetAction() {

	var (
		set types.TypeMeta
	)
	defer c.RenderJson(&set)

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

	var req lpapi.PackageInfoIcoSet
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "BadArgument")
		return
	}

	if req.Name == "" || len(req.Data) < 10 {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "BadArgument")
		return
	}

	//
	img64 := strings.SplitAfter(req.Data, ";base64,")
	if len(img64) != 2 {
		set.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "BadArgument")
		return
	}

	var info lpapi.PackageInfo
	if rs := data.Data.PvGet("info/" + req.Name); rs.OK() {
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

	if rs := data.Data.PvPut("ico/"+req.Name+"/"+req.Type, ico, &skv.PathWriteOptions{
		Force: true,
	}); rs.OK() {
		set.Kind = "PackageInfo"
	} else {
		set.Error = types.NewErrorMeta(types.ErrCodeServerError, "Error "+rs.Bytex().String())
	}
}
