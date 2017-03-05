// Copyright 2015 lessOS.com, All rights reserved.
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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"code.hooto.com/lessos/lospack/server/data"
	"code.hooto.com/lessos/lospack/lpapi"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/httpsrv"
	"github.com/lessos/lessgo/types"
)

const (
	pkg_spec_name = "lospack.json"
)

type Pkg struct {
	*httpsrv.Controller
}

func (c Pkg) ListAction() {

	ls := lpapi.PackageList{}
	defer c.RenderJson(&ls)

	var (
		qry_pkgname = c.Params.Get("qry_pkgname")
		qry_chanid  = c.Params.Get("qry_chanid")
		qry_text    = c.Params.Get("qry_text")
		limit       = 100
	)

	rs := data.Data.ObjectScan("p/", "", "", 1000)
	if !rs.OK() {
		ls.Error = &types.ErrorMeta{
			Code:    "500",
			Message: rs.Status,
		}
		return
	}

	rs.KvEach(func(k, v types.Bytex) {

		if len(ls.Items) >= limit {
			return
		}

		var set lpapi.Package
		if err := v.JsonDecode(&set); err == nil {

			if qry_pkgname != "" && qry_pkgname != set.Meta.Name {
				return
			}

			if qry_chanid != "" && qry_chanid != set.Channel {
				return
			}

			if qry_text != "" && !strings.Contains(set.Meta.Name, qry_text) {
				return
			}

			ls.Items = append(ls.Items, set)
		}
	})

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].Meta.Updated > ls.Items[j].Meta.Updated
	})

	ls.Kind = "PackageList"
}

func (c Pkg) EntryAction() {

	set := lpapi.Package{}
	defer c.RenderJson(&set)

	var (
		id   = c.Params.Get("id")
		name = c.Params.Get("name")
		// version = c.Params.Get("version")
		// release = c.Params.Get("release")
		// dist    = c.Params.Get("dist")
		// arch    = c.Params.Get("arch")
	)

	if id == "" && name == "" {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "ID or Name can not be null",
		}
		return
	}

	if id != "" {

		if rs := data.Data.ObjectGet("p/" + id); rs.OK() {
			rs.JsonDecode(&set)
		} else if name != "" {
			// TODO
		} else {

		}
	}

	if set.Meta.Name == "" {
		set.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Package Not Found",
		}
		return
	}

	set.Kind = "Package"
}

func (c Pkg) CommitAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	var req lpapi.PackageCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: err.Error(),
		}
		return
	}

	var (
		chs     = channelList()
		channel *lpapi.PackageChannel
	)
	for _, v := range chs {
		if v.Meta.ID == req.Channel ||
			v.Meta.Name == req.Channel {
			channel = &v
			break
		}
	}
	if channel == nil {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Channel Not Found",
		}
		return
	}

	body64 := strings.SplitAfter(req.Data, ";base64,")
	if len(body64) != 2 {
		return
	}
	filedata, err := base64.StdEncoding.DecodeString(body64[1])
	if err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: err.Error(),
		}
		return
	}

	// Save the file to a temporary directory
	fp, err := os.OpenFile("/tmp/"+req.Name, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}
	defer fp.Close()

	fsize := int64(len(filedata))
	fp.Seek(0, 0)
	fp.Truncate(fsize)
	if _, err = fp.Write(filedata); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}

	// Export package definition information, checking
	spec, err := exec.Command("/bin/tar", "-Jxvf", "/tmp/"+req.Name, "-O", pkg_spec_name).Output()
	if err != nil {

		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}

		os.Remove("/tmp/" + req.Name)
		return
	}

	var pack_spec lpapi.PackageSpec
	if err := json.Decode(spec, &pack_spec); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}

	//
	pkg_full_name := fmt.Sprintf(
		"%s-%s-%s.%s.%s",
		pack_spec.Name, pack_spec.Version, pack_spec.Release,
		pack_spec.PkgOS, pack_spec.PkgArch,
	)
	if !strings.HasPrefix(req.Name, pkg_full_name) {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Package Name Error",
		}
		return
	}

	//
	pn_hash := sha256.New()
	pn_hash.Write([]byte(strings.ToLower(pkg_full_name)))
	pkg_id := fmt.Sprintf("%x", pn_hash.Sum(nil))[:16]

	pkgpath := fmt.Sprintf("p/%s", pkg_id)

	rs := data.Data.ObjectGet(pkgpath)
	if !rs.NotFound() {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Package already exists",
		}
		return
	}

	// TODO  /name/version/*
	path := fmt.Sprintf(
		"/%s/%s/%s",
		pack_spec.Name, pack_spec.Version, req.Name,
	)
	dir := filepath.Dir(path)
	if st, err := data.Storage.Stat(dir); os.IsNotExist(err) {

		if err = data.Storage.MkdirAll(dir, 0755); err != nil {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: err.Error(),
			}
			return
		}

		// if err := os.Chmod(dir, 0755); err != nil {
		//return err
		// }

		// exec.Command("/bin/chown", "action:action", dir).Output()

	} else if !st.IsDir() {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Can not create directory, File exists",
		}
		return
	}

	fop, err := data.Storage.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}
	defer fop.Close()

	if _, err := fop.Write(filedata); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}

	//
	// exec.Command("/bin/mv", "/tmp/"+req.Name, path).Output()
	// exec.Command("/bin/chmod", "0644", path).Output()
	// exec.Command("/bin/chown", "action:action", path).Output()

	filehash := sha256.New()
	// io.Copy(filehash, fp)
	filehash.Write(filedata)
	pkg_sum := fmt.Sprintf("sha256:%x", filehash.Sum(nil))
	// TODO
	// if req.SumCheck != pkg_sum {
	// 	set.Error = &types.ErrorMeta{
	// 		Code:    "400",
	// 		Message: "Error on Sum Check",
	// 	}
	// 	return
	// }

	// package file
	pack := lpapi.Package{
		Meta: types.InnerObjectMeta{
			ID:      pkg_id,
			Name:    pack_spec.Name,
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Version:     pack_spec.Version,
		Release:     pack_spec.Release,
		PkgOS:       pack_spec.PkgOS,
		PkgArch:     pack_spec.PkgArch,
		PkgSize:     fsize,
		PkgSum:      pkg_sum,
		Keywords:    pack_spec.Keywords,
		Description: pack_spec.Description,
		Vendor:      pack_spec.Vendor,
		License:     pack_spec.License,
		Channel:     channel.Meta.ID,
		Built:       pack_spec.Created,
	}
	for _, v := range pack_spec.Groups {
		pack.Groups.Insert(v)
	}

	if rs = data.Data.ObjectPut(pkgpath, pack, nil); !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Can not write to database",
		}
		return
	}

	var prev_info lpapi.PackageInfo
	if rs := data.Data.ObjectGet("info/" + pack_spec.Name); rs.NotFound() {

		prev_info = lpapi.PackageInfo{
			Meta: types.InnerObjectMeta{
				Name:    pack_spec.Name,
				Created: types.MetaTimeNow(),
			},
			LastVersion: pack_spec.Version,
			LastRelease: pack_spec.Release,
			Description: pack_spec.Description,
			Groups:      pack_spec.Groups,
			PkgNum:      1,
			Homepage:    pack_spec.Homepage,
		}

	} else if rs.OK() {

		if err := rs.JsonDecode(&prev_info); err != nil {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Server Error",
			}
			return
		}

		switch pack_spec.Version.Compare(&prev_info.LastVersion) {

		case 1:
			prev_info.LastVersion = pack_spec.Version
			prev_info.LastRelease = pack_spec.Release

		case 0:
			if pack_spec.Release.Compare(&prev_info.LastRelease) > 0 {
				prev_info.LastRelease = pack_spec.Release
			}
		}

		if prev_info.Description == "" &&
			prev_info.Description != pack_spec.Description {
			prev_info.Description = pack_spec.Description
		}

		//
		prev_info.PkgNum++

		if prev_info.Homepage == "" &&
			prev_info.Homepage != pack_spec.Homepage {
			prev_info.Homepage = pack_spec.Homepage
		}

		if len(prev_info.Groups) < 1 &&
			!prev_info.Groups.Equal(pack_spec.Groups) {
			prev_info.Groups = pack_spec.Groups
		}

	} else {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Server Error",
		}
		return
	}

	prev_info.Meta.Updated = types.MetaTimeNow()

	if rs := data.Data.ObjectPut("info/"+pack_spec.Name, prev_info, nil); !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Server Error",
		}
		return
	}

	set.Kind = "PackageCommit"
}

func (c Pkg) SetAction() {

	set := lpapi.Package{}

	defer c.RenderJson(&set)

	//
	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Bad Request",
		}
		return
	}

	if set.Meta.ID == "" { // TODO
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "Bad Request",
		}
		return
	}

	rs := data.Data.ObjectGet("p/" + set.Meta.ID)
	if !rs.OK() {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "No Package Found",
		}
		return
	}

	var prev lpapi.Package
	if err := rs.JsonDecode(&prev); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: "Server Error",
		}
		return
	}

	if prev.Channel != set.Channel {

		var (
			prevChannel lpapi.PackageChannel
			currChannel lpapi.PackageChannel
		)

		if rs := data.Data.ObjectGet("channel/" + set.Channel); !rs.OK() ||
			rs.JsonDecode(&prevChannel) != nil {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Server Error",
			}
			return
		}

		if rs := data.Data.ObjectGet("channel/" + prev.Channel); !rs.OK() ||
			rs.JsonDecode(&currChannel) != nil {
			set.Error = &types.ErrorMeta{
				Code:    "500",
				Message: "Server Error",
			}
			return
		}

		currChannel.Packages--
		prevChannel.Packages++

		if currChannel.Packages < 0 {
			currChannel.Packages = 0
		}

		if prevChannel.Packages < 0 {
			prevChannel.Packages = 0
		}

		prev.Channel = set.Channel
		prev.Meta.Updated = types.MetaTimeNow()

		data.Data.ObjectPut("channel/"+currChannel.Meta.ID, currChannel, nil)
		data.Data.ObjectPut("channel/"+prevChannel.Meta.ID, prevChannel, nil)

		data.Data.ObjectPut("p/"+set.Meta.ID, prev, nil)
	}

	set.Kind = "Package"
}

func channelList() []lpapi.PackageChannel {

	sets := []lpapi.PackageChannel{}

	rs := data.Data.ObjectScan("channel/", "", "", 100)
	if !rs.OK() {
		return sets
	}

	rs.KvEach(func(key, value types.Bytex) {

		var set lpapi.PackageChannel
		if err := value.JsonDecode(&set); err == nil {
			sets = append(sets, set)
		}
	})

	return sets
}
