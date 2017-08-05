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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"code.hooto.com/lessos/iam/iamapi"
	"code.hooto.com/lessos/iam/iamclient"
	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/httpsrv"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/lospack/lpapi"
	"code.hooto.com/lessos/lospack/server/config"
	"code.hooto.com/lessos/lospack/server/data"
)

const (
	pkg_spec_name = ".lospack/lospack.json"
)

type Pkg struct {
	*httpsrv.Controller
}

func (c Pkg) DlAction() {

	c.AutoRender = false

	file := filepath.Clean(c.Request.RequestPath)

	if !strings.HasPrefix(file, "lps/v1/pkg/dl/") {
		c.RenderError(400, "Bad Request")
		return
	}

	// TODO auth
	opts := config.Config.IoConnectors.Options("lps_storage")
	if opts == nil {
		c.RenderError(400, "Bad Request")
		return
	}
	fs_dir := opts.Value("data_dir")
	if fs_dir == "" {
		c.RenderError(400, "Bad Request")
		return
	}

	http.ServeFile(
		c.Response.Out,
		c.Request.Request,
		fs_dir+file[len("lps/v1/pkg/dl"):],
	)
}

func (c Pkg) ListAction() {

	ls := lpapi.PackageList{}
	defer c.RenderJson(&ls)

	var (
		qry_pkgname = c.Params.Get("qry_pkgname")
		qry_chanid  = c.Params.Get("qry_chanid")
		qry_text    = c.Params.Get("qry_text")
		limit       = int(c.Params.Int64("limit"))
	)

	if qry_pkgname == "" {
		ls.Error = types.NewErrorMeta(types.ErrCodeBadArgument, "Package Name Not Found")
		return
	}

	if limit < 1 {
		limit = 100
	} else if limit > 200 {
		limit = 200
	}

	rs := data.Data.PoScan("p", []byte{}, []byte{}, 1000)
	if !rs.OK() {
		ls.Error = &types.ErrorMeta{
			Code:    "500",
			Message: rs.Bytex().String(),
		}
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	rs.KvEach(func(entry *skv.ResultEntry) int {

		if len(ls.Items) >= limit {
			// TOPO return 0
		}

		var set lpapi.Package
		if err := entry.Decode(&set); err == nil {

			if qry_pkgname != "" && qry_pkgname != set.Meta.Name {
				return 0
			}

			if qry_chanid != "" && qry_chanid != set.Channel {
				return 0
			}

			if qry_text != "" && !strings.Contains(set.Meta.Name, qry_text) {
				return 0
			}

			if us.IsLogin() && (us.UserName == set.Meta.User || us.UserName == "sysadmin") {
				set.OpPerm = lpapi.OpPermRead | lpapi.OpPermWrite
			} else {
				set.OpPerm = lpapi.OpPermRead
			}

			ls.Items = append(ls.Items, set)
		}

		return 0
	})

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].Meta.Updated > ls.Items[j].Meta.Updated
	})

	if len(ls.Items) > limit {
		ls.Items = ls.Items[:limit]
	}

	ls.Kind = "PackageList"
}

func (c Pkg) EntryAction() {

	var set struct {
		types.TypeMeta
		lpapi.Package
	}
	defer c.RenderJson(&set)

	var (
		id   = c.Params.Get("id")
		name = c.Params.Get("name")
	)

	if id == "" && name == "" {
		set.Error = &types.ErrorMeta{
			Code:    "400",
			Message: "ID or Name can not be null",
		}
		return
	} else if name != "" {

		id = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(
			fmt.Sprintf(
				"%s-%s-%s.%s.%s",
				name, c.Params.Get("version"), c.Params.Get("release"),
				c.Params.Get("dist"), c.Params.Get("arch"),
			),
		))))[:16]
	}

	if id != "" {

		if rs := data.Data.PoGet("p", id); rs.OK() {
			rs.Decode(&set.Package)
		} else if name != "" {
			// TODO
		} else {

		}
	}

	if set.Meta.Name == "" {
		set.Error = types.NewErrorMeta("404", "Package Not Found")
	} else {
		set.Kind = "Package"
	}
}

func (c Pkg) CommitAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
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

	var req lpapi.PackageCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
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
		set.Error = types.NewErrorMeta("400", "Channel Not Found")
		return
	}

	if channel.Meta.User != aksess.User &&
		(channel.Roles == nil || !channel.Roles.Write.MatchAny(aksess.Roles)) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
			"AccessDenied to Channel ("+channel.Meta.Name+")")
		return
	}

	body64 := strings.SplitAfter(req.Data, ";base64,")
	if len(body64) != 2 {
		return
	}
	filedata, err := base64.StdEncoding.DecodeString(body64[1])
	if err != nil {
		set.Error = types.NewErrorMeta("400", "Package Not Found")
		return
	}

	// Save the file to a temporary directory
	fp, err := os.OpenFile(config.Prefix+"/var/tmp/"+req.Name, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}
	defer fp.Close()

	fsize := int64(len(filedata))
	fp.Seek(0, 0)
	fp.Truncate(fsize)
	if _, err = fp.Write(filedata); err != nil {
		set.Error = types.NewErrorMeta("400", "Package Not Found")
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}

	// Export package definition information, checking
	spec, err := exec.Command("/bin/tar", "-Jxvf", config.Prefix+"/var/tmp/"+req.Name, "-O", pkg_spec_name).Output()
	if err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		os.Remove(config.Prefix + "/var/tmp/" + req.Name)
		return
	}

	var pack_spec lpapi.PackageSpec
	if err := json.Decode(spec, &pack_spec); err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}

	//
	pkg_full_name := fmt.Sprintf(
		"%s-%s-%s.%s.%s",
		pack_spec.Name, pack_spec.Version, pack_spec.Release,
		pack_spec.PkgOS, pack_spec.PkgArch,
	)
	if !strings.HasPrefix(req.Name, pkg_full_name) {
		set.Error = types.NewErrorMeta("400", "Package Name Error")
		return
	}

	//
	pn_hash := sha256.New()
	pn_hash.Write([]byte(strings.ToLower(pkg_full_name)))
	pkg_id := fmt.Sprintf("%x", pn_hash.Sum(nil))[:16]

	rs := data.Data.PoGet("p", pkg_id)
	if !rs.NotFound() {
		set.Error = types.NewErrorMeta("400", "Package already exists")
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
			set.Error = types.NewErrorMeta("500", err.Error())
			return
		}

		// if err := os.Chmod(dir, 0755); err != nil {
		//return err
		// }

		// exec.Command("/bin/chown", "action:action", dir).Output()

	} else if !st.IsDir() {
		set.Error = types.NewErrorMeta("500", "Can not create directory, File exists")
		return
	}

	fop, err := data.Storage.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}
	defer fop.Close()

	if _, err := fop.Write(filedata); err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}

	//
	// exec.Command("/bin/mv", config.Prefix +"/var/tmp/"+req.Name, path).Output()
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
			User:    aksess.User,
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

	if rs = data.Data.PoPut("p", pkg_id, pack, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database")
		return
	}

	var prev_info lpapi.PackageInfo
	if rs := data.Data.PvGet("info/" + pack_spec.Name); rs.NotFound() {

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

		if err := rs.Decode(&prev_info); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
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
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	prev_info.Meta.Updated = types.MetaTimeNow()

	if rs := data.Data.PvPut("info/"+pack_spec.Name, prev_info, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	channel.Packages++
	data.Data.PvPut("channel/"+channel.Meta.ID, channel, nil)

	set.Kind = "PackageCommit"
}

func (c Pkg) SetAction() {

	var set struct {
		types.TypeMeta
		lpapi.Package
	}
	defer c.RenderJson(&set)

	//
	if err := c.Request.JsonDecode(&set.Package); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if set.Meta.ID == "" { // TODO
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	rs := data.Data.PoGet("p", set.Meta.ID)
	if !rs.OK() {
		set.Error = types.NewErrorMeta("400", "No Package Found")
		return
	}

	var prev lpapi.Package
	if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)
	if !us.IsLogin() || (us.UserName != prev.Meta.User && us.UserName != "sysadmin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if prev.Channel != set.Channel {

		var (
			prevChannel lpapi.PackageChannel
			currChannel lpapi.PackageChannel
		)

		if rs := data.Data.PvGet("channel/" + set.Channel); !rs.OK() ||
			rs.Decode(&prevChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}

		if rs := data.Data.PvGet("channel/" + prev.Channel); !rs.OK() ||
			rs.Decode(&currChannel) != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
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

		data.Data.PvPut("channel/"+currChannel.Meta.ID, currChannel, nil)
		data.Data.PvPut("channel/"+prevChannel.Meta.ID, prevChannel, nil)

		data.Data.PoPut("p", set.Meta.ID, prev, nil)
	}

	set.Kind = "Package"
}

func channelList() []lpapi.PackageChannel {

	sets := []lpapi.PackageChannel{}

	rs := data.Data.PvScan("channel/", "", "", 100)
	if !rs.OK() {
		return sets
	}

	rs.KvEach(func(entry *skv.ResultEntry) int {

		var set lpapi.PackageChannel
		if err := entry.Decode(&set); err == nil {
			sets = append(sets, set)
		}

		return 0
	})

	return sets
}
