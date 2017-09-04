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

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

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
		q_name    = c.Params.Get("name")
		q_channel = c.Params.Get("channel")
		q_text    = c.Params.Get("q")
		limit     = int(c.Params.Int64("limit"))
	)

	if !lpapi.PackageNameRe.MatchString(q_name) {
		ls.Error = types.NewErrorMeta("400", "Invalid Package Name")
		return
	}

	if limit < 1 {
		limit = 100
	} else if limit > 200 {
		limit = 200
	}

	rs := data.Data.PoScan("p", []byte{}, []byte{}, 1000)
	if !rs.OK() {
		ls.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	us, _ := iamclient.SessionInstance(c.Session)

	rs.KvEach(func(entry *skv.ResultEntry) int {

		if len(ls.Items) >= limit {
			// TOPO return 0
		}

		var set lpapi.Package
		if err := entry.Decode(&set); err == nil {

			if q_name != "" && q_name != set.Meta.Name {
				return 0
			}

			if q_channel != "" && q_channel != set.Channel {
				return 0
			}

			if q_text != "" && !strings.Contains(set.Meta.Name, q_text) {
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
		set.Error = types.NewErrorMeta("400", "Package ID or Name Not Found")
		return
	} else if name != "" {

		if !lpapi.PackageNameRe.MatchString(name) {
			set.Error = types.NewErrorMeta("400", "Invalid Package Name")
			return
		}

		version := lpapi.PackageVersion{
			Version: types.Version(c.Params.Get("version")),
			Release: types.Version(c.Params.Get("release")),
			Dist:    c.Params.Get("dist"),
			Arch:    c.Params.Get("arch"),
		}
		if err := version.Valid(); err != nil {
			set.Error = types.NewErrorMeta("400", err.Error())
			return
		}

		id = lpapi.PackageMetaId(name, version)
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

	var req lpapi.PackageCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

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

	var (
		chs     = channelList()
		channel *lpapi.PackageChannel
	)
	for _, v := range chs {
		if v.Meta.Name == req.Channel {
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
		set.Error = types.NewErrorMeta("400", err.Error())
		os.Remove(config.Prefix + "/var/tmp/" + req.Name)
		return
	}

	var pack_spec lpapi.PackageSpec
	if err := json.Decode(spec, &pack_spec); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if err := pack_spec.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	pkg_filename := lpapi.PackageFilename(pack_spec.Name, pack_spec.Version)
	if !strings.HasPrefix(req.Name, pkg_filename) {
		set.Error = types.NewErrorMeta("400", "Package Name Error")
		return
	}

	//
	pkg_id := lpapi.PackageMetaId(pack_spec.Name, pack_spec.Version)

	rs := data.Data.PoGet("p", pkg_id)
	if !rs.NotFound() {
		set.Error = types.NewErrorMeta("400", "Package already exists")
		return
	}

	// TODO  /name/version/*
	path := fmt.Sprintf(
		"/%s/%s/%s",
		pack_spec.Name, pack_spec.Version.Version, req.Name,
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
	sum_check := fmt.Sprintf("sha256:%x", filehash.Sum(nil))
	// TODO
	// if req.SumCheck != sum_check {
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
		Version:  pack_spec.Version,
		Size:     fsize,
		SumCheck: sum_check,
		Project:  pack_spec.Project,
		Channel:  channel.Meta.Name,
		Built:    pack_spec.Built,
	}
	for _, v := range pack_spec.Groups {
		pack.Groups.Insert(v)
	}

	if rs = data.Data.PoPut("p", pkg_id, pack, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database")
		return
	}

	var prev_info lpapi.PackageInfo
	name_lower := strings.ToLower(pack_spec.Name)
	if rs := data.Data.PvGet("info/" + name_lower); rs.NotFound() {

		prev_info = lpapi.PackageInfo{
			Meta: types.InnerObjectMeta{
				Name:    pack_spec.Name,
				User:    aksess.User,
				Created: types.MetaTimeNow(),
			},
			LastVersion: pack_spec.Version.Version,
			Project:     pack_spec.Project,
			Groups:      pack_spec.Groups,
			StatNum:     1,
			StatSize:    pack.Size,
		}

	} else if rs.OK() {

		if err := rs.Decode(&prev_info); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}

		switch pack_spec.Version.Version.Compare(&prev_info.LastVersion) {
		case 1:
			prev_info.LastVersion = pack_spec.Version.Version
		}

		//
		prev_info.StatNum++
		prev_info.StatSize += pack.Size

		if prev_info.Project.Description == "" &&
			prev_info.Project.Description != pack_spec.Project.Description {
			prev_info.Project.Description = pack_spec.Project.Description
		}

		if prev_info.Project.Homepage == "" &&
			prev_info.Project.Homepage != pack_spec.Project.Homepage {
			prev_info.Project.Homepage = pack_spec.Project.Homepage
		}

		if len(prev_info.Groups) < 1 &&
			!prev_info.Groups.Equal(pack_spec.Groups) {
			prev_info.Groups = pack_spec.Groups
		}

		if prev_info.Meta.User == "" {
			prev_info.Meta.User = aksess.User
		}

	} else {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	prev_info.Meta.Updated = types.MetaTimeNow()

	if rs := data.Data.PvPut("info/"+name_lower, prev_info, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	channel.StatNum++
	channel.StatSize += pack.Size
	data.Data.PvPut("channel/"+channel.Meta.Name, channel, nil)

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

		currChannel.StatNum--
		prevChannel.StatNum++
		if currChannel.StatNum < 0 {
			currChannel.StatNum = 0
		}
		if prevChannel.StatNum < 0 {
			prevChannel.StatNum = 0
		}

		currChannel.StatSize -= prev.Size
		prevChannel.StatSize += prev.Size
		if currChannel.StatSize < 0 {
			currChannel.StatSize = 0
		}
		if prevChannel.StatSize < 0 {
			prevChannel.StatSize = 0
		}

		prev.Channel = set.Channel
		prev.Meta.Updated = types.MetaTimeNow()

		data.Data.PvPut("channel/"+currChannel.Meta.Name, currChannel, nil)
		data.Data.PvPut("channel/"+prevChannel.Meta.Name, prevChannel, nil)

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
