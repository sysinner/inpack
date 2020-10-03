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
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hooto/hauth/go/hauth/v1"
	"github.com/hooto/hlog4g/hlog"
	iamdata "github.com/hooto/iam/data"
	"github.com/hooto/iam/iamapi"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/config"
	"github.com/sysinner/inpack/server/data"
)

const (
	pkg_spec_name       = ".inpack/inpack.json"
	pkg_size_max  int64 = 200 * 1024 * 1024 // 200MB
)

var (
	mpp_mu     = locker.NewHashPool(runtime.NumCPU())
	cmd_shasum = "/usr/bin/sha256sum"
)

func init() {

	if path, err := exec.LookPath("sha256sum"); err == nil {
		cmd_shasum = path
	}
}

func (c Pkg) CommitAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	var req ipapi.PackCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if req.Channel == "" {
		req.Channel = "beta"
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

	var (
		chs     = channelList()
		channel *ipapi.PackChannel
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

	if channel.Meta.User != av.Key.User {
		// (channel.Roles == nil || !channel.Roles.Write.MatchAny(av.Key.Roles)) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
			"AccessDenied to Channel ("+channel.Meta.Name+")")
		return
	}
	if err := av.Allow(hauth.NewScopeFilter("app", config.Config.InstanceId)); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
			"AccessDenied to Scope(app : "+config.Config.InstanceId+")")
		return
	}

	if req.Size > pkg_size_max {
		set.Error = types.NewErrorMeta("400",
			fmt.Sprintf("the max size of Pack can not more than %d", pkg_size_max))
		return
	}

	body64 := strings.SplitAfter(req.Data, ";base64,")
	if len(body64) != 2 {
		return
	}
	filedata, err := base64.StdEncoding.DecodeString(body64[1])
	if err != nil {
		set.Error = types.NewErrorMeta("400", "Pack Not Found")
		return
	}

	tmp_file := config.Prefix + "/var/tmp/" + req.Name

	// Save the file to a temporary directory
	fp, err := os.OpenFile(tmp_file, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}
	defer fp.Close()

	fsize := int64(len(filedata))

	fp.Seek(0, 0)
	fp.Truncate(fsize)
	if _, err = fp.Write(filedata); err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}

	// Export package definition information, checking
	spec, err := exec.Command("/bin/tar", "-Jxvf", tmp_file, "-O", pkg_spec_name).Output()
	if err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		os.Remove(tmp_file)
		return
	}

	var packBuild ipapi.PackBuild
	if err := json.Decode(spec, &packBuild); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if err := packBuild.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	pkg_filename := ipapi.PackFilename(packBuild.Name, packBuild.Version)
	if !strings.HasPrefix(req.Name, pkg_filename) {
		set.Error = types.NewErrorMeta("400", "Pack Name Error")
		return
	}

	//
	pkg_id := ipapi.PackFilenameKey(packBuild.Name, packBuild.Version)

	rs := data.Data.NewReader(ipapi.DataPackKey(pkg_id)).Query()
	if !rs.NotFound() {
		set.Error = types.NewErrorMeta("400", "Pack already exists")
		return
	}

	// TODO  /name/version/*
	path := fmt.Sprintf(
		"/ips/%s/%s/%s",
		packBuild.Name, packBuild.Version.Version, req.Name,
	)
	// dir := filepath.Dir(path)
	// if st, err := data.Storage.Stat(dir); os.IsNotExist(err) {

	// 	if err = data.Storage.MkdirAll(dir, 0755); err != nil {
	// 		set.Error = types.NewErrorMeta("500", err.Error())
	// 		return
	// 	}

	// 	// if err := os.Chmod(dir, 0755); err != nil {
	// 	//return err
	// 	// }

	// 	// exec.Command("/bin/chown", "action:action", dir).Output()

	// } else if !st.IsDir() {
	// 	set.Error = types.NewErrorMeta("500", "Can not create directory, File exists")
	// 	return
	// }

	// fop, err := data.Storage.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	// if err != nil {
	// 	set.Error = types.NewErrorMeta("500", err.Error())
	// 	return
	// }
	// defer fop.Close()

	// if _, err := fop.Write(filedata); err != nil {
	// 	set.Error = types.NewErrorMeta("500", err.Error())
	// 	return
	// }

	//
	// exec.Command("/bin/mv", config.Prefix +"/var/tmp/"+req.Name, path).Output()
	// exec.Command("/bin/chmod", "0644", path).Output()
	// exec.Command("/bin/chown", "action:action", path).Output()

	// filehash := sha256.New()
	// // io.Copy(filehash, fp)
	// filehash.Write(filedata)
	// sum_check := fmt.Sprintf("sha256:%x", filehash.Sum(nil))
	sum_check := ipm_entry_sync_sumcheck(tmp_file)

	// TODO
	// if req.SumCheck != sum_check {
	// 	set.Error = &types.ErrorMeta{
	// 		Code:    "400",
	// 		Message: "Error on Sum Check",
	// 	}
	// 	return
	// }

	if rs := data.Storage.FoFilePut(tmp_file, path); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.String())
		return
	}

	// package file
	pack := ipapi.Pack{
		Meta: types.InnerObjectMeta{
			ID:      pkg_id,
			Name:    packBuild.Name,
			User:    av.Key.User,
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Version:  packBuild.Version,
		Size:     fsize,
		SumCheck: sum_check,
		Project:  packBuild.Project,
		Channel:  channel.Meta.Name,
		Built:    packBuild.Built,
	}
	for _, v := range packBuild.Groups {
		pack.Groups.Set(v)
	}

	if rs := data.Data.NewWriter(ipapi.DataPackKey(pkg_id), pack).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database")
		return
	}

	var prev_info ipapi.PackInfo
	name_lower := strings.ToLower(packBuild.Name)
	if rs := data.Data.NewReader(ipapi.DataInfoKey(name_lower)).Query(); rs.NotFound() {

		prev_info = ipapi.PackInfo{
			Meta: types.InnerObjectMeta{
				Name:    packBuild.Name,
				User:    av.Key.User,
				Created: types.MetaTimeNow(),
			},
			LastVersion: packBuild.Version.Version,
			Project:     packBuild.Project,
			Groups:      packBuild.Groups,
			StatNum:     1,
			StatSize:    pack.Size,
		}

	} else if rs.OK() {

		if err := rs.Decode(&prev_info); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}

		switch packBuild.Version.Version.Compare(prev_info.LastVersion) {
		case 1:
			prev_info.LastVersion = packBuild.Version.Version
		}

		//
		prev_info.StatNum++
		prev_info.StatSize += pack.Size

		if prev_info.Project.Description == "" &&
			prev_info.Project.Description != packBuild.Project.Description {
			prev_info.Project.Description = packBuild.Project.Description
		}

		if prev_info.Project.Homepage == "" &&
			prev_info.Project.Homepage != packBuild.Project.Homepage {
			prev_info.Project.Homepage = packBuild.Project.Homepage
		}

		if len(prev_info.Groups) < 1 &&
			!prev_info.Groups.Equal(packBuild.Groups) {
			prev_info.Groups = packBuild.Groups
		}

		if prev_info.Meta.User == "" {
			prev_info.Meta.User = av.Key.User
		}

	} else {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	prev_info.Meta.Updated = types.MetaTimeNow()

	if rs := data.Data.NewWriter(ipapi.DataInfoKey(name_lower), prev_info).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	channel.StatNum++
	channel.StatSize += pack.Size
	data.Data.NewWriter(ipapi.DataChannelKey(channel.Meta.Name), channel).Commit()

	set.Kind = "PackCommit"
}

func (c Pkg) MultipartCommitAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	var req ipapi.PackMultipartCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if req.Channel == "" {
		req.Channel = "beta"
	}

	av, err := hauth.NewAppValidatorWithHttpRequest(c.Request.Request, iamdata.KeyMgr)
	if err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized "+err.Error())
		return
	}

	if err := av.SignValid(nil); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, err.Error())
		return
	}

	var (
		chs     = channelList()
		channel *ipapi.PackChannel
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

	if channel.Meta.User != av.Key.User {
		// (channel.Roles == nil || !channel.Roles.Write.MatchAny(ak.Key.Roles)) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
			"AccessDenied to Channel ("+channel.Meta.Name+")")
		return
	}
	if err := av.Allow(hauth.NewScopeFilter("app", config.Config.InstanceId)); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
			"AccessDenied to Scope(app : "+config.Config.InstanceId+")")
		return
	}

	if req.Size > pkg_size_max {
		set.Error = types.NewErrorMeta("400", fmt.Sprintf("the max size of Pack can not more than %d", pkg_size_max))
		return
	}

	body64 := strings.SplitAfter(req.BlockData, ";base64,")
	if len(body64) != 2 {
		return
	}
	block_data, err := base64.StdEncoding.DecodeString(body64[1])
	if err != nil {
		set.Error = types.NewErrorMeta("400", "Pack Not Found")
		return
	}

	fsize := int64(len(block_data))
	if req.BlockOffset+fsize > req.Size {
		set.Error = types.NewErrorMeta("400", "Invalid Pack Offset, Size or Data Set")
		return
	}

	if req.BlockCrc32 != crc32.ChecksumIEEE(block_data) {
		set.Error = types.NewErrorMeta("400", "Invalid Pack BlockCrc32 SumCheck")
		return
	}

	//
	if err := ipapi.PackNameValid(req.Name); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	//
	if err := req.Version.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	//
	pkg_id := ipapi.PackFilenameKey(req.Name, req.Version)
	pkg_name := ipapi.PackFilename(req.Name, req.Version)

	rs := data.Data.NewReader(ipapi.DataPackKey(pkg_id)).Query()
	if !rs.NotFound() {
		set.Error = types.NewErrorMeta("400", "Pack already exists")
		return
	}

	mpp_mu.Lock([]byte(req.Name))
	defer mpp_mu.Unlock([]byte(req.Name))

	// Save the file to a temporary directory
	tmp_file := config.Prefix + "/var/tmp/" + pkg_name + ".txz"
	if req.BlockOffset == 0 {
		os.Remove(tmp_file)
	}
	fp, err := os.OpenFile(tmp_file, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		set.Error = types.NewErrorMeta("500", err.Error())
		return
	}
	defer func() {
		fp.Close()
		if req.BlockOffset+fsize >= req.Size {
			os.Remove(tmp_file)
		}
	}()

	if _, err = fp.WriteAt(block_data, req.BlockOffset); err != nil {
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}

	if req.BlockOffset+fsize < req.Size {
		set.Kind = "PackMultipartCommit"
		return
	}

	// Export package definition information, checking
	spec, err := exec.Command("/bin/tar", "-Jxvf", tmp_file, "-O", pkg_spec_name).Output()
	if err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		os.Remove(tmp_file)
		return
	}

	var packBuild ipapi.PackBuild
	if err := json.Decode(spec, &packBuild); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if err := packBuild.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if packBuild.Version.Compare(req.Version) != 0 {
		set.Error = types.NewErrorMeta("400", "Invalid Pack Version Set")
		return
	}

	if pkg_name != ipapi.PackFilename(packBuild.Name, packBuild.Version) {
		set.Error = types.NewErrorMeta("400", "Pack Name Error")
		return
	}

	// TODO  /name/version/*
	path := fmt.Sprintf(
		"/ips/%s/%s/%s.txz",
		packBuild.Name, packBuild.Version.Version, pkg_name,
	)
	// dir := filepath.Dir(path)
	// if st, err := data.Storage.Stat(dir); os.IsNotExist(err) {

	// 	if err = data.Storage.MkdirAll(dir, 0755); err != nil {
	// 		set.Error = types.NewErrorMeta("500", err.Error())
	// 		return
	// 	}

	// } else if !st.IsDir() {
	// 	set.Error = types.NewErrorMeta("500", "Can not create directory, File exists")
	// 	return
	// }

	// fop, err := data.Storage.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	// if err != nil {
	// 	set.Error = types.NewErrorMeta("500", err.Error())
	// 	return
	// }
	// defer fop.Close()
	// fop.Seek(0, 0)
	// fop.Truncate(0)

	// data_full := make([]byte, int(req.Size))
	// if n, _ := fp.ReadAt(data_full, 0); n != int(req.Size) {
	// 	set.Error = types.NewErrorMeta("500", "Server Error")
	// 	return
	// }

	// if _, err := fop.Write(data_full); err != nil {
	// 	set.Error = types.NewErrorMeta("500", "Server Error")
	// 	return
	// }

	// fp.Seek(0, 0 +".txz")
	// if n, err := io.Copy(fop, fp); err != nil {
	// 	set.Error = types.NewErrorMeta("500", err.Error())
	// 	return
	// }

	// filehash := sha256.New()
	// filehash.Write(data_full)
	// sum_check := fmt.Sprintf("sha256:%x", filehash.Sum(nil))
	sum_check := ipm_entry_sync_sumcheck(tmp_file)

	hlog.Printf("info", "%s to %s", tmp_file, path)
	if rs := data.Storage.FoFilePut(tmp_file, path); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.String())
		return
	}

	// package file
	pack := ipapi.Pack{
		Meta: types.InnerObjectMeta{
			ID:      pkg_id,
			Name:    packBuild.Name,
			User:    av.Key.User,
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Version:  packBuild.Version,
		Size:     req.Size,
		SumCheck: sum_check,
		Project:  packBuild.Project,
		Channel:  channel.Meta.Name,
		Built:    packBuild.Built,
	}
	for _, v := range packBuild.Groups {
		pack.Groups.Set(v)
	}

	if rs = data.Data.NewWriter(ipapi.DataPackKey(pkg_id), pack).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database")
		return
	}

	var prev_info ipapi.PackInfo
	name_lower := strings.ToLower(packBuild.Name)
	if rs := data.Data.NewReader(ipapi.DataInfoKey(name_lower)).Query(); rs.NotFound() {

		prev_info = ipapi.PackInfo{
			Meta: types.InnerObjectMeta{
				Name:    packBuild.Name,
				User:    av.Key.User,
				Created: types.MetaTimeNow(),
			},
			LastVersion: packBuild.Version.Version,
			Project:     packBuild.Project,
			Groups:      packBuild.Groups,
			StatNum:     1,
			StatSize:    pack.Size,
		}

	} else if rs.OK() {

		if err := rs.Decode(&prev_info); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error")
			return
		}

		switch packBuild.Version.Version.Compare(prev_info.LastVersion) {
		case 1:
			prev_info.LastVersion = packBuild.Version.Version
		}

		//
		prev_info.StatNum++
		prev_info.StatSize += pack.Size

		if prev_info.Project.Description == "" &&
			prev_info.Project.Description != packBuild.Project.Description {
			prev_info.Project.Description = packBuild.Project.Description
		}

		if prev_info.Project.Homepage == "" &&
			prev_info.Project.Homepage != packBuild.Project.Homepage {
			prev_info.Project.Homepage = packBuild.Project.Homepage
		}

		if len(prev_info.Groups) < 1 &&
			!prev_info.Groups.Equal(packBuild.Groups) {
			prev_info.Groups = packBuild.Groups
		}

		if prev_info.Meta.User == "" {
			prev_info.Meta.User = av.Key.User
		}

	} else {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	prev_info.Meta.Updated = types.MetaTimeNow()

	if rs := data.Data.NewWriter(ipapi.DataInfoKey(name_lower), prev_info).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	channel.StatNum++
	channel.StatSize += pack.Size
	data.Data.NewWriter(ipapi.DataChannelKey(channel.Meta.Name), channel).Commit()

	set.Kind = "PackMultipartCommit"
}

func ipm_entry_sync_sumcheck(filepath string) string {

	rs, err := exec.Command(cmd_shasum, filepath).Output()
	if err != nil {
		return ""
	}

	rss := strings.Split(string(rs), " ")
	if len(rss) < 2 {
		return ""
	}

	return "sha256:" + rss[0]
}
