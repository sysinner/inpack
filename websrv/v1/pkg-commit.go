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

	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/config"
	"github.com/sysinner/inpack/server/data"
)

const (
	pkg_spec_name       = ".inpack/inpack.json"
	pkg_size_max  int64 = 100 * 1024 * 1024 // 100MB
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

	var req ipapi.PackageCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if req.Channel == "" {
		req.Channel = "beta"
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
		channel *ipapi.PackageChannel
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

	if req.Size > pkg_size_max {
		set.Error = types.NewErrorMeta("400", fmt.Sprintf("the max size of Package can not more than %d", pkg_size_max))
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
		set.Error = types.NewErrorMeta("400", "Package Not Found")
		set.Error = &types.ErrorMeta{
			Code:    "500",
			Message: err.Error(),
		}
		return
	}

	// Export package definition information, checking
	spec, err := exec.Command("/bin/tar", "-Jxvf", tmp_file, "-O", pkg_spec_name).Output()
	if err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		os.Remove(tmp_file)
		return
	}

	var pack_spec ipapi.PackageSpec
	if err := json.Decode(spec, &pack_spec); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if err := pack_spec.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	pkg_filename := ipapi.PackageFilename(pack_spec.Name, pack_spec.Version)
	if !strings.HasPrefix(req.Name, pkg_filename) {
		set.Error = types.NewErrorMeta("400", "Package Name Error")
		return
	}

	//
	pkg_id := ipapi.PackageMetaId(pack_spec.Name, pack_spec.Version)

	rs := data.Data.ProgGet(ipapi.DataPackKey(pkg_id))
	if !rs.NotFound() {
		set.Error = types.NewErrorMeta("400", "Package already exists")
		return
	}

	// TODO  /name/version/*
	path := fmt.Sprintf(
		"/ips/%s/%s/%s",
		pack_spec.Name, pack_spec.Version.Version, req.Name,
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

	if rs = data.Storage.OsFilePut(tmp_file, path); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.String())
		return
	}

	// package file
	pack := ipapi.Package{
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

	if rs = data.Data.ProgPut(ipapi.DataPackKey(pkg_id), skv.NewValueObject(pack), nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database")
		return
	}

	var prev_info ipapi.PackageInfo
	name_lower := strings.ToLower(pack_spec.Name)
	if rs := data.Data.ProgGet(ipapi.DataInfoKey(name_lower)); rs.NotFound() {

		prev_info = ipapi.PackageInfo{
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

	if rs := data.Data.ProgPut(ipapi.DataInfoKey(name_lower), skv.NewValueObject(prev_info), nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	channel.StatNum++
	channel.StatSize += pack.Size
	data.Data.ProgPut(ipapi.DataChannelKey(channel.Meta.Name), skv.NewValueObject(channel), nil)

	set.Kind = "PackageCommit"
}

func (c Pkg) MultipartCommitAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	var req ipapi.PackageMultipartCommit
	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if req.Channel == "" {
		req.Channel = "beta"
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
		channel *ipapi.PackageChannel
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

	if req.Size > pkg_size_max {
		set.Error = types.NewErrorMeta("400", fmt.Sprintf("the max size of Package can not more than %d", pkg_size_max))
		return
	}

	body64 := strings.SplitAfter(req.BlockData, ";base64,")
	if len(body64) != 2 {
		return
	}
	block_data, err := base64.StdEncoding.DecodeString(body64[1])
	if err != nil {
		set.Error = types.NewErrorMeta("400", "Package Not Found")
		return
	}

	fsize := int64(len(block_data))
	if req.BlockOffset+fsize > req.Size {
		set.Error = types.NewErrorMeta("400", "Invalid Package Offset, Size or Data Set")
		return
	}

	if req.BlockCrc32 != crc32.ChecksumIEEE(block_data) {
		set.Error = types.NewErrorMeta("400", "Invalid Package BlockCrc32 SumCheck")
		return
	}

	//
	if err := ipapi.PackageNameValid(req.Name); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	//
	if err := req.Version.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	//
	pkg_id := ipapi.PackageMetaId(req.Name, req.Version)
	pkg_name := ipapi.PackageFilename(req.Name, req.Version)

	rs := data.Data.ProgGet(ipapi.DataPackKey(pkg_id))
	if !rs.NotFound() {
		set.Error = types.NewErrorMeta("400", "Package already exists")
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
		set.Kind = "PackageMultipartCommit"
		return
	}

	// Export package definition information, checking
	spec, err := exec.Command("/bin/tar", "-Jxvf", tmp_file, "-O", pkg_spec_name).Output()
	if err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		os.Remove(tmp_file)
		return
	}

	var pack_spec ipapi.PackageSpec
	if err := json.Decode(spec, &pack_spec); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if err := pack_spec.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	if pack_spec.Version.Compare(req.Version) != 0 {
		set.Error = types.NewErrorMeta("400", "Invalid Package Version Set")
		return
	}

	if pkg_name != ipapi.PackageFilename(pack_spec.Name, pack_spec.Version) {
		set.Error = types.NewErrorMeta("400", "Package Name Error")
		return
	}

	// TODO  /name/version/*
	path := fmt.Sprintf(
		"/ips/%s/%s/%s.txz",
		pack_spec.Name, pack_spec.Version.Version, pkg_name,
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

	if rs := data.Storage.OsFilePut(tmp_file, path); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.String())
		return
	}

	// package file
	pack := ipapi.Package{
		Meta: types.InnerObjectMeta{
			ID:      pkg_id,
			Name:    pack_spec.Name,
			User:    aksess.User,
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Version:  pack_spec.Version,
		Size:     req.Size,
		SumCheck: sum_check,
		Project:  pack_spec.Project,
		Channel:  channel.Meta.Name,
		Built:    pack_spec.Built,
	}
	for _, v := range pack_spec.Groups {
		pack.Groups.Insert(v)
	}

	if rs = data.Data.ProgPut(ipapi.DataPackKey(pkg_id), skv.NewValueObject(pack), nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Can not write to database")
		return
	}

	var prev_info ipapi.PackageInfo
	name_lower := strings.ToLower(pack_spec.Name)
	if rs := data.Data.ProgGet(ipapi.DataInfoKey(name_lower)); rs.NotFound() {

		prev_info = ipapi.PackageInfo{
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

	if rs := data.Data.ProgPut(ipapi.DataInfoKey(name_lower), skv.NewValueObject(prev_info), nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	channel.StatNum++
	channel.StatSize += pack.Size
	data.Data.ProgPut(ipapi.DataChannelKey(channel.Meta.Name), skv.NewValueObject(channel), nil)

	set.Kind = "PackageMultipartCommit"
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
