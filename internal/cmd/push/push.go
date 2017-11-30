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

package push // import "github.com/sysinner/inpack/internal/cmd/push"

import (
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hooto/hflag4g/hflag"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/internal/cmd/auth"
	"github.com/sysinner/inpack/internal/ini"
	"github.com/sysinner/inpack/ipapi"
)

var (
	arg_pack_path = ""
	arg_channel   = "beta"
	arg_repo      = "local"
	cfg           *ini.ConfigIni
	err           error
	pkg_spec_name = ".inpack/inpack.json"
	block_size    = int64(4 * 1024 * 1024)
)

func Cmd() error {

	if v, ok := hflag.Value("channel"); ok {
		arg_channel = filepath.Clean(v.String())
	}

	if v, ok := hflag.Value("repo"); ok {
		arg_repo = filepath.Clean(v.String())
	}

	if v, ok := hflag.Value("pack_path"); ok {
		arg_pack_path = filepath.Clean(v.String())
	}
	if arg_pack_path == "" {
		return fmt.Errorf("Package Path (--pack_path) Not Found")
	}
	arg_pack_path, _ = filepath.Abs(arg_pack_path)
	pack_stat, err := os.Stat(arg_pack_path)
	if err != nil || pack_stat.IsDir() {
		return fmt.Errorf("Package Path Not Found (%s)", arg_pack_path)
	}
	if pack_stat.Size() < 1 {
		return fmt.Errorf("pack size empty")
	}
	fmt.Printf("\nPUSH %s\n", arg_pack_path)

	//

	// check if uploaded
	spec, err := exec.Command("/bin/tar", "-Jxvf", arg_pack_path, "-O", pkg_spec_name).Output()
	if err != nil {
		return err
	}

	var pack_spec ipapi.PackageSpec
	if err := json.Decode(spec, &pack_spec); err != nil {
		return err
	}

	cfg, err = auth.Config()
	if err != nil {
		return err
	}

	aka, err := auth.AccessKeyAuth(arg_repo)
	if err != nil {
		return err
	}

	{
		url := fmt.Sprintf(
			"%s/ips/v1/pkg/entry?id=%s",
			cfg.Get(arg_repo, "service_url").String(),
			ipapi.PackageMetaId(pack_spec.Name, pack_spec.Version),
		)

		hcp := httpclient.Get(url)
		hcp.Header("Authorization", aka.Encode())
		defer hcp.Close()

		var rspkg types.TypeMeta
		if err = hcp.ReplyJson(&rspkg); err != nil {
			return err
		}
		if rspkg.Kind == "Package" {
			fmt.Printf("  Target Package (%s) already existed\n",
				ipapi.PackageFilename(pack_spec.Name, pack_spec.Version))
			return nil
		}
	}

	// do commit
	req := ipapi.PackageMultipartCommit{
		Channel: arg_channel,
		Name:    pack_spec.Name,
		Version: pack_spec.Version,
		Size:    pack_stat.Size(),
	}

	fp, err := os.Open(arg_pack_path)
	if err != nil {
		return err
	}
	defer fp.Close()

	for offset := int64(0); offset < pack_stat.Size(); offset += block_size {

		data_len := block_size
		if offset+data_len > pack_stat.Size() {
			data_len = pack_stat.Size() - offset
		}

		if data_len < 1 {
			fmt.Println("  Invalid Offset")
			break
		}

		buf := make([]byte, int(data_len))
		fp.ReadAt(buf, offset)

		req.BlockOffset = offset
		req.BlockCrc32 = crc32.ChecksumIEEE(buf)
		req.BlockData = "data:inpack/txz;base64," + base64.StdEncoding.EncodeToString(buf)

		hc := httpclient.Put(fmt.Sprintf(
			"%s/ips/v1/pkg/multipart-commit",
			cfg.Get(arg_repo, "service_url").String(),
		))
		defer hc.Close()

		js, _ := json.Encode(req, "")
		hc.Header("Authorization", aka.Encode())
		hc.Body(js)

		var rsp types.TypeMeta
		err = hc.ReplyJson(&rsp)
		if err != nil {
			fmt.Printf("  %s\n", err.Error())
			break
		}
		if rsp.Error != nil {
			fmt.Printf("  %s\n", rsp.Error.Message)
			break
		}

		if rsp.Kind != "PackageMultipartCommit" {
			fmt.Println("  Invalid response message")
			break
		}

		fmt.Printf("  ok %s %d%%\n",
			req.Name, int(100*(offset+data_len)/pack_stat.Size()))
	}
	fmt.Printf("  ok %s\n", req.Name)

	return nil
}
