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
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/internal/cliflags"
	"github.com/sysinner/inpack/internal/cmd/auth"
	"github.com/sysinner/inpack/internal/ini"
	"github.com/sysinner/inpack/ipapi"
)

var (
	arg_pack_path = ""
	arg_channel   = ""
	cfg           *ini.ConfigIni
	err           error
	pkg_spec_name = ".inpack/inpack.json"
)

func Cmd() error {

	if v, ok := cliflags.Value("channel"); ok {
		arg_channel = filepath.Clean(v.String())
	}
	if arg_channel == "" {
		return fmt.Errorf("Channel Not Found")
	}

	if v, ok := cliflags.Value("pack_path"); ok {
		arg_pack_path = filepath.Clean(v.String())
	}
	arg_pack_path, _ = filepath.Abs(arg_pack_path)
	pack_stat, err := os.Stat(arg_pack_path)
	if err != nil {
		return fmt.Errorf("pack_path Not Found")
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

	aka, err := auth.AccessKeyAuth()
	if err != nil {
		return err
	}

	{
		url := fmt.Sprintf(
			"%s/ips/v1/pkg/entry?id=%s",
			cfg.Get("access_key", "service_url").String(),
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
	req := ipapi.PackageCommit{
		Size:     pack_stat.Size(),
		Name:     pack_stat.Name(),
		Data:     "data:inpack/txz;base64,",
		SumCheck: "sha1:TODO",
		Channel:  arg_channel,
	}

	fp, err := os.Open(arg_pack_path)
	if err != nil {
		return err
	}
	bs, err := ioutil.ReadAll(fp)
	if err != nil {
		return err
	}

	req.Data += base64.StdEncoding.EncodeToString(bs)

	hc := httpclient.Put(fmt.Sprintf(
		"%s/ips/v1/pkg/commit",
		cfg.Get("access_key", "service_url").String(),
	))
	defer hc.Close()

	js, _ := json.Encode(req, "")
	hc.Header("Authorization", aka.Encode())
	hc.Body(js)

	var rsp types.TypeMeta
	err = hc.ReplyJson(&rsp)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if rsp.Error != nil {
		fmt.Println("err", rsp.Error)
	}
	fmt.Println("  ok", rsp.Kind)

	return nil
}
