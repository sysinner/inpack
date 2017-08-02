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

package push // import "code.hooto.com/lessos/lospack/internal/cmd/push"

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/iam/iamclient"
	"code.hooto.com/lessos/lospack/internal/cliflags"
	"code.hooto.com/lessos/lospack/internal/ini"
	"code.hooto.com/lessos/lospack/lpapi"
)

var (
	arg_pack_path = ""
	arg_conf_path = ""
	arg_channel   = ""
	cfg           *ini.ConfigIni
	err           error
)

func init() {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	arg_conf_path = usr.HomeDir + "/.lospack"
}

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
	fmt.Printf("push %s\n", arg_pack_path)

	//
	arg_conf_path, _ = filepath.Abs(arg_conf_path)
	if cfg, err = ini.ConfigIniParse(arg_conf_path); err != nil {
		return err
	}

	if cfg == nil {
		return fmt.Errorf("No Config File Found (" + arg_conf_path + ")")
	}

	req := lpapi.PackageCommit{
		Size:     pack_stat.Size(),
		Name:     pack_stat.Name(),
		Data:     "data:lospack/txz;base64,",
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

	aka, err := iamclient.NewAccessKeyAuth(
		cfg.Get("access_key", "user").String(),
		cfg.Get("access_key", "access_key").String(),
		cfg.Get("access_key", "secret_key").String(),
		"",
	)
	if err != nil {
		return err
	}

	url := fmt.Sprintf(
		"%s/lps/v1/pkg/commit",
		cfg.Get("access_key", "service_url").String(),
	)
	fmt.Println(url)

	hc := httpclient.Put(fmt.Sprintf(
		"%s/lps/v1/pkg/commit",
		cfg.Get("access_key", "service_url").String(),
	))
	defer hc.Close()

	js, _ := json.Encode(req, "")
	hc.Header("Authorization", aka.Encode())
	hc.Body(js)

	// fmt.Println(aka.Encode())
	// fmt.Println(string(js))

	var rsp types.TypeMeta
	err = hc.ReplyJson(&rsp)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if rsp.Error != nil {
		fmt.Println("err", rsp.Error)
	}
	fmt.Println("ok", rsp.Kind)

	return nil
}
