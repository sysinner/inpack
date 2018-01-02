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

package info // import "github.com/sysinner/inpack/internal/cmd/info"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"os"
	"path/filepath"

	"github.com/hooto/hflag4g/hflag"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/internal/cmd/auth"
	"github.com/sysinner/inpack/ipapi"
)

var (
	arg_icon_path = ""
	arg_icon_type = ""
	arg_repo      = "local"
	arg_pkgname   = ""
)

func IcoSet() error {

	//
	if v, ok := hflag.Value("name"); ok {
		arg_pkgname = filepath.Clean(v.String())
	}
	if arg_pkgname == "" {
		return fmt.Errorf("Package Name Not Found")
	}

	if v, ok := hflag.Value("repo"); ok {
		arg_repo = filepath.Clean(v.String())
	}

	//
	if v, ok := hflag.Value("type"); ok {
		arg_icon_type = v.String()
	}
	if arg_icon_type != "11" && arg_icon_type != "21" {
		return fmt.Errorf("Invalid Type Set")
	}

	//
	if v, ok := hflag.Value("icon_path"); ok {
		arg_icon_path = filepath.Clean(v.String())
	}
	arg_icon_path, _ = filepath.Abs(arg_icon_path)
	pack_stat, err := os.Stat(arg_icon_path)
	if err != nil {
		return fmt.Errorf("icon_path Not Found")
	}
	fmt.Printf("icon set %s\n", arg_icon_path)

	//
	cfg, err := auth.Config()
	if cfg == nil {
		return err
	}

	req := ipapi.PackageInfoIcoSet{
		Type: arg_icon_type,
		Size: pack_stat.Size(),
		Name: arg_pkgname,
		Data: "",
	}

	ext := filepath.Ext(pack_stat.Name())
	mtype := mime.TypeByExtension(ext)
	req.Data = fmt.Sprintf("data:%s;base64,", mtype)

	fp, err := os.Open(arg_icon_path)
	if err != nil {
		return err
	}
	bs, err := ioutil.ReadAll(fp)
	if err != nil {
		return err
	}

	req.Data += base64.StdEncoding.EncodeToString(bs)

	aka, err := auth.AccessKeyAuth(arg_repo)
	if err != nil {
		return err
	}

	hc := httpclient.Put(fmt.Sprintf(
		"%s/ips/v1/pkg-info/icon-set",
		cfg.Get(arg_repo, "service_url").String(),
	))
	defer hc.Close()

	js, _ := json.Encode(req, "")
	hc.Header("Authorization", aka.Encode())
	hc.Body(js)

	var rsp types.TypeMeta
	if err = hc.ReplyJson(&rsp); err != nil {
		return err
	}
	if rsp.Error != nil {
		return errors.New(rsp.Error.Message)
	}

	fmt.Println("OK")
	return nil
}
