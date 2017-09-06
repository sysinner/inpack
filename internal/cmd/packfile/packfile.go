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

package packfile // import "github.com/lessos/lospack/internal/cmd/packfile"

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/apcera/termtables"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"github.com/lessos/lospack/internal/cliflags"
	"github.com/lessos/lospack/internal/cmd/auth"
	"github.com/lessos/lospack/internal/ini"
	"github.com/lessos/lospack/lpapi"
)

var (
	arg_pkgname = ""
	cfg         *ini.ConfigIni
	err         error
)

func List() error {

	if v, ok := cliflags.Value("name"); ok {
		arg_pkgname = filepath.Clean(v.String())
	}
	if arg_pkgname == "" {
		return fmt.Errorf("Package Name Not Found")
	}

	//
	cfg, err = auth.Config()
	if cfg == nil {
		return err
	}

	aka, err := auth.AccessKeyAuth()
	if err != nil {
		return err
	}

	hc := httpclient.Get(fmt.Sprintf(
		"%s/lps/v1/pkg/list?name=%s",
		cfg.Get("access_key", "service_url").String(),
		arg_pkgname,
	))
	defer hc.Close()

	hc.Header("Authorization", aka.Encode())

	var ls lpapi.PackageList
	if err = hc.ReplyJson(&ls); err != nil {
		return err
	}
	if ls.Error != nil {
		return errors.New(ls.Error.Message)
	}

	tbl := termtables.CreateTable()
	tbl.AddHeaders("Name", "Version", "Release", "Dist", "Arch", "Built")

	fmt.Println("Found", len(ls.Items))
	for _, v := range ls.Items {
		tbl.AddRow(
			v.Meta.Name,
			v.Version.Version,
			v.Version.Release,
			v.Version.Dist,
			v.Version.Arch,
			types.MetaTime(v.Built).Format("2006-01-02 15:04"),
		)
	}
	fmt.Println(tbl.Render())

	return nil
}
