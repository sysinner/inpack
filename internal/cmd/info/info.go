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
	"errors"
	"fmt"
	"path/filepath"

	"github.com/gosuri/uitable"
	"github.com/hooto/hflag4g/hflag"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/internal/cmd/auth"
	"github.com/sysinner/inpack/internal/ini"
	"github.com/sysinner/inpack/ipapi"
)

var (
	cfg *ini.ConfigIni
	err error
)

func List() error {

	//
	cfg, err = auth.Config()
	if cfg == nil {
		return err
	}

	if v, ok := hflag.ValueOK("repo"); ok {
		arg_repo = filepath.Clean(v.String())
	}

	aka, err := auth.AccessKeyAuth(arg_repo)
	if err != nil {
		return err
	}

	hc := httpclient.Get(fmt.Sprintf(
		"%s/ips/v1/pkg-info/list",
		cfg.Get(arg_repo, "service_url").String(),
	))
	defer hc.Close()

	aka.SignHttpToken(hc.Req, nil)

	var ls ipapi.PackInfoList
	if err = hc.ReplyJson(&ls); err != nil {
		return err
	}
	if ls.Error != nil {
		return errors.New(ls.Error.Message)
	}

	tbl := uitable.New()
	tbl.AddRow("Name", "Last Version", "Num", "Updated")

	fmt.Println("Found", len(ls.Items))
	for _, v := range ls.Items {
		tbl.AddRow(
			v.Meta.Name,
			v.LastVersion,
			v.StatNum,
			types.MetaTime(v.Meta.Updated).Format("2006-01-02"),
		)
	}
	fmt.Println(tbl.String())

	return nil
}
