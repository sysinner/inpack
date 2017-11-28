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

package auth // import "github.com/sysinner/inpack/internal/cmd/auth"

import (
	"fmt"
	"os/user"
	"path/filepath"

	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/sysinner/inpack/internal/ini"
)

var (
	arg_conf_paths []string
	err            error
	cfg            *ini.ConfigIni
)

func init() {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	arg_conf_paths = []string{
		".inpack",
		usr.HomeDir + "/.inpack",
	}

	for _, v := range arg_conf_paths {

		v, _ = filepath.Abs(v)
		if cfg, err = ini.ConfigIniParse(v); err == nil {
			break
		}
	}

}

func Config() (*ini.ConfigIni, error) {

	if cfg == nil {
		return nil, fmt.Errorf("No Config File Found")
	}

	return cfg, nil
}

func AccessKeyAuth(repo string) (iamapi.AccessKeyAuth, error) {

	if cfg == nil {
		return iamapi.AccessKeyAuth{}, fmt.Errorf("No Config File Found")
	}

	return iamclient.NewAccessKeyAuth(
		cfg.Get(repo, "user").String(),
		cfg.Get(repo, "access_key").String(),
		cfg.Get(repo, "secret_key").String(),
		"",
	)
}
