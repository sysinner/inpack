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

package config // import "github.com/sysinner/inpack/server/config"

import (
	"os"
	"path/filepath"
	"time"

	"github.com/hooto/hauth/go/hauth/v1"
	"github.com/hooto/htoml4g/htoml"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	iox_utils "github.com/lynkdb/iomix/utils"
	kvclient "github.com/lynkdb/kvgo/v2/pkg/client"
)

var (
	Prefix           string
	PrefixWebUI      string
	Version          = "0.9.0"
	Config           ConfigCommon
	err              error
	init_cache_akacc hauth.AccessKey
	init_sys_user    = "sysadmin"
)

type ConfigCommon struct {
	filepath      string
	InstanceId    string           `json:"instance_id" toml:"instance_id"`
	SecretKey     string           `json:"secret_key" toml:"secret_key"`
	HttpPort      uint16           `json:"http_port,omitempty" toml:"http_port,omitempty"`
	Database      *kvclient.Config `json:"database,omitempty" toml:"database,omitempty"`
	IamServiceUrl string           `json:"iam_service_url,omitempty" toml:"iam_service_url,omitempty"`
	PprofHttpPort uint16           `json:"pprof_http_port,omitempty" toml:"pprof_http_port,omitempty"`
}

func (cfg *ConfigCommon) Sync() error {
	return htoml.EncodeToFile(cfg, cfg.filepath, nil)
}

func (cfg *ConfigCommon) AccessKeyAuth() (iamapi.AccessKeyAuth, error) {
	return iamclient.NewAccessKeyAuth("app", cfg.InstanceId, cfg.SecretKey, "")
}

func Setup(prefix string) error {

	// var Prefix
	if prefix == "" {

		if prefix, err = filepath.Abs(filepath.Dir(os.Args[0]) + "/.."); err != nil {
			prefix = "/opt/sysinner/inpack"
		}
	}

	Prefix = filepath.Clean(prefix)

	if err := htoml.DecodeFromFile(Prefix+"/etc/inpack.conf", &Config); err != nil {

		if !os.IsNotExist(err) {
			return err
		}

		//
		if err := json.DecodeFile(Prefix+"/etc/inpack_config.json", &Config); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	Config.filepath = Prefix + "/etc/inpack.conf"

	if Config.Database == nil {
		Config.Database = &kvclient.Config{
			Addr:     "127.0.0.1:9566",
			Database: "inpack",
		}
	}

	if len(Config.InstanceId) < 16 {
		Config.InstanceId = iox_utils.Uint32ToHexString(uint32(time.Now().Unix())) + idhash.RandHexString(8)
	}

	if len(Config.SecretKey) < 30 {
		Config.SecretKey = idhash.RandBase64String(40)
	}

	return Config.Sync()
}

func IamAppInstance() iamapi.AppInstance {

	return iamapi.AppInstance{
		Meta: types.InnerObjectMeta{
			ID:   Config.InstanceId,
			User: init_sys_user,
		},
		Version:  Version,
		AppID:    "inpack-server",
		AppTitle: "inPack Server",
		Status:   1,
		Url:      "",
		Privileges: []iamapi.AppPrivilege{
			{
				Privilege: "inpack.admin",
				Roles:     []uint32{1},
				Desc:      "Package Manager",
			},
		},
		SecretKey: Config.SecretKey,
	}
}

func InitIamAccessKeyData() []hauth.AccessKey {

	if len(Config.InstanceId) < 16 || len(Config.SecretKey) < 32 {
		return nil
	}

	return []hauth.AccessKey{
		{
			User:   init_sys_user,
			Id:     Config.InstanceId[:8] + idhash.HashToHexString([]byte(Config.InstanceId), 8),
			Secret: idhash.HashToBase64String(idhash.AlgSha256, []byte(Config.SecretKey), 40),
			Scopes: []*hauth.ScopeFilter{
				{
					Name:  "app",
					Value: Config.InstanceId,
				},
			},
			Description: "inPack Server",
		},
	}
}
