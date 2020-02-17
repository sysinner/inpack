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

	"github.com/hooto/hconf4g/hconf"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/connect"
	iox_utils "github.com/lynkdb/iomix/utils"
)

var (
	Prefix           string
	PrefixWebUI      string
	Version          = "0.9.0"
	Config           ConfigCommon
	err              error
	init_cache_akacc iamapi.AccessKey
	init_sys_user    = "sysadmin"
)

type ConfigCommon struct {
	filepath      string
	InstanceId    string              `json:"instance_id" toml:"instance_id"`
	SecretKey     string              `json:"secret_key" toml:"secret_key"`
	HttpPort      uint16              `json:"http_port,omitempty" toml:"http_port,omitempty"`
	DataConnect   connect.ConnOptions `json:"data_connect" toml:"data_connect"`
	IamServiceUrl string              `json:"iam_service_url,omitempty" toml:"iam_service_url,omitempty"`
	PprofHttpPort uint16              `json:"pprof_http_port,omitempty" toml:"pprof_http_port,omitempty"`
}

func (cfg *ConfigCommon) Sync() error {
	return hconf.EncodeToFile(cfg, cfg.filepath)
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

	if err := hconf.DecodeFromFile(&Config, Prefix+"/etc/inpack.conf"); err != nil {

		if !os.IsNotExist(err) {
			return err
		}

		//
		if err := json.DecodeFile(Prefix+"/etc/inpack_config.json", &Config); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	Config.filepath = Prefix + "/etc/inpack.conf"

	if Config.DataConnect.Connector == "" {
		Config.DataConnect.Connector = "iomix/sko/client-connector"
		Config.DataConnect.Driver = types.NewNameIdentifier("lynkdb/kvgo")
		Config.DataConnect.SetValue("data_dir", Prefix+"/var/db_inpack")
		Config.DataConnect.SetValue("lynkdb/sko/compaction_table_size", "16")
		Config.DataConnect.SetValue("lynkdb/sko/write_buffer", "8")
		Config.DataConnect.SetValue("lynkdb/sko/cache_capacity", "32")
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

func InitIamAccessKeyData() []iamapi.AccessKey {

	if len(Config.InstanceId) < 16 || len(Config.SecretKey) < 32 {
		return nil
	}

	return []iamapi.AccessKey{
		{
			User:      init_sys_user,
			AccessKey: Config.InstanceId[:8] + idhash.HashToHexString([]byte(Config.InstanceId), 8),
			SecretKey: idhash.HashToBase64String(idhash.AlgSha256, []byte(Config.SecretKey), 40),
			Bounds: []iamapi.AccessKeyBound{{
				Name: "app/" + Config.InstanceId,
			}},
			Description: "inPack Server",
		},
	}
}
