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

package config // import "code.hooto.com/lessos/lospack/server/config"

import (
	"os"
	"path/filepath"

	"code.hooto.com/lessos/iam/iamapi"
	"code.hooto.com/lynkdb/iomix/connect"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
)

var (
	Prefix  string
	Version = "0.0.1.dev"
	Config  ConfigCommon
	err     error
)

type ConfigCommon struct {
	filepath      string
	InstanceId    string                   `json:"instance_id"`
	HttpPort      uint16                   `json:"http_port,omitempty"`
	IoConnectors  connect.MultiConnOptions `json:"io_connects"`
	IamServiceUrl string                   `json:"iam_service_url,omitempty"`
	PprofHttpPort uint16                   `json:"pprof_http_port,omitempty"`
}

func (cfg *ConfigCommon) Sync() error {
	return json.EncodeToFile(cfg, cfg.filepath, "  ")
}

func Init(prefix string) error {

	// var Prefix
	if prefix == "" {

		if prefix, err = filepath.Abs(filepath.Dir(os.Args[0]) + "/.."); err != nil {
			prefix = "/home/action/apps/lospack"
		}
	}

	Prefix = filepath.Clean(prefix)

	//
	file := Prefix + "/etc/lps_config.json"
	if err := json.DecodeFile(file, &Config); err != nil {
		return err
	}
	Config.filepath = file

	if opts := Config.IoConnectors.Options("database"); opts == nil {
		Config.IoConnectors.SetOptions(connect.ConnOptions{
			Name:      "lps_database",
			Connector: "iomix/skv/Connector",
		})
	}

	if opts := Config.IoConnectors.Options("storage"); opts == nil {
		Config.IoConnectors.SetOptions(connect.ConnOptions{
			Name:      "lps_storage",
			Connector: "iomix/fs/Connector",
		})
	}

	for _, opts := range Config.IoConnectors {

		if opts.Name == "lps_database" &&
			opts.Connector == "iomix/skv/Connector" {

			opts.Driver = types.NewNameIdentifier("lynkdb/kvgo")

			if v := opts.Value("data_dir"); v == "" {
				opts.SetValue("data_dir", prefix+"/var/lps_database")
			}
		}

		if opts.Name == "lps_storage" &&
			opts.Connector == "iomix/fs/Connector" {

			opts.Driver = types.NewNameIdentifier("lynkdb/localfs")

			if v := opts.Value("data_dir"); v == "" {
				opts.SetValue("data_dir", prefix+"/var/lps_storage")
			}
		}
	}

	if len(Config.InstanceId) < 16 {
		Config.InstanceId = idhash.RandHexString(16)
	}

	return Config.Sync()
}

func IamAppInstance() iamapi.AppInstance {

	return iamapi.AppInstance{
		Meta: types.InnerObjectMeta{
			ID: Config.InstanceId,
		},
		Version:  Version,
		AppID:    "lospack",
		AppTitle: "lessOS Package Service",
		Status:   1,
		Url:      "",
		Privileges: []iamapi.AppPrivilege{
			{
				Privilege: "lps.admin",
				Roles:     []uint32{1},
				Desc:      "Package Management",
			},
		},
	}
}
