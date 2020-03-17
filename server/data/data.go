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

package data

import (
	"errors"
	"fmt"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/sko"
	"github.com/lynkdb/kvgo"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/config"
)

var (
	Data    sko.ClientConnector
	Storage sko.ClientFileObjectConnector
)

func Setup() error {

	if err := setupDataConnect(); err != nil {
		return err
	}

	tn := types.MetaTimeNow()
	def_channels := []ipapi.PackChannel{
		{
			Meta: types.InnerObjectMeta{
				Name:    "release",
				User:    "sysadmin",
				Created: tn,
				Updated: tn,
			},
			VendorName: "localhost",
			Roles: &ipapi.PackChannelRoles{
				Read: types.ArrayUint32([]uint32{100, 101}),
			},
		},
		{
			Meta: types.InnerObjectMeta{
				Name:    "beta",
				User:    "sysadmin",
				Created: tn,
				Updated: tn,
			},
			VendorName: "localhost",
			Roles: &ipapi.PackChannelRoles{
				Create: types.ArrayUint32([]uint32{100, 101}),
				Read:   types.ArrayUint32([]uint32{100, 101}),
				Write:  types.ArrayUint32([]uint32{100, 101}),
			},
		},
	}
	for _, v := range def_channels {
		if rs := Data.NewWriter(ipapi.DataChannelKey(v.Meta.Name), v).
			ModeCreateSet(true).Commit(); !rs.OK() {
			return errors.New("Data/Channel init error")
		}
	}

	return nil
}

func setupDataConnect() error {

	if config.Config.DataConnect.Driver == "lynkdb/kvgo" {

		db, err := kvgo.Open(config.Config.DataConnect)
		if err != nil {
			return err
		}

		Data = db
		Storage = db

		hlog.Printf("info", "DataConnect (%s) Open %s OK",
			config.Config.DataConnect.Name, config.Config.DataConnect.Driver)
	}

	if Data == nil {
		return fmt.Errorf("No DataConnect Setup")
	}

	if Storage == nil {
		return fmt.Errorf("No StorageConnect Setup")
	}

	return nil
}
