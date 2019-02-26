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
	"plugin"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/connect"
	"github.com/lynkdb/iomix/skv"
	"github.com/lynkdb/kvgo"
	"github.com/lynkdb/localfs"

	"github.com/sysinner/inpack/ipapi"
	"github.com/sysinner/inpack/server/config"
)

var (
	Data    skv.Connector
	Storage skv.FileObjectConnector
)

func Setup() error {

	if err := setupDataConnect(); err != nil {
		return err
	}

	tn := types.MetaTimeNow()
	def_channels := []ipapi.PackageChannel{
		{
			Meta: types.InnerObjectMeta{
				Name:    "release",
				User:    "sysadmin",
				Created: tn,
				Updated: tn,
			},
			VendorName: "localhost",
			Roles: &ipapi.PackageChannelRoles{
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
			Roles: &ipapi.PackageChannelRoles{
				Create: types.ArrayUint32([]uint32{100, 101}),
				Read:   types.ArrayUint32([]uint32{100, 101}),
				Write:  types.ArrayUint32([]uint32{100, 101}),
			},
		},
	}
	for _, v := range def_channels {
		if rs := Data.KvNew(ipapi.DataChannelKey(v.Meta.Name), v, nil); !rs.OK() {
			return errors.New("Data/Channel init error")
		}
	}

	return nil
}

func setupDataConnect() error {

	for _, v := range config.Config.IoConnectors {

		if v.Name != "inpack_database" && v.Name != "inpack_storage" {
			continue
		}

		if v.Driver == "lynkdb/kvgo" {

			db, err := kvgo.Open(*v)
			if err != nil {
				return err
			}

			if v.Name == "inpack_database" {
				Data = db
			}

			hlog.Printf("info", "DataConnector (%s) Open %s OK", v.Name, v.Driver)
			continue

		} else if v.Driver == "lynkdb/localfs" {

			db, err := localfs.FileObjectConnect(*v)
			if err != nil {
				return err
			}

			if v.Name == "inpack_storage" {
				Storage = db
			}

			hlog.Printf("info", "DataConnector (%s) Open %s OK", v.Name, v.Driver)
			continue
		}

		if v.DriverPlugin == "" {
			return fmt.Errorf("No Plugin Name Found (%s)", v.Name)
		}

		p, err := plugin.Open(config.Prefix + "/plugin/" + string(v.DriverPlugin))
		if err != nil {
			return err
		}

		switch v.Name {
		case "inpack_database":

			nc, err := p.Lookup("NewConnector")
			if err != nil {
				return err
			}

			fn, ok := nc.(func(opts *connect.ConnOptions) (skv.Connector, error))
			if !ok {
				return fmt.Errorf("No Plugin/Method (%s) Found", "NewConnector #1")
			}

			db, err := fn(v)
			if err != nil {
				return err
			}

			Data = db

		case "inpack_storage":

			nc, err := p.Lookup("NewFileObjectConnector")
			if err != nil {
				return err
			}

			fn, ok := nc.(func(opts *connect.ConnOptions) (skv.FileObjectConnector, error))
			if !ok {
				return fmt.Errorf("No Plugin/Method (%s) Found", "NewConnector #2")
			}

			db, err := fn(v)
			if err != nil {
				return err
			}

			Storage = db

		default:
			continue
		}

		hlog.Printf("info", "DataConnector (%s) plugin Open %s OK",
			v.Name, string(v.DriverPlugin))
	}

	if Data == nil {
		return fmt.Errorf("No DataConnector (%s) Setup", "inpack_database")
	}

	if Storage == nil {
		return fmt.Errorf("No DataConnector (%s) Setup", "inpack_storage")
	}

	return nil
}
