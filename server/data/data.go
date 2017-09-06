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

package data // import "github.com/lessos/lospack/server/data"

import (
	"fmt"

	"github.com/lynkdb/iomix/connect"
	"github.com/lynkdb/iomix/fs"
	"github.com/lynkdb/iomix/skv"
	"github.com/lynkdb/kvgo"
	"github.com/lynkdb/localfs"
)

var (
	err     error
	Data    skv.Connector
	Storage fs.Connector
)

func Init(cfg connect.MultiConnOptions) error {

	//
	if opts := cfg.Options("lps_database"); opts == nil {
		return fmt.Errorf("No IoConnector (%s) Found", "database")
	} else if Data, err = kvgo.Open(*opts); err != nil {
		return fmt.Errorf("Can Not Connect To %s, Error: %s", "database", err.Error())
	}

	//
	if opts := cfg.Options("lps_storage"); opts == nil {
		return fmt.Errorf("Can Not Connect To %s", "storage")
	} else if Storage, err = localfs.Open(*opts); err != nil {
		return fmt.Errorf("Can Not Connect To %s, Error: %s", "storage", err.Error())
	}

	return nil
}
