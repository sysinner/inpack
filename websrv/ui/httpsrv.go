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

package ui

import (
	"path/filepath"

	"github.com/hooto/httpsrv"
	"github.com/sysinner/inpack/server/config"
)

func NewModule(prefix string) *httpsrv.Module {

	if prefix == "" {
		prefix = config.Prefix
	}
	prefix = filepath.Clean(prefix)

	mod := httpsrv.NewModule()

	mod.RegisterFileServer("/~", prefix+"/webui", nil)

	mod.RegisterFileServer("/-", prefix+"/webui/ips/tpl", nil)

	return mod
}
