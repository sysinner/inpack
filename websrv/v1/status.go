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

package v1 // import "code.hooto.com/lessos/lospack/websrv/v1"

import (
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"
)

type Status struct {
	*httpsrv.Controller
}

func (c Status) InfoAction() {

	var sets struct {
		types.TypeMeta
		UserChannelWrite bool `json:"user_channel_write"`
	}
	defer c.RenderJson(&sets)

	us, _ := iamclient.SessionInstance(c.Session)
	if us.IsLogin() && us.UserName == "sysadmin" {
		sets.UserChannelWrite = true
	}

	sets.Kind = "StatusInfo"
}
