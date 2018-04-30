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

package ipapi // import "github.com/sysinner/inpack/ipapi"

import (
	"github.com/lynkdb/iomix/skv"
	"github.com/lynkdb/iomix/utils"
)

const (
	data_prefix  = "ip"
	data_channel = "ch"
	data_info    = "if"
	data_pack    = "p"
	data_icon    = "ic"
)

func DataChannelKey(name string) skv.ProgKey {
	return skv.NewProgKey(data_prefix, data_channel, name)
}

func DataInfoKey(name string) skv.ProgKey {
	return skv.NewProgKey(data_prefix, data_info, name)
}

func DataPackKey(id string) skv.ProgKey {
	if id == "" {
		return skv.NewProgKey(data_prefix, data_pack, []byte{})
	}
	return skv.NewProgKey(data_prefix, data_pack, utils.HexStringToBytes(id))
}

func DataIconKey(name, typ string) skv.ProgKey {
	return skv.NewProgKey(data_prefix, data_icon, name, typ)
}
