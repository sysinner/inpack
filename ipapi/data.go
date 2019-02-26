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
	"fmt"
	"strings"
)

func DataChannelKey(name string) []byte {
	return []byte(fmt.Sprintf("ip:ch:%s", strings.ToLower(name)))
}

func DataInfoKey(name string) []byte {
	return []byte(fmt.Sprintf("ip:if:%s", strings.ToLower(name)))
}

func DataInfoIconKey(name, typ string) []byte {
	return []byte(fmt.Sprintf("ip:ific:%s:%s", strings.ToLower(name), typ))
}

func DataPackKey(name string) []byte {
	return []byte(fmt.Sprintf("ip:p:%s", strings.ToLower(name)))
}
