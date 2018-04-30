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

package v1 // import "github.com/sysinner/inpack/websrv/v1"

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hooto/httpsrv"
	"github.com/sysinner/inpack/server/data"
)

type Fs struct {
	*httpsrv.Controller
}

func (c Fs) IndexAction() {

	c.AutoRender = false

	file := filepath.Clean(c.Request.RequestPath)
	if !strings.HasPrefix(file, "v1/fs/") {
		c.RenderError(400, "Bad Request")
		return
	}

	// TODO auth
	fop, err := data.Storage.OsFileOpen(file[len("v1/fs"):])
	if err != nil {
		c.RenderError(404, "File Not Found")
		return
	}

	_, filename := filepath.Split(file)

	c.Response.Out.Header().Set("Cache-Control", "max-age=3600")
	http.ServeContent(c.Response.Out, c.Request.Request, filename, time.Now(), fop)

	// http.ServeFile(c.Response.Out, c.Request.Request, "./var/storage/"+file[len("v1/fs/"):])
}
