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

package main

import (
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamclient"

	"github.com/sysinner/inpack/server/config"
	"github.com/sysinner/inpack/server/data"
	"github.com/sysinner/inpack/websrv/ui"
	"github.com/sysinner/inpack/websrv/v1"
)

var (
	version    = "0.1.2.dev"
	flagPrefix = flag.String("prefix", "", "the prefix folder path")
	err        error
)

func main() {
	//
	config.Version = version

	//
	runtime.GOMAXPROCS(runtime.NumCPU())

	//
	if !flag.Parsed() {
		flag.Parse()
	}

	if err = config.Setup(*flagPrefix); err != nil {
		fmt.Printf("conf.Initialize error: %s\n", err.Error())
		os.Exit(1)
	}

	if err = data.Setup(); err != nil {
		fmt.Printf("data.Init error: %s\n", err.Error())
		os.Exit(1)
	}

	if config.Config.IamServiceUrl != "" {
		iamclient.ServiceUrl = config.Config.IamServiceUrl
	}
	//
	httpsrv.DefaultService.HandleModule("/ips/v1", v1.NewModule())
	httpsrv.DefaultService.HandleModule("/ips", ui.NewModule(""))

	//
	if config.Config.PprofHttpPort > 0 {
		go http.ListenAndServe(fmt.Sprintf(":%d", config.Config.PprofHttpPort), nil)
	}

	// http service
	httpsrv.DefaultService.Config.HttpPort = config.Config.HttpPort

	//
	hlog.Print("info", "running")
	httpsrv.DefaultService.Start()
}
