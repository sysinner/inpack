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

package main

import (
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	"code.hooto.com/lessos/iam/iamclient"
	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"

	"code.hooto.com/lessos/lospack/server/config"
	"code.hooto.com/lessos/lospack/server/data"
	"code.hooto.com/lessos/lospack/websrv/ui"
	"code.hooto.com/lessos/lospack/websrv/v1"
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

	if err = config.Init(*flagPrefix); err != nil {
		fmt.Printf("conf.Initialize error: %s\n", err.Error())
		os.Exit(1)
	}

	if err = data.Init(config.Config.IoConnectors); err != nil {
		fmt.Printf("data.Init error: %s\n", err.Error())
		os.Exit(1)
	}

	if config.Config.IamServiceUrl != "" {
		iamclient.ServiceUrl = config.Config.IamServiceUrl
	}
	//
	httpsrv.GlobalService.ModuleRegister("/lps/v1", v1.NewModule())
	httpsrv.GlobalService.ModuleRegister("/lps", ui.NewModule())

	//
	if config.Config.PprofHttpPort > 0 {
		go http.ListenAndServe(fmt.Sprintf(":%d", config.Config.PprofHttpPort), nil)
	}

	// http service
	httpsrv.GlobalService.Config.HttpPort = config.Config.HttpPort

	//
	hlog.Print("info", "running")
	httpsrv.GlobalService.Start()
}
