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
	"fmt"
	"log"
	"os"

	cmd_build "github.com/sysinner/inpack/internal/cmd/build"
	cmd_info "github.com/sysinner/inpack/internal/cmd/info"
	cmd_pack "github.com/sysinner/inpack/internal/cmd/packfile"
	cmd_push "github.com/sysinner/inpack/internal/cmd/push"
)

var (
	version = "0.9.0"
)

func main() {

	if len(os.Args) < 2 {
		log.Fatal("No Args Found")
	}

	switch os.Args[1] {

	case "build":
		if err := cmd_build.Cmd(); err != nil {
			log.Fatal(err)
		}

	case "push":
		if err := cmd_push.Cmd(); err != nil {
			log.Fatal(err)
		}

	case "info-list":
		if err := cmd_info.List(); err != nil {
			log.Fatal(err)
		}

	case "info-icon-set":
		if err := cmd_info.IconSet(); err != nil {
			log.Fatal(err)
		}

	case "packfile-list":
		if err := cmd_pack.List(); err != nil {
			log.Fatal(err)
		}

	case "version":
		fmt.Println("Version", version)

	default:
		log.Fatalf("No Command Found (%s)", os.Args[1])
	}
}
