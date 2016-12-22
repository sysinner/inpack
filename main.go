// Copyright 2016 lessos Author, All rights reserved.
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
	"log"
	"os"

	"github.com/lessos/lpm/build"
)

func main() {

	if len(os.Args) < 2 {
		log.Fatal("No Args Found")
	}

	switch os.Args[1] {

	case "build":
		if err := build.Cmd(); err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatalf("No Command Found (%s)", os.Args[1])
	}
}
