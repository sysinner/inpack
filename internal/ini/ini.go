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

package ini // import "code.hooto.com/lessos/lospack-cli/internal/ini"

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	sectionStart = []byte{'['}
	sectionEnd   = []byte{']'}
)

type ConfigIni struct {
	mu       sync.Mutex
	parsed   bool
	File     string
	data     types.Labels
	replaces map[string]string
}

func ConfigIniParse(file string) (*ConfigIni, error) {

	fp, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	return &ConfigIni{
		File:     file,
		replaces: map[string]string{},
	}, nil
}

func (cfg *ConfigIni) parse() {

	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	if cfg.parsed {
		return
	}

	fp, err := os.Open(cfg.File)
	if err != nil {
		return
	}
	defer fp.Close()

	buf := bufio.NewReader(fp)

	bom, err := buf.Peek(3)
	if err == nil && bom[0] == 239 && bom[1] == 187 && bom[2] == 191 {
		for i := 1; i <= 3; i++ {
			buf.ReadByte()
		}
	}

	var (
		section_open = "main"
		tag_open     = ""
		tag_value    = ""
	)

	for {

		line, _, err := buf.ReadLine()
		if err != nil {
			break
		}

		line = bytes.TrimRight(line, " ")
		if len(line) < 1 {
			continue
		}

		if bytes.HasPrefix(line, sectionStart) && bytes.HasSuffix(line, sectionEnd) {

			section := strings.ToLower(string(line[1 : len(line)-1]))

			if section != section_open {

				if tag_open != "" {
					cfg.data.Set(section_open+"/"+tag_open, tag_value)
					tag_open, tag_value = "", ""
				}
			}

			section_open = section
		}

		if tag_open == "" && bytes.HasPrefix(line, []byte{'#'}) {
			continue
		}

		if bytes.HasPrefix(line, []byte{'%'}) {

			if tag_open != "" {
				cfg.data.Set(section_open+"/"+tag_open, tag_value)
			}

			if len(line) > 1 {
				tag_open = strings.ToLower(string(line[1:]))
			} else {
				tag_open = ""
			}

			tag_value = ""

			continue
		}

		if tag_open != "" {

			if len(tag_value) > 0 {
				tag_value += "\n"
			}

			tag_value += string(line)

			continue
		}

		if kv := bytes.Split(line, []byte{'='}); len(kv) == 2 {

			key := strings.ToLower(string(bytes.TrimSpace(kv[0])))
			val := string(bytes.TrimSpace(kv[1]))

			if len(key) > 0 && len(val) > 0 {
				cfg.data.Set(section_open+"/"+key, val)
			}
		}
	}

	if tag_open != "" {
		cfg.data.Set(section_open+"/"+tag_open, tag_value)
	}

	cfg.parsed = true
}

func (cfg *ConfigIni) Params(args ...string) {

	if len(args) < 2 || len(args)%2 != 0 {
		return
	}

	for i := 0; i < len(args); i += 2 {
		cfg.replaces[args[i]] = args[i+1]
	}
}

func (cfg *ConfigIni) value_render(val string) string {

	for k, v := range cfg.replaces {
		val = strings.Replace(val, "{{."+k+"}}", v, -1)
	}

	return val
}

func (cfg *ConfigIni) Get(args ...string) types.Bytex {

	cfg.parse()

	var val types.Bytex

	if len(args) == 1 {
		val, _ = cfg.data.Get("main/" + args[0])
	} else if len(args) == 2 {
		val, _ = cfg.data.Get(args[0] + "/" + args[1])
	}

	if len(val) > 0 {
		val = types.Bytex([]byte(cfg.value_render(val.String())))
	}

	return val
}

func (cfg *ConfigIni) Set(args ...string) error {

	if len(args) < 2 {
		return errors.New("Invalid Args")
	}

	cfg.parse()

	if len(args) == 3 {
		cfg.data.Set(args[0]+"/"+args[1], args[2])
	} else {
		cfg.data.Set("main/"+args[0], args[1])
	}

	return nil
}
