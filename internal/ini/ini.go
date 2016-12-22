package ini

import (
	"bufio"
	"bytes"
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
	file     string
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
		file:     file,
		replaces: map[string]string{},
	}, nil
}

func (cfg *ConfigIni) parse() {

	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	if cfg.parsed {
		return
	}

	fp, err := os.Open(cfg.file)
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
					cfg.data.Set(section_open+"/"+tag_open, cfg.value_render(tag_value))
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
				cfg.data.Set(section_open+"/"+tag_open, cfg.value_render(tag_value))
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
				cfg.data.Set(section_open+"/"+key, cfg.value_render(val))
			}
		}
	}

	if tag_open != "" {
		cfg.data.Set(section_open+"/"+tag_open, cfg.value_render(tag_value))
	}
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

	return val
}
