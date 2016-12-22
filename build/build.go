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

package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/lessos/lpm/internal/ini"
	"github.com/lessos/lpm/lpmtypes"
)

var (
	build_dir = ".build"
	jscp      = "/usr/bin/uglifyjs %s -c -m -o %s"
	csscp     = "/usr/bin/uglifycss %s > %s"
	htmlcp    = "/usr/bin/html-minifier --remove-comments " +
		"--collapse-whitespace --minify-js --minify-css %s -o %s"
	filecp  = "cp -rpf %s %s"
	cpfiles types.ArrayString
)

func Cmd() error {

	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("CPU: amd64 or x86_64 is required")
	}

	dist := ""
	arch := "x64"

	{
		cmd, err := exec.LookPath("lsb_release")
		if err != nil {
			return fmt.Errorf("CMD: lsb_release is required")
		}

		rs, err := exec.Command(cmd, "-r", "-i", "-s").Output()
		if err != nil {
			return err
		}

		out := strings.Replace(string(rs), "\n", " ", -1)
		rs2 := strings.Split(out, " ")
		if len(rs2) < 2 {
			return err
		}

		if rs2[0] == "CentOS" {
			dist = "el"
		} else if rs2[0] == "Debian" {
			dist = "de"
		} else {
			return fmt.Errorf("OS: CentOS is required")
		}

		ver := strings.Split(rs2[1], ".")
		if len(ver) == 0 {
			return fmt.Errorf("No OS Version Found")
		}

		switch rs2[0] {

		case "CentOS":
			if ver[0] != "7" {
				return fmt.Errorf("CentOS Version 7.x is required")
			}
			dist += ver[0]

		case "Debian":
			return fmt.Errorf("OS not Supported")

		default:
			return fmt.Errorf("OS not Supported")
		}
	}

	cfg, err := ini.ConfigIniParse("./misc/lpm/lpm.spec")
	if err != nil {
		if cfg, err = ini.ConfigIniParse("./lpm.spec"); err != nil {
			return fmt.Errorf("No SPEC Found in `misc/lpm/lpm.spec`")
		}
	}

	cfg.Params("buildroot", build_dir)

	os.Mkdir(build_dir, 0755)

	if err := _cmd(cfg.Get("build").String()); err != nil {
		return err
	}

	subfiles := _lookup_files(cfg.Get("js_compress").String(), ".js")
	if err := _compress(subfiles, jscp); err != nil {
		return fmt.Errorf("JsCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("css_compress").String(), ".css")
	if err := _compress(subfiles, csscp); err != nil {
		return fmt.Errorf("CssCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("html_compress").String(), ".html")
	if err := _compress(subfiles, htmlcp); err != nil {
		return fmt.Errorf("HtmlCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("html_compress").String(), ".tpl")
	if err := _compress(subfiles, htmlcp); err != nil {
		return fmt.Errorf("HtmlCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("files").String(), "")
	if err := _compress(subfiles, filecp); err != nil {
		return fmt.Errorf("FileCopy %s", err.Error())
	}

	pkg := lpmtypes.Package{
		Meta: types.InnerObjectMeta{
			Name:    cfg.Get("project.name").String(),
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Vendor:   cfg.Get("project.vendor").String(),
		Version:  cfg.Get("project.version").String(),
		Release:  "1",
		PkgArch:  arch,
		PkgOS:    dist,
		Homepage: cfg.Get("project.homepage").String(),
	}
	if err := json.EncodeToFile(pkg, build_dir+"/lpm.json", "  "); err != nil {
		return err
	}

	pkg_name := fmt.Sprintf("%s-%s-%s.%s.%s", pkg.Meta.Name, pkg.Version, pkg.Release, dist, arch)

	tar := `
cd ` + build_dir + `
tar -cvf ` + pkg_name + `.tar *
xz -z -e -9 -v ` + pkg_name + `.tar
mv ` + pkg_name + `.tar.xz ../` + pkg_name + `.txz
`
	if err := _cmd(tar); err != nil {
		return err
	}

	fmt.Println("OK:", pkg_name+".txz")

	return nil
}

func _lookup_files(txt, suffix string) types.ArrayString {

	ls := strings.Split(txt, "\n")

	var subfiles types.ArrayString

	for _, v := range ls {

		v = filepath.Clean(strings.TrimSpace(v))

		fps, err := os.Stat(v)
		if err != nil {
			continue
		}

		if strings.HasSuffix(v, ".gitignore") ||
			strings.HasSuffix(v, ".git") {
			continue
		}

		if !fps.IsDir() {

			if suffix == "" || (suffix != "" && strings.HasSuffix(v, suffix)) {

				if !cpfiles.Contain(v) {
					subfiles.Insert(v)
					cpfiles.Insert(v)
				}
			}

			continue
		}

		var out []byte
		if suffix != "" {
			out, _ = exec.Command("find", v, "-type", "f", "-name", "*"+suffix).Output()
		} else {
			out, _ = exec.Command("find", v, "-type", "f").Output()
		}
		fs := strings.Split(strings.TrimSpace(string(out)), "\n")

		for _, fv := range fs {

			fv = filepath.Clean(strings.TrimSpace(fv))

			if fv == "" || fv == "." || fv == ".." {
				continue
			}

			if strings.HasSuffix(fv, ".gitignore") ||
				strings.HasSuffix(fv, ".git") ||
				strings.Contains(fv, ".git/") {
				continue
			}

			if suffix != "" && !strings.HasSuffix(fv, suffix) {
				continue
			}

			if !cpfiles.Contain(fv) {
				subfiles.Insert(fv)
				cpfiles.Insert(fv)
			}
		}
	}

	return subfiles
}

func _compress(ls types.ArrayString, cmd_str string) error {

	for _, file := range ls {

		dstfile := fmt.Sprintf("./%s/%s", build_dir, file)
		if err := os.MkdirAll(filepath.Dir(dstfile), 0755); err != nil {
			return err
		}

		cmd := fmt.Sprintf(cmd_str, file, dstfile)

		if out, err := exec.Command("sh", "-c", cmd).Output(); err != nil {

			fmt.Printf("FILE ER (%s) %s %s\n", file, err.Error(), string(out))

			if _, err := exec.Command("cp", "-rpf", file, dstfile).Output(); err != nil {
				return err
			} else {
				fmt.Println("FILE ER-OK", file)
			}
		} else {
			fmt.Println("FILE OK", file)
		}
	}

	return nil
}

func _cmd(script string) error {

	script = "set -e\nset -o pipefail\n" + script + "\nexit 0\n"

	if out, err := exec.Command("bash", "-c", script).Output(); err != nil {
		return fmt.Errorf("CMD ERR(%s) %s", err.Error(), string(out)+script)
	}

	return nil
}
