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

package build // import "code.hooto.com/lessos/lospack-cli/internal/cmd/build"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/lospack-cli/internal/cliflags"
	"code.hooto.com/lessos/lospack-cli/internal/ini"
	"code.hooto.com/lessos/lospack/lpapi"
)

// yum install npm optipng
// npm install uglify-js -g
// npm install clean-css -g
// npm install html-minifier -g
var (
	build_dir = ".build"
	build_src = ".build_src"
	spec_json = "lospack.json"
	jscp      = "uglifyjs %s -c -m -o %s"
	csscp     = "cleancss --skip-rebase %s -o %s"
	htmlcp    = "html-minifier -c /tmp/html-minifier.conf %s -o %s"
	pngcp     = "optipng -o7 %s -out %s"
	filecp    = "cp -rpf %s %s"
	cpfiles   types.ArrayString
	ignores   = types.ArrayString{
		".git",
		".gitignore",
		".gitmodules",
	}
	htmlcp_config = `{
  "collapseWhitespace": true,
  "ignoreCustomFragments": [
    "<#[\\s\\S]*?#>",
    "<%[\\s\\S]*?%>",
    "<\\?[\\s\\S]*?\\?>",
    "{{.*?}}",
    "{\\[.*?\\]}"
  ],
  "minifyCSS": true,
  "minifyJS": false,
  "processScripts": [
    "text/html"
  ],
  "removeAttributeQuotes": false,
  "removeComments": true
}`
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

	var (
		err        error
		cfg        *ini.ConfigIni
		spec_files = []string{
			"./.lospack/lospack.spec",
			"./misc/lospack/lospack.spec",
			"./lospack.spec",
		}
	)

	if v, ok := cliflags.Value("spec"); ok {
		spec_files = append([]string{v.String()}, spec_files...)
	}

	// tpl, err := template.New("s").Parse(etr.ExecStart)
	for _, v := range spec_files {

		if cfg, err = ini.ConfigIniParse(v); err == nil {
			break
		}
	}

	if cfg == nil {
		return fmt.Errorf("No SPEC File Found")
	}

	if v, ok := cliflags.Value("version"); ok {
		cfg.Set("project.version", v.String())
	}

	if v, ok := cliflags.Value("release"); ok {
		cfg.Set("project.release", v.String())
	} else {
		cfg.Set("project.release", "1")
	}

	//
	pkg := lpapi.PackageSpec{
		Name:     cfg.Get("project.name").String(),
		Version:  types.Version(cfg.Get("project.version").String()),
		Release:  types.Version(cfg.Get("project.release").String()),
		PkgOS:    "all", // dist,
		PkgArch:  "src", // arch,
		Vendor:   cfg.Get("project.vendor").String(),
		Homepage: cfg.Get("project.homepage").String(),
		Created:  types.MetaTimeNow(),
	}
	groups := strings.Split(cfg.Get("project.groups").String(), ",")
	for _, v := range groups {
		pkg.Groups.Insert(v)
	}

	fmt.Printf(`building
    package: %s
    version: %s
    release: %s
    os:      %s
    arch:    %s
    vendor:  %s
`,
		pkg.Name,
		pkg.Version,
		pkg.Release,
		dist,
		arch,
		pkg.Vendor,
	)

	//
	if err := _build_source(cfg); err == nil {

		//
		if err := json.EncodeToFile(pkg, build_src+"/.lospack/"+spec_json, "  "); err != nil {
			return err
		}

		if err := _tar_compress(
			build_src,
			fmt.Sprintf("%s-%s-%s.all.src", pkg.Name, pkg.Version, pkg.Release),
		); err != nil {
			return err
		}
	}

	//
	pkg.PkgOS = dist
	pkg.PkgArch = arch

	cfg.Params("buildroot", build_dir)
	os.Mkdir(build_dir, 0755)

	cfp, err := os.OpenFile("/tmp/html-minifier.conf", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer cfp.Close()

	cfp.Seek(0, 0)
	cfp.Truncate(0)

	if _, err := cfp.Write([]byte(htmlcp_config)); err != nil {
		return err
	}

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

	subfiles = _lookup_files(cfg.Get("png_compress").String(), ".png")
	if err := _compress(subfiles, pngcp); err != nil {
		return fmt.Errorf("PngCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("files").String(), "")
	if err := _compress(subfiles, filecp); err != nil {
		return fmt.Errorf("FileCopy %s", err.Error())
	}

	os.MkdirAll(build_dir+"/.lospack", 0755)

	//
	if err := json.EncodeToFile(pkg, build_dir+"/.lospack/"+spec_json, "  "); err != nil {
		return err
	}

	return _tar_compress(
		build_dir,
		fmt.Sprintf("%s-%s-%s.%s.%s", pkg.Name, pkg.Version, pkg.Release, dist, arch),
	)
}

func _tar_compress(dir, pkg_name string) error {

	tar := `
cd ` + dir + `
tar -cvf ` + pkg_name + `.tar .??* *
xz -z -e -9 -v ` + pkg_name + `.tar
mv ` + pkg_name + `.tar.xz ../` + pkg_name + `.txz
`
	if err := _cmd(tar); err != nil {
		return err
	}

	fmt.Printf("OK\n    %s.txz\n\n", pkg_name)

	return nil
}

func _build_source(cfg *ini.ConfigIni) error {

	out, _ := exec.Command("git", "ls-files").Output()
	ls := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, file := range ls {

		info, err := os.Lstat(file)
		if err != nil {
			continue
		}

		if info.IsDir() {
			continue
		}

		dstfile := fmt.Sprintf("./%s/%s", build_src, file)

		if _, fname := filepath.Split(dstfile); ignores.Contain(fname) {
			continue
		}

		if _, err := os.Stat(dstfile); err == nil {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dstfile), 0755); err != nil {
			return err
		}

		if _, err := exec.Command("cp", "-rpf", file, dstfile).Output(); err != nil {
			os.Remove(dstfile)
			return err
		}
	}

	spec_file := fmt.Sprintf("./%s/.lospack/lospack.spec", build_src)
	if err := os.MkdirAll(filepath.Dir(spec_file), 0755); err != nil {
		return err
	}
	if _, err := exec.Command("cp", "-rpf", cfg.File, spec_file).Output(); err != nil {
		return err
	}

	return nil
}

func _lookup_files(txt, suffix string) types.ArrayString {

	ls := strings.Split(txt, "\n")

	var subfiles types.ArrayString

	for _, v := range ls {

		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		v = filepath.Clean(v)
		if _, fname := filepath.Split(v); ignores.Contain(fname) {
			continue
		}

		fps, err := os.Stat(v)
		if err != nil {
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

			_, fvfile := filepath.Split(fv)

			if ignores.Contain(fvfile) || strings.Contains(fv, ".git/") {
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

		if _, err := os.Stat(dstfile); err == nil {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dstfile), 0755); err != nil {
			return err
		}

		cmd := fmt.Sprintf(cmd_str, file, dstfile)

		if out, err := exec.Command("sh", "-c", cmd).Output(); err != nil {

			fmt.Printf("FILE ER (%s) %s %s\n", file, err.Error(), string(out))

			if _, err := exec.Command("cp", "-rpf", file, dstfile).Output(); err != nil {
				os.Remove(dstfile)
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
