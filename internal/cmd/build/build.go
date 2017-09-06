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

package build // import "github.com/lessos/lospack/internal/cmd/build"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/lessos/lospack/internal/cliflags"
	"github.com/lessos/lospack/internal/ini"
	"github.com/lessos/lospack/lpapi"
)

// yum install npm optipng
// npm install uglify-js -g
// npm install clean-css-cli -g
// npm install html-minifier -g
var (
	pack_dir          = ""
	pack_spec         = "lospack.spec"
	build_tempdir     = ".build_tempdir"
	build_src_tempdir = ".build_src_tempdir"
	arg_output_dir    = ""
	packed_spec_dir   = ".lospack"
	packed_spec       = packed_spec_dir + "/lospack.json"
	jscp              = "uglifyjs %s -c -m -o %s"
	csscp             = "cleancss --skip-rebase %s -o %s"
	htmlcp            = "html-minifier -c /tmp/html-minifier.conf %s -o %s"
	pngcp             = "optipng -o7 %s -out %s"
	filecp            = "cp -rpf %s %s"
	cpfiles           types.ArrayString
	ignores           = types.ArrayString{
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

	if v, ok := cliflags.Value("pack_dir"); ok {
		pack_dir = filepath.Clean(v.String()) + "/"
		if _, err := os.Stat(pack_dir); err != nil {
			return fmt.Errorf("pack_dir Not Found")
		}
		fmt.Println("  change dir\n    ", pack_dir)
		os.Chdir(pack_dir)
	}
	pack_dir, _ = filepath.Abs(pack_dir)

	if v, ok := cliflags.Value("output"); ok {
		arg_output_dir, _ = filepath.Abs(v.String())
		if pack_dir == arg_output_dir || len(arg_output_dir) < 3 {
			arg_output_dir = ""
		} else if st, err := os.Stat(arg_output_dir); err != nil || !st.IsDir() {
			arg_output_dir = ""
		}
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
			fmt.Sprintf("./.lospack/%s", pack_spec),
			fmt.Sprintf("./%s", pack_spec),
			fmt.Sprintf("./misc/lospack/%s", pack_spec),
		}
	)

	if v, ok := cliflags.Value("spec"); ok {
		spec_files = append([]string{v.String()}, spec_files...)
	}

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

	cfg.Set("project.dist", dist)

	//
	pkg := lpapi.PackageSpec{
		Name: cfg.Get("project.name").String(),
		Version: lpapi.PackageVersion{
			Version: types.Version(cfg.Get("project.version").String()),
			Release: types.Version(cfg.Get("project.release").String()),
			Dist:    "all", // dist,
			Arch:    "src", // arch,
		},
		Project: lpapi.PackageProject{
			Vendor:      cfg.Get("project.vendor").String(),
			License:     cfg.Get("project.license").String(),
			Homepage:    cfg.Get("project.homepage").String(),
			Repository:  cfg.Get("project.repository").String(),
			Author:      cfg.Get("project.author").String(),
			Description: cfg.Get("project.description").String(),
		},
		Built: types.MetaTimeNow(),
	}
	groups := strings.Split(cfg.Get("project.groups").String(), ",")
	for _, v := range groups {
		pkg.Groups.Set(v)
	}
	tags := strings.Split(cfg.Get("project.keywords").String(), ",")
	for _, v := range tags {
		pkg.Project.Keywords.Set(v)
	}

	fmt.Printf(`
Building
  package: %s
  version: %s
  release: %s
  dist:    %s
  arch:    %s
  vendor:  %s
`,
		pkg.Name,
		pkg.Version.Version,
		pkg.Version.Release,
		dist,
		arch,
		pkg.Project.Vendor,
	)

	//
	if _, ok := cliflags.Value("build_src"); ok {

		target_name := lpapi.PackageFilename(pkg.Name, pkg.Version)

		target_path := target_name + ".txz"
		if arg_output_dir != "" {
			target_path = arg_output_dir + "/" + target_path
		}

		if _, err := os.Stat(target_path); err != nil {

			if err := _build_source(cfg); err == nil {

				//
				if err := json.EncodeToFile(pkg, fmt.Sprintf("%s/%s", build_src_tempdir, packed_spec), "  "); err != nil {
					return err
				}

				if err := _tar_compress(build_src_tempdir, target_name); err != nil {
					return err
				}

				if arg_output_dir != "" {
					if err = os.Rename(target_name+".txz", arg_output_dir+"/"+target_name+".txz"); err != nil {
						return err
					}
				}
			}
			os.RemoveAll(build_src_tempdir)
		} else {
			fmt.Printf("  Target Package (%s) already existed\n", target_path)
		}
	}

	if v, ok := cliflags.Value("build_dir"); ok && v.String() != "" {
		build_tempdir = v.String()
	}
	build_tempdir, err = filepath.Abs(build_tempdir)
	if err != nil {
		return err
	}

	//
	pkg.Version.Dist = dist
	pkg.Version.Arch = arch

	if _, ok := cliflags.Value("build_nocompress"); !ok {
		target_path := lpapi.PackageFilename(pkg.Name, pkg.Version) + ".txz"
		if arg_output_dir != "" {
			target_path = arg_output_dir + "/" + target_path
		}
		if _, err := os.Stat(target_path); err == nil {
			fmt.Printf("  Target Package (%s) already existed\n", target_path)
			return nil
		}
	}

	cfg.Params("lospack__pack_dir", pack_dir)
	cfg.Params("buildroot", build_tempdir)
	cfg.Params("project__version", string(pkg.Version.Version))
	cfg.Params("project__release", string(pkg.Version.Release))
	cfg.Params("project__dist", dist)
	cfg.Params("project__arch", arch)
	cfg.Params("project__prefix", "/home/action/apps/"+pkg.Name)

	os.Mkdir(build_tempdir, 0755)

	subfiles := _lookup_files(cfg.Get("js_compress").String(), ".js")
	if err := _compress(subfiles, jscp); err != nil {
		return fmt.Errorf("JsCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("css_compress").String(), ".css")
	if err := _compress(subfiles, csscp); err != nil {
		return fmt.Errorf("CssCompress %s", err.Error())
	}

	{
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

		subfiles = _lookup_files(cfg.Get("html_compress").String(), ".html")
		if err := _compress(subfiles, htmlcp); err != nil {
			return fmt.Errorf("HtmlCompress %s", err.Error())
		}

		subfiles = _lookup_files(cfg.Get("html_compress").String(), ".tpl")
		if err := _compress(subfiles, htmlcp); err != nil {
			return fmt.Errorf("HtmlCompress %s", err.Error())
		}
	}

	subfiles = _lookup_files(cfg.Get("png_compress").String(), ".png")
	if err := _compress(subfiles, pngcp); err != nil {
		return fmt.Errorf("PngCompress %s", err.Error())
	}

	subfiles = _lookup_files(cfg.Get("files").String(), "")
	if err := _compress(subfiles, filecp); err != nil {
		return fmt.Errorf("FileCopy %s", err.Error())
	}

	os.MkdirAll(fmt.Sprintf("%s/%s", build_tempdir, packed_spec_dir), 0755)

	if err := _cmd(cfg.Get("build").String()); err != nil {
		return err
	}

	//
	if err := json.EncodeToFile(pkg, fmt.Sprintf("%s/%s", build_tempdir, packed_spec), "  "); err != nil {
		return err
	}

	if _, ok := cliflags.Value("build_nocompress"); !ok {
		target_name := lpapi.PackageFilename(pkg.Name, pkg.Version)
		if err = _tar_compress(build_tempdir, target_name); err != nil {
			return err
		}
		if arg_output_dir != "" {
			if err = os.Rename(target_name+".txz", arg_output_dir+"/"+target_name+".txz"); err != nil {
				return err
			}
		}
		os.RemoveAll(build_tempdir)
	}

	return nil
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

	fmt.Printf("  OK\n    %s.txz\n\n", pkg_name)

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

		dstfile := fmt.Sprintf("./%s/%s", build_src_tempdir, file)

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

	spec_file := fmt.Sprintf("./%s/%s/%s", build_src_tempdir, packed_spec_dir, pack_spec)
	if err := os.MkdirAll(filepath.Dir(spec_file), 0755); err != nil {
		return err
	}
	if _, err := exec.Command("cp", "-rpf", cfg.File, spec_file).Output(); err != nil {
		return err
	}

	return nil
}

func _lookup_files(txt, suffix string) types.ArrayString {

	var subfiles types.ArrayString

	ls := strings.Split(txt, "\n")

	for _, v := range ls {

		v = strings.TrimSpace(v)
		if v == "" || v == "/" {
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
			out, _ = exec.Command("find", v+"/", "-type", "f", "-name", "*"+suffix).Output()
		} else {
			out, _ = exec.Command("find", v+"/", "-type", "f").Output()
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

		dstfile := fmt.Sprintf("%s/%s", build_tempdir, file)

		if _, err := os.Stat(dstfile); err == nil {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dstfile), 0755); err != nil {
			return err
		}

		cmd := fmt.Sprintf(cmd_str, file, dstfile)

		if out, err := exec.Command("sh", "-c", cmd).Output(); err != nil {

			fmt.Printf("  FILE ER (%s) %s %s\n", file, err.Error(), string(out))

			if _, err := exec.Command("cp", "-rpf", file, dstfile).Output(); err != nil {
				os.Remove(dstfile)
				return err
			} else {
				fmt.Println("  FILE ER-OK", file)
			}
		} else {
			fmt.Println("  FILE OK", file)
		}
	}

	return nil
}

func _cmd(script string) error {

	script = "set -e\nset -o pipefail\n" + script + "\nexit 0\n"

	if out, err := exec.Command("bash", "-c", script).Output(); err != nil {
		return fmt.Errorf("CMD ERR(%s) %s\nSCRIPT: %s", err.Error(), string(out), script)
	}

	return nil
}
