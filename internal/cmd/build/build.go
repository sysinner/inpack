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

package build // import "github.com/sysinner/inpack/internal/cmd/build"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hooto/hflag4g/hflag"
	"github.com/hooto/htoml4g/htoml"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/inpack/internal/ini"
	"github.com/sysinner/inpack/ipapi"
)

// RHEL, CentOS, RockyLinux
//
//	yum install npm optipng upx
//
// Debian, Ubuntu
//
//	sudo apt-get install npm optipng upx
//
// sudo npm install -g uglify-js clean-css-cli html-minifier esformatter js-beautify
var (
	pack_dir          = ""
	packSpecFile      = "inpack.toml"
	packSpecFilePrev  = "inpack.spec"
	build_tempdir     = ".build_tempdir"
	build_src_tempdir = ".build_src_tempdir"
	argOutputDir      = ""
	packed_spec_dir   = ".inpack"
	packed_spec       = packed_spec_dir + "/inpack.json"
	jscp              = "uglifyjs %s -m -o %s"
	csscp             = "cleancss %s -o %s"
	htmlcp            = "html-minifier -c /tmp/html-minifier.conf %s -o %s"
	pngcp             = "optipng -o7 %s -out %s"
	filecp            = "cp -rpf %s %s"
	cpfiles           types.ArrayString
	ignores           = types.ArrayString{
		".git",
		".gitignore",
		".gitmodules",
		".DS_Store",
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

	if v, ok := hflag.ValueOK("pack_dir"); ok {
		pack_dir = filepath.Clean(v.String()) + "/"
		if _, err := os.Stat(pack_dir); err != nil {
			return fmt.Errorf("pack_dir Not Found")
		}
		fmt.Println("  change dir\n    ", pack_dir)
		os.Chdir(pack_dir)
	}
	pack_dir, _ = filepath.Abs(pack_dir)

	if v, ok := hflag.ValueOK("output"); ok {
		argOutputDir, _ = filepath.Abs(v.String())
		if pack_dir == argOutputDir || len(argOutputDir) < 3 {
			argOutputDir = ""
		} else if st, err := os.Stat(argOutputDir); err != nil || !st.IsDir() {
			argOutputDir = ""
		}
	}

	extName := "txz"
	if v, ok := hflag.ValueOK("compress-name"); ok && v.String() == "gzip" {
		extName = "tgz"
	}

	dist := ""
	arch := "x64"

	if v, ok := hflag.ValueOK("dist"); ok {
		switch v.String() {
		case "linux":
			dist = v.String()

		default:
			return fmt.Errorf("invalid --dist")
		}
	}

	if v, ok := hflag.ValueOK("arch"); ok {
		switch v.String() {
		case "src", "x64":
			arch = v.String()

		default:
			return fmt.Errorf("invalid --arch")
		}
	}

	if dist == "" {
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

		if rs2[0] == "CentOS" || rs2[0] == "RockyLinux" {
			dist = "el"
		} else if rs2[0] == "Debian" {
			dist = "de"
		} else if rs2[0] == "Ubuntu" {
			dist = "ub"
		} else {
			return fmt.Errorf("OS: CentOS/Debian/Ubuntu is required")
		}

		ver := strings.Split(rs2[1], ".")
		if len(ver) == 0 {
			return fmt.Errorf("No OS Version Found")
		}

		switch rs2[0] {

		case "CentOS", "RockyLinux":
			if ver[0] != "7" && ver[0] != "8" && ver[0] != "9" {
				return fmt.Errorf("RHEL Version 7.x/8.x is required")
			}
			dist += ver[0]

		case "Debian":
			return fmt.Errorf("OS not Supported")

		default:
			return fmt.Errorf("OS not Supported")
		}
	}

	var (
		err       error
		specItem  ipapi.PackSpec
		specFile  = ""
		specFiles = []string{
			//
			fmt.Sprintf("./%s", packSpecFile),
			fmt.Sprintf("./.inpack/%s", packSpecFile),
			fmt.Sprintf("./misc/inpack/%s", packSpecFile),
		}
	)

	if v, ok := hflag.ValueOK("spec"); ok {
		spec_file := filepath.Clean(v.String())
		if _, err := os.Stat(spec_file); err != nil {
			return fmt.Errorf("spec file Not Found %s", spec_file)
		}
		specFiles = append([]string{spec_file}, specFiles...)
	}

	for _, v := range specFiles {
		if err = htoml.DecodeFromFile(v, &specItem); err == nil {
			specFile = v
			break
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	if specItem.Project.Name == "" {

		var (
			cfg           *ini.ConfigIni
			specFilesPrev = []string{
				fmt.Sprintf("./%s", packSpecFilePrev),
				fmt.Sprintf("./.inpack/%s", packSpecFilePrev),
				fmt.Sprintf("./misc/inpack/%s", packSpecFilePrev),
			}
		)

		for _, v := range specFilesPrev {
			if cfg, err = ini.ConfigIniParse(v); err == nil {
				specFile = strings.Replace(v, packSpecFilePrev, packSpecFile, -1)
				break
			}
		}

		if cfg == nil {
			return fmt.Errorf("No SPEC File Found")
		}

		specItem.Project = ipapi.PackSpecProject{
			Name:        cfg.Get("project/name").String(),
			Release:     types.Version(cfg.Get("project/release").String()),
			Version:     types.Version(cfg.Get("project/version").String()),
			Vendor:      cfg.Get("project/vendor").String(),
			License:     cfg.Get("project/license").String(),
			Homepage:    cfg.Get("project/homepage").String(),
			Description: cfg.Get("project/description").String(),
		}

		if len(cfg.Get("project/groups").String()) > 1 {
			specItem.Project.Groups = strings.Split(cfg.Get("project/groups").String(), ",")
		}

		if len(cfg.Get("project/keywords").String()) > 1 {
			specItem.Project.Keywords = strings.Split(cfg.Get("project/keywords").String(), ",")
		}

		if cfg.Get("project/repository").String() != "" {
			specItem.Project.Source = &ipapi.PackSpecSource{
				Url: cfg.Get("project/repository").String(),
			}
		}

		if cfg.Get("project/author").String() != "" {
			specItem.Project.Authors = append(specItem.Project.Authors, &ipapi.PackSpecAuthor{
				Name: cfg.Get("project/author").String(),
			})
		}

		specItem.Files = ipapi.PackSpecFiles{
			Allow:        cfg.Get("files").String(),
			JsCompress:   cfg.Get("js_compress").String(),
			CssCompress:  cfg.Get("css_compress").String(),
			HtmlCompress: cfg.Get("html_compress").String(),
			PngCompress:  cfg.Get("png_compress").String(),
		}

		if v := cfg.Get("build").String(); v != "" {
			specItem.Scripts.Build = v + "\n"
		}

		if err := htoml.EncodeToFile(specItem, specFile, &htoml.EncodeOptions{
			Indent: "",
		}); err != nil {
			return err
		}
	}

	if v, ok := hflag.ValueOK("version"); ok {
		specItem.Project.Version = types.Version(v.String())
	}

	if v, ok := hflag.ValueOK("release"); ok {
		specItem.Project.Release = types.Version(v.String())
	} else if specItem.Project.Release == "" {
		specItem.Project.Release = "1"
	}

	//
	pkg := ipapi.PackBuild{
		Name: specItem.Project.Name,
		Version: ipapi.PackVersion{
			Version: specItem.Project.Version,
			Release: specItem.Project.Release,
			Dist:    dist,
			Arch:    arch,
		},
		Project: ipapi.PackSpecProject{
			Vendor:      specItem.Project.Vendor,
			License:     specItem.Project.License,
			Homepage:    specItem.Project.Homepage,
			Source:      specItem.Project.Source,
			Authors:     specItem.Project.Authors,
			Description: specItem.Project.Description,
			Keywords:    specItem.Project.Keywords,
		},
		Groups: specItem.Project.Groups,
		Built:  types.MetaTimeNow(),
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
	if _, ok := hflag.ValueOK("build_src"); ok {

		targetName := ipapi.PackFilename(pkg.Name, pkg.Version)

		target_path := targetName + "." + extName
		if argOutputDir != "" {
			target_path = argOutputDir + "/" + target_path
		}

		if _, err := os.Stat(target_path); err != nil {

			if err := buildSource(&specItem, specFile); err == nil {

				//
				if err := json.EncodeToFile(pkg, fmt.Sprintf("%s/%s", build_src_tempdir, packed_spec), "  "); err != nil {
					return err
				}

				if err := tarCompress(build_src_tempdir, targetName, extName); err != nil {
					return err
				}

				if argOutputDir != "" {
					if err = os.Rename(targetName+"."+extName, argOutputDir+"/"+targetName+"."+extName); err != nil {
						return err
					}
				}
			}
			os.RemoveAll(build_src_tempdir)
		} else {
			fmt.Printf("  Target Pack (%s) already existed\n", target_path)
		}
	}

	if v, ok := hflag.ValueOK("build_dir"); ok && v.String() != "" {
		build_tempdir = v.String()
	}
	build_tempdir, err = filepath.Abs(build_tempdir)
	if err != nil {
		return err
	}

	//
	pkg.Version.Dist = dist
	pkg.Version.Arch = arch

	if _, ok := hflag.ValueOK("build_nocompress"); !ok {
		target_path := ipapi.PackFilename(pkg.Name, pkg.Version) + "." + extName
		if argOutputDir != "" {
			target_path = argOutputDir + "/" + target_path
		}
		if _, err := os.Stat(target_path); err == nil {
			fmt.Printf("  Target Pack (%s) already existed\n", target_path)
			return nil
		}
	}

	os.Mkdir(build_tempdir, 0755)

	subfiles := lookupFiles(specItem.Files.JsCompress, ".js")
	if err := _compress(subfiles, jscp); err != nil {
		return fmt.Errorf("JsCompress %s", err.Error())
	}

	subfiles = lookupFiles(specItem.Files.CssCompress, ".css")
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

		subfiles = lookupFiles(specItem.Files.HtmlCompress, ".html")
		if err := _compress(subfiles, htmlcp); err != nil {
			return fmt.Errorf("HtmlCompress %s", err.Error())
		}

		subfiles = lookupFiles(specItem.Files.HtmlCompress, ".tpl")
		if err := _compress(subfiles, htmlcp); err != nil {
			return fmt.Errorf("HtmlCompress %s", err.Error())
		}
	}

	subfiles = lookupFiles(specItem.Files.PngCompress, ".png")
	if err := _compress(subfiles, pngcp); err != nil {
		return fmt.Errorf("PngCompress %s", err.Error())
	}

	subfiles = lookupFiles(specItem.Files.Allow, "")
	if err := _compress(subfiles, filecp); err != nil {
		return fmt.Errorf("FileCopy %s", err.Error())
	}

	os.MkdirAll(fmt.Sprintf("%s/%s", build_tempdir, packed_spec_dir), 0755)

	if len(specItem.Scripts.Build) > 0 {

		scriptParams := map[string]string{
			"inpack__pack_dir": pack_dir,
			"buildroot":        build_tempdir,
			"project__version": string(pkg.Version.Version),
			"project__release": string(pkg.Version.Release),
			"project__dist":    dist,
			"project__arch":    arch,
			"project__prefix":  "/opt/" + pkg.Name,
		}

		build := specItem.Scripts.Build

		for k, v := range scriptParams {
			build = strings.Replace(build, "{{."+k+"}}", v, -1)
		}

		if _, ok := hflag.ValueOK("show-build"); ok {
			fmt.Printf(" BuildScript >>>\n%s\n<<<\n", build)
		}

		if err := _cmd(build); err != nil {
			return err
		}
	}

	//
	if err := json.EncodeToFile(pkg, fmt.Sprintf("%s/%s", build_tempdir, packed_spec), "  "); err != nil {
		return err
	}

	if _, ok := hflag.ValueOK("build_nocompress"); !ok {
		targetName := ipapi.PackFilename(pkg.Name, pkg.Version)
		if err = tarCompress(build_tempdir, targetName, extName); err != nil {
			return err
		}
		if argOutputDir != "" {
			if err = os.Rename(targetName+"."+extName, argOutputDir+"/"+targetName+"."+extName); err != nil {
				return err
			}
		}
		os.RemoveAll(build_tempdir)
	}

	return nil
}

func tarCompress(dir, pkgName, extName string) error {

	cmdScript := `
cd ` + dir + `
tar -cvf ` + pkgName + `.tar .??* *
`

	switch extName {
	case "txz":
		cmdScript += `
xz -z -e -9 -v ` + pkgName + `.tar
mv ` + pkgName + `.tar.xz ../` + pkgName + `.txz
`
	case "tgz":
		cmdScript += `
gzip -9 ` + pkgName + `.tar
mv ` + pkgName + `.tar.gz ../` + pkgName + `.tgz
`
	}

	if err := _cmd(cmdScript); err != nil {
		return err
	}

	fmt.Printf("  OK\n    %s.%s\n\n", pkgName, extName)

	return nil
}

func buildSource(specItem *ipapi.PackSpec, specFile string) error {

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

		if _, fname := filepath.Split(dstfile); ignores.Has(fname) {
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

	specFileTarget := fmt.Sprintf("./%s/%s/%s", build_src_tempdir, packed_spec_dir, packSpecFile)
	if err := os.MkdirAll(filepath.Dir(specFileTarget), 0755); err != nil {
		return err
	}
	if _, err := exec.Command("cp", "-rpf", specFile, specFileTarget).Output(); err != nil {
		return err
	}

	return nil
}

func lookupFiles(txt, suffix string) types.ArrayString {

	var subfiles types.ArrayString

	ls := strings.Split(txt, "\n")

	for _, v := range ls {

		v = strings.TrimSpace(v)
		if v == "" || v == "/" {
			continue
		}

		if v[0] == '/' {
			v = strings.TrimLeft(v, "/")
		}

		suffix2 := ""

		if suffix == "" {
			if n := strings.LastIndex(v, "/*."); n > 0 && (n+3) < len(v) {
				suffix2 = v[n+3:]
				v = v[:n]
			}
		}

		v = filepath.Clean(v)
		if _, fname := filepath.Split(v); ignores.Has(fname) {
			continue
		}

		fps, err := os.Stat(v)
		if err != nil {
			continue
		}

		if !fps.IsDir() {

			if suffix == "" || (suffix != "" && strings.HasSuffix(v, suffix)) {

				if !cpfiles.Has(v) {
					subfiles.Set(v)
					cpfiles.Set(v)
				}
			}

			continue
		}

		var out []byte
		if suffix2 != "" {
			out, _ = exec.Command("find", v+"/", "-type", "f", "-name", "*"+suffix2).Output()
		} else if suffix != "" {
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

			if ignores.Has(fvfile) || strings.Contains(fv, ".git/") {
				continue
			}

			if suffix != "" && !strings.HasSuffix(fv, suffix) {
				continue
			}

			if !cpfiles.Has(fv) {
				subfiles.Set(fv)
				cpfiles.Set(fv)
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

	if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil {
		scriptShow := ""
		if hflag.Value("show_script").String() == "true" {
			scriptShow = fmt.Sprintf(" Script >>> %s <<<", script)
		}
		return fmt.Errorf("Error %s\nMessage %s\n%s\n",
			err.Error(), string(out), scriptShow)
	}

	return nil
}
