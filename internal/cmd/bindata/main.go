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

package bindata

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hooto/hflag4g/hflag"
	"github.com/lessos/lessgo/types"
)

// RHEL, CentOS
//   yum install npm optipng upx
// Debian, Ubuntu
//   sudo apt-get install npm optipng upx
//
// sudo npm install -g uglify-js clean-css-cli html-minifier esformatter js-beautify
var (
	argSrc  = ""
	argDst  = ""
	argInc  = "*"
	tmpDir  = ".bindata_temp_dir"
	jscp    = "uglifyjs %s -m -o %s"
	csscp   = "cleancss --skip-rebase %s -o %s"
	htmlcp  = "html-minifier -c /tmp/html-minifier.conf %s -o %s"
	pngcp   = "optipng -o7 %s -out %s"
	filecp  = "cp -rpf %s %s"
	cpfiles types.ArrayString
	ignores = types.ArrayString{
		".git",
		".gitignore",
		".gitmodules",
	}
	htmlcpConf = `{
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
	err error
)

func Cmd() error {

	if v, ok := hflag.ValueOK("src"); !ok {
		return errors.New("src not found")
	} else {
		argSrc, _ = filepath.Abs(v.String())
	}

	if v, ok := hflag.ValueOK("dst"); !ok {
		return errors.New("dst not found")
	} else {
		argDst, _ = filepath.Abs(v.String())
	}

	if v, ok := hflag.ValueOK("inc"); ok {
		argInc = v.String()
	}

	os.RemoveAll(tmpDir)

	out, err := exec.Command("cp", "-rpf", argSrc, tmpDir).Output()
	if err != nil {
		return errors.New(err.Error() + string(out))
	}

	{
		subfiles := lookupFiles(tmpDir, ".js")
		if err := cmdCompress(subfiles, jscp); err != nil {
			return fmt.Errorf("JsCompress %s", err.Error())
		}

		subfiles = lookupFiles(tmpDir, ".css")
		if err := cmdCompress(subfiles, csscp); err != nil {
			return fmt.Errorf("CssCompress %s", err.Error())
		}
	}

	{
		cfp, err := os.OpenFile("/tmp/html-minifier.conf", os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer cfp.Close()

		cfp.Seek(0, 0)
		cfp.Truncate(0)

		if _, err := cfp.Write([]byte(htmlcpConf)); err != nil {
			return err
		}

		subfiles := lookupFiles(tmpDir, ".html")
		if err := cmdCompress(subfiles, htmlcp); err != nil {
			return fmt.Errorf("HtmlCompress %s", err.Error())
		}

		subfiles = lookupFiles(tmpDir, ".tpl")
		if err := cmdCompress(subfiles, htmlcp); err != nil {
			return fmt.Errorf("HtmlCompress %s", err.Error())
		}
	}

	{
		subfiles := lookupFiles(tmpDir, ".png")
		if err := cmdCompress(subfiles, pngcp); err != nil {
			return fmt.Errorf("PngCompress %s", err.Error())
		}
	}

	pkgName := strings.TrimRight(argDst, "/")
	if n := strings.LastIndex(pkgName, "/"); n > 0 {
		pkgName = pkgName[n+1:]
		argDst = argDst[:n]
	}

	binArgs := []string{
		"-src", tmpDir,
		"-dest", argDst,
		"-p", pkgName,
		"-ns", pkgName,
		"-f",
	}

	if argInc != "*" {
		incs := strings.Split(argInc, ",")
		for i, v := range incs {
			if !strings.HasPrefix(v, "*.") {
				incs[i] = "*." + v
			}
		}
		binArgs = append(binArgs, "-include")
		binArgs = append(binArgs, strings.Join(incs, ","))
	}

	_, err = exec.Command("statik", binArgs...).Output()

	if err == nil {
		os.RemoveAll(tmpDir)
	}

	return err
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

func cmdCompress(ls types.ArrayString, cmd_str string) error {

	for _, file := range ls {

		cmd := fmt.Sprintf(cmd_str, file, file)

		if _, err := exec.Command("sh", "-c", cmd).Output(); err != nil {
			fmt.Println("  FILE ER-OK", file)
		} else {
			fmt.Println("  FILE OK", file)
		}
	}

	return nil
}
