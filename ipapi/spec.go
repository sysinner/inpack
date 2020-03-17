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

package ipapi // import "github.com/sysinner/inpack/ipapi"

import (
	"github.com/lessos/lessgo/types"
)

type PackSpec struct {
	Project PackSpecProject `json:"project" toml:"project"`
	Files   PackSpecFiles   `json:"files" toml:"files"`
	Scripts PackSpecScripts `json:"scripts" toml:"scripts"`
}

type PackSpecProject struct {
	Name        string            `json:"name,omitempty" toml:"name,omitempty"`
	Version     types.Version     `json:"version,omitempty" toml:"version,omitempty"`
	Release     types.Version     `json:"release,omitempty" toml:"release,omitempty"`
	Vendor      string            `json:"vendor,omitempty" toml:"vendor,omitempty"`
	License     string            `json:"license,omitempty" toml:"license,omitempty"`
	Homepage    string            `json:"homepage,omitempty" toml:"homepage,omitempty"`
	Source      *PackSpecSource   `json:"source,omitempty" toml:"source,omitempty"`
	Authors     []*PackSpecAuthor `json:"authors,omitempty" toml:"authors,omitempty"`
	Description string            `json:"description,omitempty" toml:"description,omitempty"`
	Groups      []string          `json:"groups,omitempty" toml:"groups,omitempty"`
	Keywords    []string          `json:"keywords,omitempty" toml:"keywords,omitempty"`
}

type PackSpecSource struct {
	Url string `json:"url,omitempty" toml:"url,omitempty"`
}

type PackSpecAuthor struct {
	Name  string `json:"name,omitempty" toml:"name,omitempty"`
	Email string `json:"email,omitempty" toml:"email,omitempty"`
}

type PackSpecScripts struct {
	Build string `json:"build,omitempty" toml:"build,omitempty"`
}

type PackSpecFiles struct {
	Allow        string `json:"allow,omitempty" toml:"allow,omitempty"`
	JsCompress   string `json:"js_compress,omitempty" toml:"js_compress,omitempty"`
	CssCompress  string `json:"css_compress,omitempty" toml:"css_compress,omitempty"`
	HtmlCompress string `json:"html_compress,omitempty" toml:"html_compress,omitempty"`
	PngCompress  string `json:"png_compress,omitempty" toml:"png_compress,omitempty"`
}
