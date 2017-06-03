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

package lpapi // import "code.hooto.com/lessos/lospack/lpapi"

import (
	"github.com/lessos/lessgo/types"
)

const (
	PackageAPIVersion = "0.1.0.dev"
)

var (
	PackageGroups = types.Labels{
		// for Application
		{
			Name:  "app/biz",
			Value: "Business",
		},
		{
			Name:  "app/co",
			Value: "Collaboration",
		},
		{
			Name:  "app/prod",
			Value: "Productivity",
		},
		{
			Name:  "app/dev",
			Value: "Development Tools",
		},
		{
			Name:  "app/other",
			Value: "App Others",
		},
		// for Development
		{
			Name:  "dev/web-static",
			Value: "Web Frontend Static Library",
		},
		{
			Name:  "dev/web-lib",
			Value: "Web Backend Library",
		},
		{
			Name:  "dev/sys-lib",
			Value: "System Library",
		},
		{
			Name:  "dev/db",
			Value: "Database Server or Service",
		},
		{
			Name:  "dev/stor",
			Value: "Storage Server or Service",
		},
		{
			Name:  "dev/sys-srv",
			Value: "System Server or Service",
		},
		{
			Name:  "dev/sys-runtime",
			Value: "System Runtime Environments",
		},
		{
			Name:  "dev/other",
			Value: "Dev Others",
		},
	}
)

type PackageSpec struct {
	Name        string            `json:"name"`
	Version     types.Version     `json:"version"`
	Release     types.Version     `json:"release"`
	Groups      types.ArrayString `json:"groups,omitempty"`
	Description string            `json:"description,omitempty"`
	License     string            `json:"license,omitempty"`
	Vendor      string            `json:"vendor,omitempty"` // example.com
	Homepage    string            `json:"homepage,omitempty"`
	Keywords    types.ArrayString `json:"keywords,omitempty"`
	PkgOS       string            `json:"pkg_os,omitempty"`
	PkgArch     string            `json:"pkg_arch,omitempty"`
	Options     types.Labels      `json:"options,omitempty"`
	Created     types.MetaTime    `json:"created,omitempty"`
}

type Package struct {
	Meta        types.InnerObjectMeta `json:"meta,omitempty"`
	Version     types.Version         `json:"version,omitempty"`
	Release     types.Version         `json:"release,omitempty"`
	Description string                `json:"description,omitempty"`
	Vendor      string                `json:"vendor,omitempty"`
	License     string                `json:"license,omitempty"`
	PkgOS       string                `json:"pkg_os,omitempty"`
	PkgArch     string                `json:"pkg_arch,omitempty"`
	PkgSize     int64                 `json:"pkg_size,omitempty"`
	PkgSum      string                `json:"pkg_sum,omitempty"`
	Groups      types.ArrayString     `json:"groups,omitempty"`
	Options     types.Labels          `json:"options,omitempty"`
	Homepage    string                `json:"homepage,omitempty"`
	Keywords    []string              `json:"keywords,omitempty"`
	Built       types.MetaTime        `json:"built,omitempty"`
	Channel     string                `json:"channel,omitempty"`
}

type PackageList struct {
	types.TypeMeta `json:",inline"`
	Items          []Package `json:"items,omitempty"`
}

type PackageInfo struct {
	types.TypeMeta
	Meta        types.InnerObjectMeta `json:"meta,omitempty"`
	Description string                `json:"description,omitempty"`
	LastVersion types.Version         `json:"last_version,omitempty"`
	LastRelease types.Version         `json:"last_release,omitempty"`
	Groups      types.ArrayString     `json:"groups,omitempty"`
	PkgNum      int                   `json:"pkg_num,omitempty"`
	Homepage    string                `json:"homepage,omitempty"`
}

type PackageInfoList struct {
	types.TypeMeta `json:",inline"`
	Items          []PackageInfo `json:"items,omitempty"`
}

type PackageGroup struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type PackageGroupList struct {
	types.TypeMeta `json:",inline"`
	Items          types.Labels `json:"items,omitempty"`
}

type PackageChannel struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`
	Type           string                `json:"type,omitempty"`
	Packages       int64                 `json:"packages,omitempty"`
	VendorName     string                `json:"vendor_name,omitempty"`
	VendorAPI      string                `json:"vendor_api,omitempty"`
	VendorSite     string                `json:"vendor_site,omitempty"`
	Upstream       string                `json:"upstream,omitempty"`
}

type PackageChannelList struct {
	types.TypeMeta `json:",inline"`
	Items          []PackageChannel `json:"items,omitempty"`
}

type PackageCommit struct {
	types.TypeMeta `json:",inline"`
	Name           string `json:"name"`
	Size           int64  `json:"size"`
	Channel        string `json:"channel"`
	Data           string `json:"data"`
	SumCheck       string `json:"sumcheck"`
	AutoRelease    bool   `json:"auto_release"`
	GitVersion     string `json:"git_version"`
}

type Version struct {
	Version string `json:"version"`
	Release string `json:"release"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Sum     string `json:"sum"`
}
