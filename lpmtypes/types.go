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

package lpmtypes

import (
	"github.com/lessos/lessgo/types"
)

const (
	PackageAPIVersion = "0.2.0.dev"

	PackageGroupAppBusiness      = "50" // Business Applications
	PackageGroupAppCollaboration = "51" // Collaboration Applications
	PackageGroupAppProductivity  = "52" // Productivity Applications
	PackageGroupAppDevelop       = "53" // Development Tools

	PackageGroupDevWebStatic  = "60" // Web Frontend Static Library, Framework
	PackageGroupDevWebLibrary = "61" // Web Backend Library, Framework
	PackageGroupDevSysLibrary = "70" // System Library
	PackageGroupDevSysService = "71" // System Server, Service
	PackageGroupDevSysRuntime = "72" // System Runtime Languages, Environments
	PackageGroupDevOther      = "79" // Unknown Type
)

var (
	PackageGroupApp = []PackageGroup{
		{PackageGroupAppBusiness, "Business", "Business Applications"},
		{PackageGroupAppCollaboration, "Collaboration", "Collaboration Applications"},
		{PackageGroupAppProductivity, "Productivity", "Productivity Applications"},
		{PackageGroupAppDevelop, "Development", "Development Tools"},
	}
	PackageGroupDev = []PackageGroup{
		{PackageGroupDevWebStatic, "Frontend", "Web Frontend Static Library, Framework"},
		{PackageGroupDevWebLibrary, "Backend", "Web Backend Library, Framework"},
		{PackageGroupDevSysLibrary, "Library", "System Library"},
		{PackageGroupDevSysService, "Service", "System Server, Service"},
		{PackageGroupDevSysRuntime, "Runtime", "System Runtime Languages, Environments"},
		{PackageGroupDevOther, "Unknown", "Unknown Type"},
	}
)

type PackageGroup struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Package struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`
	Vendor         string                `json:"vendor,omitempty"`
	Version        string                `json:"version,omitempty"`
	Release        string                `json:"release,omitempty"`
	Description    string                `json:"description,omitempty"`
	License        string                `json:"license,omitempty"`
	GrpApp         string                `json:"grp_app,omitempty"`
	GrpDev         string                `json:"grp_dev,omitempty"`
	PkgOS          string                `json:"pkg_os,omitempty"`
	PkgArch        string                `json:"pkg_arch,omitempty"`
	PkgSize        int64                 `json:"pkg_size,omitempty"`
	PkgSum         string                `json:"pkg_sum,omitempty"`
	GroupApp       []PackageGroup        `json:"group_app,omitempty"`
	GroupDev       []PackageGroup        `json:"group_dev,omitempty"`
	Options        types.Labels          `json:"options,omitempty"`
	Homepage       string                `json:"homepage,omitempty"`
	Keywords       []string              `json:"keywords,omitempty"`
}

type PackageList struct {
	types.TypeMeta `json:",inline"`
	Items          []Package `json:"items,omitempty"`
}
