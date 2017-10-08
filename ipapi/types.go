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
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lessos/lessgo/types"
)

const (
	PackageAPIVersion = "0.1.0.dev"
)

var (
	ChannelNameRe   = regexp.MustCompile("^[a-z0-9]{3,10}$")
	ChannelVendorRe = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9-.]{2,49}$")
	PackageNameRe   = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9-_]{1,28}[a-zA-Z0-9]$")
	VersionDistRe   = types.ArrayString([]string{"all", "el7"})
	VersionArchRe   = types.ArrayString([]string{"src", "x64"})
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

type PackageVersion struct {
	Version types.Version `json:"version"`
	Release types.Version `json:"release"`
	Dist    string        `json:"dist,omitempty"` // Distribution name
	Arch    string        `json:"arch,omitempty"` // Computer architecture
}

func (it *PackageVersion) Valid() error {

	if !it.Version.Valid() {
		return errors.New("Invalid Version Value")
	}

	if !it.Release.Valid() {
		return errors.New("Invalid Release Value")
	}

	if !VersionDistRe.Has(it.Dist) {
		return errors.New("Invalid Distribution")
	}

	if !VersionArchRe.Has(it.Arch) {
		return errors.New("Invalid Computer Architecture")
	}

	return nil
}

func (it *PackageVersion) Compare(cp PackageVersion) int {
	if it.Version == cp.Version &&
		it.Release == cp.Release &&
		it.Dist == cp.Dist &&
		it.Arch == cp.Arch {
		return 0
	}
	return 1
}

type PackageProject struct {
	Vendor      string            `json:"vendor,omitempty"` // example.com
	License     string            `json:"license,omitempty"`
	Homepage    string            `json:"homepage,omitempty"`
	Repository  string            `json:"repository,omitempty"`
	Author      string            `json:"author,omitempty"`
	Keywords    types.ArrayString `json:"keywords,omitempty"`
	Description string            `json:"description,omitempty"`
}

type PackageSpec struct {
	Name    string            `json:"name"`
	Version PackageVersion    `json:"version"`
	Project PackageProject    `json:"project,omitempty"`
	Groups  types.ArrayString `json:"groups,omitempty"`
	Labels  types.Labels      `json:"labels,omitempty"`
	Built   types.MetaTime    `json:"built,omitempty"`
}

func (it *PackageSpec) Valid() error {

	if !PackageNameRe.MatchString(it.Name) {
		return errors.New("Invalid Name")
	}

	if err := it.Version.Valid(); err != nil {
		return err
	}

	return nil
}

func PackageFilename(name string, ver PackageVersion) string {
	return fmt.Sprintf(
		"%s-%s-%s.%s.%s",
		name, ver.Version, ver.Release, ver.Dist, ver.Arch,
	)
}

func PackageMetaId(name string, ver PackageVersion) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(PackageFilename(name, ver)))))[:16]
}

type Package struct {
	Meta     types.InnerObjectMeta `json:"meta,omitempty"`
	Version  PackageVersion        `json:"version,omitempty"`
	Project  PackageProject        `json:"project,omitempty"`
	Groups   types.ArrayString     `json:"groups,omitempty"`
	Labels   types.Labels          `json:"labels,omitempty"`
	Channel  string                `json:"channel,omitempty"`
	Built    types.MetaTime        `json:"built,omitempty"`
	Size     int64                 `json:"size,omitempty"`
	SumCheck string                `json:"sum_check,omitempty"`
	OpPerm   uint8                 `json:"op_perm,omitempty"`
}

func (it *Package) Valid() error {

	if !PackageNameRe.MatchString(it.Meta.Name) {
		return errors.New("Invalid Name")
	}

	if err := it.Version.Valid(); err != nil {
		return err
	}

	return nil
}

type PackageList struct {
	types.TypeMeta `json:",inline"`
	Items          []Package `json:"items,omitempty"`
}

type PackageInfo struct {
	types.TypeMeta
	Meta        types.InnerObjectMeta `json:"meta,omitempty"`
	Project     PackageProject        `json:"project,omitempty"`
	LastVersion types.Version         `json:"last_version,omitempty"`
	Groups      types.ArrayString     `json:"groups,omitempty"`
	StatNum     int64                 `json:"stat_num,omitempty"`
	StatSize    int64                 `json:"stat_size,omitempty"`
	Images      types.ArrayString     `json:"images,omitempty"`
	OpPerm      uint8                 `json:"op_perm,omitempty"`
}

type PackageInfoList struct {
	types.TypeMeta `json:",inline"`
	Items          []PackageInfo `json:"items,omitempty"`
}

type PackageInfoIco struct {
	Mime string `json:"mime"`
	Data string `json:"data"`
}

type PackageInfoIcoSet struct {
	types.TypeMeta `json:",inline"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Size           int64  `json:"size"`
	Data           string `json:"data,omitempty"`
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
	VendorName     string                `json:"vendor_name,omitempty"`
	VendorAPI      string                `json:"vendor_api,omitempty"`
	VendorSite     string                `json:"vendor_site,omitempty"`
	Upstream       string                `json:"upstream,omitempty"`
	StatNum        int64                 `json:"stat_num,omitempty"`
	StatSize       int64                 `json:"stat_size,omitempty"`
	Roles          *PackageChannelRoles  `json:"roles,omitempty"`
}

type PackageChannelRoles struct {
	Create types.ArrayUint32 `json:"create,omitempty"`
	Read   types.ArrayUint32 `json:"read,omitempty"`
	Write  types.ArrayUint32 `json:"write,omitempty"`
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

type PackageMultipartCommit struct {
	types.TypeMeta `json:",inline"`
	Name           string         `json:"name"`
	Version        PackageVersion `json:"version"`
	Channel        string         `json:"channel"`
	Size           int64          `json:"size"`
	BlockOffset    int64          `json:"blk_offset"`
	BlockData      string         `json:"blk_data"`
	BlockCrc32     uint32         `json:"blk_crc32"`
}

const (
	OpPermRead   uint8 = 1 << 0
	OpPermWrite  uint8 = 1 << 1
	OpPermCreate uint8 = 1 << 2
	OpPermDelete uint8 = 1 << 3
	OpPermList   uint8 = 1 << 4
	OpPermPut    uint8 = OpPermWrite | OpPermCreate
	OpPermMirror uint8 = OpPermRead | OpPermList
	OpPermAll    uint8 = OpPermRead | OpPermWrite | OpPermCreate | OpPermDelete | OpPermList
)

func OpPermAllow(p, perms uint8) bool {
	return (perms & p) == perms
}
