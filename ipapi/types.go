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
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lessos/lessgo/types"
)

const (
	PackAPIVersion = "0.1.0.dev"
)

var (
	ChannelNameRe   = regexp.MustCompile("^[a-z0-9]{3,10}$")
	ChannelVendorRe = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9-.]{2,49}$")
	PackNameRe      = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9-_]{1,28}[a-zA-Z0-9]$")
	VersionDistRe   = types.ArrayString([]string{"all", "linux", "el7", "el8"})
	VersionArchRe   = types.ArrayString([]string{"src", "x64"})
)

var (
	PackGroups = types.Labels{
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

type PackVersion struct {
	Version types.Version `json:"version" toml:"version"`
	Release types.Version `json:"release" toml:"release"`
	Dist    string        `json:"dist,omitempty" toml:"dist,omitempty"` // Distribution name
	Arch    string        `json:"arch,omitempty" toml:"arch,omitempty"` // Computer architecture
}

func (it *PackVersion) Valid() error {

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

func (it *PackVersion) Compare(cp PackVersion) int {
	if it.Version == cp.Version &&
		it.Release == cp.Release &&
		it.Dist == cp.Dist &&
		it.Arch == cp.Arch {
		return 0
	}
	return 1
}

func (it *PackVersion) HashString() string {
	return strings.ToLower(fmt.Sprintf("%s-%s.%s.%s",
		it.Version,
		it.Release,
		it.Dist,
		it.Arch))
}

type PackBuild struct {
	Name    string            `json:"name" toml:"name"`
	Version PackVersion       `json:"version" toml:"version"`
	Project PackSpecProject   `json:"project,omitempty" toml:"project,omitempty"`
	Groups  types.ArrayString `json:"groups,omitempty" toml:"groups,omitempty"`
	Labels  types.Labels      `json:"labels,omitempty" toml:"labels,omitempty"`
	Built   types.MetaTime    `json:"built,omitempty" toml:"built,omitempty"`
}

func (it *PackBuild) Valid() error {

	if !PackNameRe.MatchString(it.Name) {
		return errors.New("Invalid Name")
	}

	if err := it.Version.Valid(); err != nil {
		return err
	}

	return nil
}

func PackFilename(name string, ver PackVersion) string {
	return fmt.Sprintf(
		"%s-%s-%s.%s.%s",
		name, ver.Version, ver.Release, ver.Dist, ver.Arch,
	)
}

func PackFilenameKey(name string, ver PackVersion) string {
	return strings.ToLower(PackFilename(name, ver))
}

func PackNameValid(name string) error {
	if !PackNameRe.MatchString(name) {
		return errors.New("Invalid Name")
	}
	return nil
}

type Pack struct {
	Meta     types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`
	Version  PackVersion           `json:"version,omitempty" toml:"version,omitempty"`
	Project  PackSpecProject       `json:"project,omitempty" toml:"project,omitempty"`
	Groups   types.ArrayString     `json:"groups,omitempty" toml:"groups,omitempty"`
	Labels   types.Labels          `json:"labels,omitempty" toml:"labels,omitempty"`
	Channel  string                `json:"channel,omitempty" toml:"channel,omitempty"`
	Built    types.MetaTime        `json:"built,omitempty" toml:"built,omitempty"`
	Size     int64                 `json:"size,omitempty" toml:"size,omitempty"`
	SumCheck string                `json:"sum_check,omitempty" toml:"sum_check,omitempty"`
	OpPerm   uint8                 `json:"op_perm,omitempty" toml:"op_perm,omitempty"`
}

func (it *Pack) Valid() error {

	if !PackNameRe.MatchString(it.Meta.Name) {
		return errors.New("Invalid Name")
	}

	if err := it.Version.Valid(); err != nil {
		return err
	}

	return nil
}

type PackList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []Pack `json:"items,omitempty" toml:"items,omitempty"`
}

type PackInfo struct {
	types.TypeMeta
	Meta        types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`
	Project     PackSpecProject       `json:"project,omitempty" toml:"project,omitempty"`
	LastVersion types.Version         `json:"last_version,omitempty" toml:"last_version,omitempty"`
	Groups      types.ArrayString     `json:"groups,omitempty" toml:"groups,omitempty"`
	StatNum     int64                 `json:"stat_num,omitempty" toml:"stat_num,omitempty"`
	StatSize    int64                 `json:"stat_size,omitempty" toml:"stat_size,omitempty"`
	StatNumOff  int64                 `json:"stat_num_off,omitempty" toml:"stat_num_off,omitempty"`
	StatSizeOff int64                 `json:"stat_size_off,omitempty" toml:"stat_size_off,omitempty"`
	Images      types.ArrayString     `json:"images,omitempty" toml:"images,omitempty"`
	OpPerm      uint8                 `json:"op_perm,omitempty" toml:"op_perm,omitempty"`
}

type PackInfoList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []PackInfo `json:"items,omitempty" toml:"items,omitempty"`
}

type PackInfoIcon struct {
	Mime string `json:"mime" toml:"mime"`
	Data string `json:"data" toml:"data"`
}

type PackInfoIconSet struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Name           string `json:"name" toml:"name"`
	Type           string `json:"type" toml:"type"`
	Size           int64  `json:"size" toml:"size"`
	Data           string `json:"data,omitempty" toml:"data,omitempty"`
}

type PackGroup struct {
	Key         string `json:"key" toml:"key"`
	Name        string `json:"name" toml:"name"`
	Description string `json:"description,omitempty" toml:"description,omitempty"`
}

type PackGroupList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          types.Labels `json:"items,omitempty" toml:"items,omitempty"`
}

type PackChannel struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`
	Type           string                `json:"type,omitempty" toml:"type,omitempty"`
	VendorName     string                `json:"vendor_name,omitempty" toml:"vendor_name,omitempty"`
	VendorAPI      string                `json:"vendor_api,omitempty" toml:"vendor_api,omitempty"`
	VendorSite     string                `json:"vendor_site,omitempty" toml:"vendor_site,omitempty"`
	Upstream       string                `json:"upstream,omitempty" toml:"upstream,omitempty"`
	StatNum        int64                 `json:"stat_num,omitempty" toml:"stat_num,omitempty"`
	StatNumOff     int64                 `json:"stat_num_off,omitempty" toml:"stat_num_off,omitempty"`
	StatSize       int64                 `json:"stat_size,omitempty" toml:"stat_size,omitempty"`
	StatSizeOff    int64                 `json:"stat_size_off,omitempty" toml:"stat_size_off,omitempty"`
	Roles          *PackChannelRoles     `json:"roles,omitempty" toml:"roles,omitempty"`
}

type PackChannelRoles struct {
	Create types.ArrayUint32 `json:"create,omitempty" toml:"create,omitempty"`
	Read   types.ArrayUint32 `json:"read,omitempty" toml:"read,omitempty"`
	Write  types.ArrayUint32 `json:"write,omitempty" toml:"write,omitempty"`
}

type PackChannelList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []PackChannel `json:"items,omitempty" toml:"items,omitempty"`
}

type PackCommit struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Name           string `json:"name" toml:"name"`
	Size           int64  `json:"size" toml:"size"`
	Channel        string `json:"channel" toml:"channel"`
	Data           string `json:"data" toml:"data"`
	SumCheck       string `json:"sumcheck" toml:"sumcheck"`
	AutoRelease    bool   `json:"auto_release" toml:"auto_release"`
	GitVersion     string `json:"git_version" toml:"git_version"`
}

type PackMultipartCommit struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Name           string      `json:"name" toml:"name"`
	Version        PackVersion `json:"version" toml:"version"`
	Channel        string      `json:"channel" toml:"channel"`
	Size           int64       `json:"size" toml:"size"`
	BlockOffset    int64       `json:"blk_offset" toml:"blk_offset"`
	BlockData      string      `json:"blk_data" toml:"blk_data"`
	BlockCrc32     uint32      `json:"blk_crc32" toml:"blk_crc32"`
}

const (
	OpPermRead   uint8 = 1 << 0
	OpPermWrite  uint8 = 1 << 1
	OpPermCreate uint8 = 1 << 2
	OpPermDelete uint8 = 1 << 3
	OpPermList   uint8 = 1 << 4
	OpPermOff    uint8 = 1 << 5
	OpPermPut    uint8 = OpPermWrite | OpPermCreate | OpPermDelete | OpPermOff
	OpPermMirror uint8 = OpPermRead | OpPermList
	OpPermAll    uint8 = OpPermRead | OpPermWrite | OpPermCreate | OpPermDelete | OpPermList | OpPermOff
)

func OpPermAllow(p, perms uint8) bool {
	return (perms & p) == perms
}
