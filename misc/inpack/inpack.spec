[project]
name = inpack
version = 0.1.0.dev
vendor = hooto.com
homepage = https://github.com/sysinner/inpack
groups = dev/sys-srv

%build
export PATH=$PATH:/usr/local/go/bin:/opt/gopath/bin
export GOPATH=/opt/gopath
mkdir -p {{.buildroot}}/etc
mkdir -p {{.buildroot}}/bin
mkdir -p {{.buildroot}}/var/{data,storage}
mkdir -p {{.buildroot}}/webui/lessui/
cp -rp webui/lessui/* {{.buildroot}}/webui/lessui/
go build -ldflags "-s -w" -o {{.buildroot}}/bin/inpackd cmd/inpackd/main.go
go build -ldflags "-s -w" -o {{.buildroot}}/bin/inpack cmd/inpack/main.go


%files
misc/
bin/
etc/config.json
webui/twbs/
webui/lessui/
webui/purecss/
webui/channel/
webui/pkg/
webui/pkginfo/
webui/css/
webui/js/
webui/img/
webui/ips.htm
webui/main.html


%js_compress

%css_compress

%html_compress

%png_compress

