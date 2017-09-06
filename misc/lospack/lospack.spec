project.name = lospack
project.version = 0.1.0.dev
project.vendor = hooto.com
project.homepage = https://github.com/lessos/lospack
project.groups = dev/sys-srv

%build
export PATH=$PATH:/usr/local/go/bin:/opt/gopath/bin
export GOPATH=/opt/gopath
mkdir -p {{.buildroot}}/etc
mkdir -p {{.buildroot}}/bin
mkdir -p {{.buildroot}}/var/{data,storage}
mkdir -p {{.buildroot}}/webui/lessui/
cp -rp webui/lessui/* {{.buildroot}}/webui/lessui/
go build -ldflags "-s -w" -o {{.buildroot}}/bin/lospackd cmd/lospackd/main.go
go build -ldflags "-s -w" -o {{.buildroot}}/bin/lospack cmd/lospack/main.go


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
webui/lps.htm
webui/main.html


%js_compress

%css_compress

%html_compress

%png_compress

