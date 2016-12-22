project.name = demo
project.version = 0.0.1

%build
go build -ldflags "-s -w" -o {{.buildroot}}/demo main.go

%files
misc/

%js_compress
js/

%css_compress
css/

%html_compress
html/

