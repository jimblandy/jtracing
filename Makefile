build_bpftool_dir:=$(PWD)/.build_bpftool/
CARGO ?= $(shell which cargo)

all: prepare app

prepare:
	[ -d hosttools ] || mkdir hosttools

hosttools/bpftool:
	rm -fr bpftool/libbpf 2>/dev/null || true
	ln -srf libbpf bpftool/libbpf
	rm -fr $(build_bpftool_dir) 2>/dev/null || true
	mkdir $(build_bpftool_dir) 
	make -j 8 OUTPUT="$(build_bpftool_dir)" -C bpftool/src
	cp $(build_bpftool_dir)/bpftool hosttools/
	rm -r $(build_bpftool_dir)

app: hosttools/bpftool
	$(MAKE) -C bootstrap
	$(MAKE) -C bootstrap_perfbuf
	$(MAKE) -C minimal
	$(MAKE) -C perfbuf
	$(MAKE) -C profile 

clean:
	rm -fr $(build_bpftool_dir) hosttools 2>/dev/null || true
	$(MAKE) -C bootstrap clean
	$(MAKE) -C minimal clean
	$(MAKE) -C perfbuf clean
	$(MAKE) -C bootstrap_perfbuf clean
	$(MAKE) -C profile clean


