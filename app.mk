export CC := aarch64-linux-gnu-gcc

CLANG ?= clang
ARCH := arm64
LIBBPF := $(abspath ../libbpf)
BPFTOOL := $(abspath ../hosttools/bpftool)
build_libbpf_dir = $(abspath build_libbpf)
output_libbpf_dir = $(abspath ../$(ARCH)/libbpf)
LIBBPF_OBJ := $(output_libbpf_dir)/libbpf.a

CFLAGS := -g -Wall
APP_LDFLAG ?= 
LDFLAG := -L../arm64 -lelf -lz $(APP_LDFLAG)
APP_INCLUDE ?= 
INCLUDES := -I../vmlinux/arm64 -I$(LIBBPF)/include/uapi -I$(output_libbpf_dir) $(APP_INCLUDE)

APP_OBJS ?=

all: $(LIBBPF_OBJ) $(APP).skel.h  $(APP)

$(APP).bpf.o: $(APP).bpf.c $(LIBBPF_OBJ)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES  ) \
		-c $(filter %.c,$^) -o $@

$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF)/src/*.[ch] $(LIBBPF)/src/Makefile)
	rm -fr $(build_libbpf_dir) 2>/dev/null || true
	mkdir -p $(build_libbpf_dir)/
	$(MAKE) -j8 -C $(LIBBPF)/src BUILD_STATIC_ONLY=1  \
		OBJDIR=$(build_libbpf_dir) DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install
	rm -fr $(build_libbpf_dir)

%.o: %.c $(wildcard %.h)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APP): $(APP).o $(APP).skel.h $(LIBBPF_OBJ) $(APP_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAG)

clean:
	rm -fr $(APP) *.o $(APP).skel.h $(build_libbpf_dir) $(output_libbpf_dir) 2>/dev/null || true
