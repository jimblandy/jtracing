#[allow(unused)]
use {
    jlogger::{jdebug, jinfo, jwarn, jerror, JloggerBuilder},
    std::{
        fs::{canonicalize, create_dir_all, remove_file},
        os::unix::fs::symlink,
        path::Path,
        env,
    }
};

extern crate libbpf_cargo;
use libbpf_cargo::SkeletonBuilder;

fn main() {
    JloggerBuilder::new()
        .max_level(log::LevelFilter::Debug)
        .log_file("/tmp/jtracing.log")
        .log_console(false)
        .log_time(false)
        .build();

    let applications = vec!["execsnoop_pb", "profile", "funccount"];
    let out_dir = env::var("OUT_DIR").unwrap();

    jinfo!("{}", out_dir);

    for &app in applications.iter() {
        let app_bpf_dir = format!("{}/bpf", app);
        let app_bpf_output_dir = format!("{}/{}/bpf/", out_dir, app);
        let skle_c = format!("{}/{}.bpf.c", app_bpf_dir, app);
        let mut vmlinux_inc = String::from("vmlinux/x86/");
        let skle_path = format!("{}/{}.skel.rs", app_bpf_output_dir, app);

        jinfo!("app_bpf_dir: {}", app_bpf_dir);
        jinfo!("app_bpf_output_dir: {}", app_bpf_output_dir);
        jinfo!("skle_c: {}", skle_c);
        jinfo!("skle_path: {}", skle_path);

        create_dir_all(&app_bpf_output_dir).unwrap();
        let skel = Path::new(&skle_path);
        let target = env::var("TARGET").unwrap();
        let mut clang_args = String::from("-g -O2");
        if target == "aarch64-unknown-linux-gnu" {
            vmlinux_inc = vmlinux_inc.replace("x86", "arm64");
            if let Ok(arm64_lib) = canonicalize("arm64") {
                let cargo_search_path = format!(
                    "cargo:rustc-link-search={}",
                    arm64_lib.as_path().to_str().unwrap()
                );
                println!("{}", cargo_search_path);
            }
            clang_args.push_str(" -D__TARGET_ARCH_arm64")
        }

        if target == "x86_64-unknown-linux-gnu" {
            clang_args.push_str(" -D__TARGET_ARCH_x86")
        }

        let abs_path_vmlinux_inc = canonicalize(vmlinux_inc).unwrap();
        clang_args.push_str(&format!(
            " -I{}",
            abs_path_vmlinux_inc.as_path().to_str().unwrap()
        ));

        SkeletonBuilder::new(&skle_c)
            .clang_args(&clang_args)
            .generate(&skel)
            .expect("bpf compilation failed");
        println!("cargo:rerun-if-changed={}", &skle_c);

        jinfo!("clang_args: {}", clang_args);

        let skle_path_dst = format!("{}/{}.skel.rs", app_bpf_dir, app);
        let _ = remove_file(&skle_path_dst);
        symlink(canonicalize(skle_path).unwrap(), skle_path_dst).unwrap();
    }
}
