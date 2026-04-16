fn main() -> anyhow::Result<()> {
    // 编译 C 代码
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    // 编译 soinfo 隐藏构造函数（.init_array，dlopen 时自动执行）
    // cc::Build::compile() 自动添加 -l static=hide_soinfo
    // -u get_hide_result 强制拉取 .o（同一 .o 内的 .init_array 构造函数也会被包含）
    // --export-dynamic-symbol 导出到动态符号表供 dlsym 查询
    cc::Build::new().file("src/hide_soinfo.c").compile("hide_soinfo");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,--export-dynamic-symbol=get_hide_result");

    Ok(())
}
