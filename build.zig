const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    if (target.result.os.tag != .linux or (target.result.cpu.arch != .x86_64 and target.result.cpu.arch != .aarch64))
        @panic("ZigGate supports Linux x86_64 and aarch64 only");
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{ .name = "ziggate", .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("ssl", .{});
    exe.root_module.linkSystemLibrary("crypto", .{});
    exe.root_module.addIncludePath(b.path("src/tls"));
    exe.root_module.addCSourceFile(.{ .file = b.path("src/tls/openssl_shim.c"), .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" } });
    if (b.option([]const u8, "openssl-prefix", "Target OpenSSL development prefix (include and lib64)")) |prefix| {
        exe.root_module.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "include" }) });
        exe.root_module.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "lib64" }) });
    }
    exe.root_module.addIncludePath(b.path("src/acme"));
    exe.root_module.addCSourceFile(.{ .file = b.path("src/acme/shim.c"), .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" } });
    exe.root_module.linkSystemLibrary("dl", .{});
    b.installArtifact(exe);
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run ZigGate").dependOn(&run.step);
    const stress = b.addSystemCommand(&.{ "python3", "tools/stress.py" });
    stress.addArtifactArg(exe);
    stress.addArgs(&.{ "--build-mode", @tagName(optimize) });
    b.step("stress", "Measure local and proxy loopback workloads").dependOn(&stress.step);
    const tls_load = b.addSystemCommand(&.{ "python3", "tools/tls_load.py" });
    tls_load.addArtifactArg(exe);
    tls_load.addArgs(&.{ "--build-mode", @tagName(optimize), "--reload-active", "--resilience" });
    b.step("tls-load", "Run optional TLS load matrix and resilience profile").dependOn(&tls_load.step);
    const unit = b.addTest(.{ .root_module = exe.root_module });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(unit).step);
    const integration = b.addSystemCommand(&.{ "python3", "tests/integration/http_test.py" });
    integration.addArtifactArg(exe);
    const concurrent = b.addSystemCommand(&.{ "python3", "tests/integration/concurrent_test.py" });
    concurrent.addArtifactArg(exe);
    const proxy = b.addSystemCommand(&.{ "python3", "tests/integration/proxy_test.py" });
    proxy.addArtifactArg(exe);
    const fixture_tests = b.addSystemCommand(&.{ "python3", "tests/unit/proxy_fixture_test.py" });
    proxy.step.dependOn(&fixture_tests.step);
    const hardening = b.addSystemCommand(&.{ "python3", "tests/integration/hardening_test.py" });
    hardening.addArtifactArg(exe);
    const tls_tests = b.addSystemCommand(&.{ "python3", "tests/integration/tls_test.py" });
    tls_tests.addArtifactArg(exe);
    b.step("tls-integration", "Run HTTPS/OpenSSL integration tests").dependOn(&tls_tests.step);
    const reliability = b.addSystemCommand(&.{ "python3", "tests/integration/tls_reliability_test.py" });
    reliability.addArtifactArg(exe);
    b.step("tls-reliability", "Run TLS admission and reload regressions").dependOn(&reliability.step);
    const acme = b.addSystemCommand(&.{ "python3", "tests/integration/acme_test.py" });
    acme.addArtifactArg(exe);
    b.step("acme-integration", "Run offline HTTPS ACME issuance/renewal regressions").dependOn(&acme.step);
    const integration_step = b.step("integration", "Run socket integration tests (Python 3)");
    integration_step.dependOn(&acme.step);
    integration_step.dependOn(&reliability.step);
    integration_step.dependOn(&tls_tests.step);
    integration_step.dependOn(&hardening.step);
    integration_step.dependOn(&integration.step);
    integration_step.dependOn(&concurrent.step);
    integration_step.dependOn(&proxy.step);
}
