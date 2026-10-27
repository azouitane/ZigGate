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
    b.installArtifact(exe);
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run ZigGate").dependOn(&run.step);
    const stress = b.addSystemCommand(&.{ "python3", "tools/stress.py" });
    stress.addArtifactArg(exe);
    stress.addArgs(&.{ "--build-mode", @tagName(optimize) });
    b.step("stress", "Measure local and proxy loopback workloads").dependOn(&stress.step);
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
    const integration_step = b.step("integration", "Run socket integration tests (Python 3)");
    integration_step.dependOn(&hardening.step);
    integration_step.dependOn(&integration.step);
    integration_step.dependOn(&concurrent.step);
    integration_step.dependOn(&proxy.step);
}
