const std = @import("std");
const builtin = @import("builtin");
const cli = @import("cli/commands.zig");
pub fn main() !void {
    if (comptime builtin.zig_version.order(.{ .major = 0, .minor = 15, .patch = 2 }) != .eq)
        @compileError("ZigGate requires Zig 0.15.2 exactly");
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    var options = cli.parse(args[1..]) catch |err| {
        std.debug.print("ziggate: {s}\n{s}", .{ @errorName(err), cli.usage });
        std.process.exit(2);
    };
    if (options.help) {
        std.debug.print("{s}", .{cli.usage});
        return;
    }
    var acme: @import("acme/manager.zig").Manager = undefined;
    var manager: ?*@import("acme/manager.zig").Manager = null;
    if (options.acme.enabled) {
        acme.init(options.acme) catch |err| {
            std.debug.print("ziggate: {s}: check private ACME storage, state and trust configuration\n", .{@errorName(err)});
            std.process.exit(2);
        };
        manager = &acme;
        acme.configure(&options);
    }
    defer if (manager) |m| m.deinit();
    var contexts: @import("tls/context.zig").Contexts = .{};
    contexts.init(if (options.acme.enabled and options.tls.cert == null) .{} else options.tls) catch |err| {
        std.debug.print("ziggate: {s}: check TLS certificate chain, unencrypted PEM key, matching key and file permissions\n", .{@errorName(err)});
        std.process.exit(2);
    };
    defer contexts.deinit();
    if (options.check_config) {
        std.debug.print("configuration valid\n", .{});
        return;
    }
    try @import("core/server.zig").run(options, &contexts, manager);
}
test {
    std.testing.refAllDeclsRecursive(@This());
}
