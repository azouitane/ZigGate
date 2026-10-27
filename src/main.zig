const std = @import("std");
const builtin = @import("builtin");
const cli = @import("cli/commands.zig");
pub fn main() !void {
    if (comptime builtin.zig_version.order(.{ .major = 0, .minor = 15, .patch = 2 }) != .eq)
        @compileError("ZigGate requires Zig 0.15.2 exactly");
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    const options = cli.parse(args[1..]) catch |err| {
        std.debug.print("ziggate: {s}\n{s}", .{ @errorName(err), cli.usage });
        std.process.exit(2);
    };
    if (options.help) {
        std.debug.print("{s}", .{cli.usage});
        return;
    }
    var contexts: @import("tls/context.zig").Contexts = .{};
    contexts.init(options.tls) catch |err| {
        std.debug.print("ziggate: {s}: check TLS certificate chain, unencrypted PEM key, matching key and file permissions\n", .{@errorName(err)});
        std.process.exit(2);
    };
    defer contexts.deinit();
    if (options.check_config) {
        std.debug.print("configuration valid\n", .{});
        return;
    }
    try @import("core/server.zig").run(options, &contexts);
}
test {
    std.testing.refAllDeclsRecursive(@This());
}
