const std = @import("std");
const listener = @import("listener.zig");
const Options = @import("../cli/commands.zig").Options;
pub fn run(options: Options) !void {
    var server = try listener.open(options.bind, options.port);
    defer server.deinit();
    std.log.info("ZigGate listening on {s}:{d} (epoll, max connections {d})", .{ options.bind, options.port, options.max_connections });
    try @import("event_loop.zig").run(server.stream.handle, options);
}
