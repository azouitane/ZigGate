const listener = @import("listener.zig");
const Options = @import("../cli/commands.zig").Options;
pub fn run(options: Options, contexts: *@import("../tls/context.zig").Contexts, manager: ?*@import("../acme/manager.zig").Manager) !void {
    var https: ?@import("std").net.Server = null;
    if (options.tls.listen) |address| https = try address.listen(.{ .force_nonblocking = true, .reuse_address = true, .kernel_backlog = 128 });
    const server = listener.open(options.bind, options.port) catch |err| {
        if (https) |*s| s.deinit();
        return err;
    };
    try @import("event_loop.zig").run(server.stream.handle, if (https) |s| s.stream.handle else null, options, contexts, manager);
}
