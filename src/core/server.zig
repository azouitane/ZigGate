const listener = @import("listener.zig");
const Options = @import("../cli/commands.zig").Options;
pub fn run(options: Options) !void {
    const server = try listener.open(options.bind, options.port);
    try @import("event_loop.zig").run(server.stream.handle, options);
}
