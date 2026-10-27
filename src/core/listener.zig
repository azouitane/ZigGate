const std = @import("std");
pub fn open(bind: []const u8, port: u16) !std.net.Server {
    const address = try std.net.Address.parseIp4(bind, port);
    return address.listen(.{ .force_nonblocking = true, .reuse_address = true, .kernel_backlog = 128 });
}
test "invalid listener address" {
    try std.testing.expectError(error.InvalidCharacter, open("bad", 8080));
}
