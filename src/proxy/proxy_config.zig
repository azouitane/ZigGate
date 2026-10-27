const std = @import("std");
pub const Route = struct { prefix: []const u8, authority: []const u8, address: std.net.Address };
pub const Limits = struct {
    max_active: u16 = 128,
    connect_ms: u16 = 2000,
    read_ms: u16 = 5000,
    write_ms: u16 = 2000,
    total_ms: u16 = 30000,
    header_bytes: u16 = 8192,
};
pub const Config = struct {
    routes: [16]Route = undefined,
    count: usize = 0,
    pub fn add(self: *Config, text: []const u8) !void {
        if (self.count == self.routes.len) return error.TooManyRoutes;
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse return error.InvalidProxyRoute;
        const prefix = text[0..eq];
        const authority = text[eq + 1 ..];
        if (prefix.len == 0 or prefix[0] != '/') return error.InvalidProxyRoute;
        for (prefix) |c| if (c <= 0x20 or c >= 0x7f or c == '?' or c == '#') return error.InvalidProxyRoute;
        const colon = std.mem.indexOfScalar(u8, authority, ':') orelse return error.InvalidUpstream;
        const port_text = authority[colon + 1 ..];
        if (port_text.len == 0) return error.InvalidUpstream;
        for (port_text) |c| if (!std.ascii.isDigit(c)) return error.InvalidUpstream;
        const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidUpstream;
        if (port == 0) return error.InvalidUpstream;
        const address = std.net.Address.parseIp4(authority[0..colon], port) catch return error.InvalidUpstream;
        for (self.routes[0..self.count]) |route| if (std.mem.eql(u8, prefix, route.prefix)) return error.DuplicateProxyRoute;
        self.routes[self.count] = .{ .prefix = prefix, .authority = authority, .address = address };
        self.count += 1;
    }
    pub fn match(self: *const Config, target: []const u8) ?usize {
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        for ([_][]const u8{ "/", "/health", "/ready" }) |internal| if (std.mem.eql(u8, path, internal)) return null;
        var selected: ?usize = null;
        for (self.routes[0..self.count], 0..) |route, i| {
            if (std.mem.startsWith(u8, path, route.prefix) and (selected == null or route.prefix.len > self.routes[selected.?].prefix.len)) selected = i;
        }
        return selected;
    }
};
test "validated routes and longest prefix with internal precedence" {
    var config: Config = .{};
    try config.add("/=127.0.0.1:8000");
    try config.add("/api/=127.0.0.1:8001");
    try config.add("/api/v2/=127.0.0.1:8002");
    try std.testing.expectEqual(@as(?usize, 2), config.match("/api/v2/x?q=1"));
    try std.testing.expectEqual(@as(?usize, 1), config.match("/api/x"));
    try std.testing.expectEqual(@as(?usize, null), config.match("/health?q=1"));
    try std.testing.expectError(error.DuplicateProxyRoute, config.add("/api/=127.0.0.1:9000"));
    for ([_][]const u8{ "/x=localhost:80", "/x=127.0.0.1:0", "/x=127.0.0.1:65536", "/x=127.0.0.1:+80", "/x=http://127.0.0.1:80", "x=127.0.0.1:80" }) |bad| try std.testing.expectError(if (bad[0] == '/') error.InvalidUpstream else error.InvalidProxyRoute, config.add(bad));
}
