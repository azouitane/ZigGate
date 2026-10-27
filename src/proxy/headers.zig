const std = @import("std");
pub const Error = error{ InvalidHeaders, NoSpaceLeft };
pub fn equal(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}
pub fn token(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) == null) return false;
    return true;
}
pub const Field = struct { name: []const u8, value: []const u8 };
pub const Iterator = struct {
    lines: std.mem.SplitIterator(u8, .sequence),
    pub fn init(raw: []const u8) Iterator {
        var lines = std.mem.splitSequence(u8, raw, "\r\n");
        _ = lines.next();
        return .{ .lines = lines };
    }
    pub fn next(self: *Iterator) error{InvalidHeaders}!?Field {
        const line = self.lines.next() orelse return null;
        if (line.len == 0) return null;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeaders;
        if (!token(line[0..colon])) return error.InvalidHeaders;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        for (value) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return error.InvalidHeaders;
        return .{ .name = line[0..colon], .value = value };
    }
};
pub fn validate(raw: []const u8) !void {
    var fields = Iterator.init(raw);
    while (try fields.next()) |field| {
        if (equal(field.name, "Connection")) {
            var items = std.mem.splitScalar(u8, field.value, ',');
            while (items.next()) |item| {
                const name = std.mem.trim(u8, item, " \t");
                // Reject attempts to hide framing or the mandatory authority behind Connection.
                if (!token(name) or equal(name, "Content-Length") or equal(name, "Transfer-Encoding") or equal(name, "Host")) return error.InvalidHeaders;
            }
        }
    }
}
pub fn hop(raw: []const u8, name: []const u8) !bool {
    for ([_][]const u8{ "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade" }) |fixed| if (equal(name, fixed)) return true;
    var fields = Iterator.init(raw);
    while (try fields.next()) |field| {
        if (equal(field.name, "connection")) {
            var items = std.mem.splitScalar(u8, field.value, ',');
            while (items.next()) |item| if (equal(name, std.mem.trim(u8, item, " \t"))) return true;
        }
    }
    return false;
}
pub fn metadata(name: []const u8) bool {
    return equal(name, "forwarded") or equal(name, "x-real-ip") or (name.len >= 12 and equal(name[0..12], "x-forwarded-"));
}
pub const Buffer = struct {
    bytes: []u8,
    len: usize = 0,
    pub fn add(self: *Buffer, value: []const u8) error{NoSpaceLeft}!void {
        if (value.len > self.bytes.len - self.len) return error.NoSpaceLeft;
        @memcpy(self.bytes[self.len..][0..value.len], value);
        self.len += value.len;
    }
    pub fn field(self: *Buffer, name: []const u8, value: []const u8) !void {
        try self.add(name);
        try self.add(": ");
        try self.add(value);
        try self.add("\r\n");
    }
};
test "connection nominations filter headers regardless of ordering" {
    const raw = "HTTP/1.1 200 OK\r\nX-Private: secret\r\nConnection: X-Private, keep-alive\r\n\r\n";
    try validate(raw);
    try std.testing.expect(try hop(raw, "x-private"));
    try std.testing.expect(!try hop(raw, "Content-Type"));
    try std.testing.expectError(error.InvalidHeaders, validate("HTTP/1.1 200 OK\r\nConnection: Content-Length\r\n\r\n"));
    try std.testing.expectError(error.InvalidHeaders, validate("HTTP/1.1 200 OK\r\n Folded: x\r\n\r\n"));
    try std.testing.expect(metadata("X-Forwarded-For"));
}
