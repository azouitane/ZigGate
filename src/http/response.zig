const std = @import("std");
pub const Response = struct {
    status: u16,
    body: []const u8,
    pub fn serialize(self: Response, buffer: []u8, head: bool) ![]const u8 {
        return self.serializeConnection(buffer, head, true);
    }
    pub fn serializeConnection(self: Response, buffer: []u8, head: bool, close: bool) ![]const u8 {
        return std.fmt.bufPrint(buffer, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: {s}\r\n{s}\r\n{s}", .{
            self.status,                          reason(self.status),                              self.body.len,
            if (close) "close" else "keep-alive", if (self.status == 405) "Allow: GET\r\n" else "", if (head) "" else self.body,
        });
    }
};
pub fn reason(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        else => "Internal Server Error",
    };
}
pub fn failure(status: u16) Response {
    return .{ .status = status, .body = reason(status) };
}
test "response framing and HEAD suppression" {
    var buffer: [512]u8 = undefined;
    const r: Response = .{ .status = 200, .body = "hello" };
    const bytes = try r.serialize(&buffer, false);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhello"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, try r.serialize(&buffer, true), "\r\n\r\n"));
}
