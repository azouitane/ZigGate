const std = @import("std");
pub const Request = @import("request.zig").Request;
/// Inclusive wire-byte limit: request line, all header lines, and final CRLFCRLF.
pub const max_header_bytes = 8192;
pub const max_body_bytes = 1024 * 1024;
pub const ParseError = error{ BadRequest, VersionNotSupported, PayloadTooLarge, BodyNotSupported, ExpectationFailed, NotImplemented };
fn token(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) == null) return false;
    return true;
}
pub fn parse(bytes: []const u8) ParseError!Request {
    if (bytes.len > max_header_bytes or !std.mem.endsWith(u8, bytes, "\r\n\r\n")) return error.BadRequest;
    var lines = std.mem.splitSequence(u8, bytes[0 .. bytes.len - 2], "\r\n");
    const line = lines.next() orelse return error.BadRequest;
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return error.BadRequest;
    const target = parts.next() orelse return error.BadRequest;
    const version = parts.next() orelse return error.BadRequest;
    if (parts.next() != null or !token(method) or target.len == 0 or target[0] != '/') return error.BadRequest;
    for (target) |c| if (c <= 0x20 or c >= 0x7f or c == '#') return error.BadRequest;
    if (!std.mem.eql(u8, version, "HTTP/1.1")) {
        if (std.mem.eql(u8, version, "HTTP/1.0") or std.mem.eql(u8, version, "HTTP/2.0")) return error.VersionNotSupported;
        return error.BadRequest;
    }
    var close = false;
    var host = false;
    var length: ?usize = null;
    var transfer = false;
    var expect = false;
    while (lines.next()) |header| {
        if (header.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, header, ':') orelse return error.BadRequest;
        const name = header[0..colon];
        if (!token(name)) return error.BadRequest;
        const value = std.mem.trim(u8, header[colon + 1 ..], " \t");
        for (value) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return error.BadRequest;
        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            var tokens = std.mem.splitScalar(u8, value, ',');
            while (tokens.next()) |item| {
                const option = std.mem.trim(u8, item, " \t");
                if (!token(option)) return error.BadRequest;
                if (std.ascii.eqlIgnoreCase(option, "close")) close = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (host or value.len == 0) return error.BadRequest;
            for (value) |c| if (c <= 0x20 or c >= 0x7f or std.mem.indexOfScalar(u8, "/\\,@?#", c) != null) return error.BadRequest;
            host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (length != null or value.len == 0) return error.BadRequest;
            for (value) |c| if (!std.ascii.isDigit(c)) return error.BadRequest;
            length = std.fmt.parseInt(usize, value, 10) catch return error.PayloadTooLarge;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            transfer = true;
        } else if (std.ascii.eqlIgnoreCase(name, "expect")) {
            expect = true;
        }
    }
    if (!host or transfer) return error.BadRequest;
    if (length != null and length.? > max_body_bytes) return error.PayloadTooLarge;
    if (expect) return error.ExpectationFailed;
    if (length != null and length.? != 0) return error.BodyNotSupported;
    const known = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH" };
    for (known) |m| if (std.mem.eql(u8, method, m)) return .{ .method = method, .target = target, .close = close };
    return error.NotImplemented;
}
test "valid request borrows target" {
    const r = try parse("GET /health?x=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    try std.testing.expectEqualStrings("/health?x=1", r.target);
}
test "reject malformed syntax and ambiguous framing" {
    const bad = [_][]const u8{
        "G@T / HTTP/1.1\r\nHost: x\r\n\r\n",                                           "GET  / HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET / HTTP/1.1\r\n\r\n",                                                      "GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : x\r\n\r\n",                                          "GET / HTTP/1.1\r\nHost: x\r\n folded: x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", "GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: +1\r\n\r\n",                     "GET / HTTP/1.1\r\nHost: x\x00\r\n\r\n",
        "GET / HTTP/1.1\nHost: x\n\n",
    };
    for (bad) |s| try std.testing.expectError(error.BadRequest, parse(s));
    try std.testing.expectError(error.VersionNotSupported, parse("GET / HTTP/1.0\r\nHost: x\r\n\r\n"));
    try std.testing.expectError(error.PayloadTooLarge, parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1048577\r\n\r\n"));
    try std.testing.expectError(error.BodyNotSupported, parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n"));
    try std.testing.expectError(error.ExpectationFailed, parse("GET / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n"));
    try std.testing.expectError(error.NotImplemented, parse("BREW / HTTP/1.1\r\nHost: x\r\n\r\n"));
}

test "connection close wins across repeated token lists" {
    try std.testing.expect((try parse("GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, CLOSE\r\nConnection: keep-alive\r\n\r\n")).close);
    try std.testing.expect(!(try parse("GET / HTTP/1.1\r\nHost: x\r\n\r\n")).close);
    try std.testing.expectError(error.BadRequest, parse("GET / HTTP/1.1\r\nHost: x\r\nConnection: close,\r\n\r\n"));
}
