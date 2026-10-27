const std = @import("std");
const h = @import("headers.zig");
const parser = @import("../http/parser.zig");
const Route = @import("proxy_config.zig").Route;

pub fn request(raw: []const u8, route: Route, peer: [4]u8, output: []u8) ![]const u8 {
    return requestScheme(raw, route, peer, output, false);
}
pub fn requestScheme(raw: []const u8, route: Route, peer: [4]u8, output: []u8, secure: bool) ![]const u8 {
    const req = try parser.parse(raw);
    if (h.equal(req.method, "CONNECT")) return error.UnsupportedUpgrade;
    try h.validate(raw);
    var out: h.Buffer = .{ .bytes = output };
    try out.add(req.method);
    try out.add(" ");
    try out.add(req.target);
    try out.add(" HTTP/1.1\r\n");
    var fields = h.Iterator.init(raw);
    while (try fields.next()) |field| {
        if (h.equal(field.name, "Upgrade")) return error.UnsupportedUpgrade;
        if (h.equal(field.name, "Host") or h.equal(field.name, "Content-Length") or h.metadata(field.name) or try h.hop(raw, field.name)) continue;
        try out.field(field.name, field.value);
    }
    var peer_buffer: [15]u8 = undefined;
    const ip = try std.fmt.bufPrint(&peer_buffer, "{d}.{d}.{d}.{d}", .{ peer[0], peer[1], peer[2], peer[3] });
    try out.field("Host", route.authority);
    try out.field("X-Forwarded-For", ip);
    try out.field("X-Forwarded-Proto", if (secure) "https" else "http");
    try out.add("Content-Length: 0\r\nConnection: close\r\n\r\n");
    return output[0..out.len];
}
pub const Response = struct { length: ?u64, no_body: bool };
pub fn response(raw: []const u8, head: bool, output: []u8) !struct { framing: Response, len: usize } {
    if (!std.mem.endsWith(u8, raw, "\r\n\r\n")) return error.InvalidResponse;
    const end = std.mem.indexOf(u8, raw, "\r\n") orelse return error.InvalidResponse;
    const line = raw[0..end];
    if (line.len < 13 or !std.mem.startsWith(u8, line, "HTTP/1.1 ") or line[12] != ' ') return error.InvalidResponse;
    for (line[9..12]) |c| if (!std.ascii.isDigit(c)) return error.InvalidResponse;
    const status = try std.fmt.parseInt(u16, line[9..12], 10);
    if (status < 200 or status > 599) return error.InvalidResponse;
    for (line[13..]) |c| if (c < 0x20 or c >= 0x7f) return error.InvalidResponse;
    try h.validate(raw);
    var length: ?u64 = null;
    var fields = h.Iterator.init(raw);
    while (try fields.next()) |field| {
        if (h.equal(field.name, "Transfer-Encoding")) return error.InvalidResponse;
        if (h.equal(field.name, "Content-Length")) {
            if (length != null or field.value.len == 0) return error.InvalidResponse;
            for (field.value) |c| if (!std.ascii.isDigit(c)) return error.InvalidResponse;
            length = std.fmt.parseInt(u64, field.value, 10) catch return error.InvalidResponse;
        }
    }
    if (status == 204 and length != null) return error.InvalidResponse;
    if (status == 205 and length != null and length.? != 0) return error.InvalidResponse;
    const no_body = head or status == 204 or status == 205 or status == 304;
    var out: h.Buffer = .{ .bytes = output };
    try out.add(line);
    try out.add("\r\n");
    fields = h.Iterator.init(raw);
    while (try fields.next()) |field| {
        if (try h.hop(raw, field.name)) continue;
        try out.field(field.name, field.value);
    }
    try out.add("Connection: close\r\n\r\n");
    return .{ .framing = .{ .length = if (no_body) 0 else length, .no_body = no_body }, .len = out.len };
}

test "request target host and forwarding metadata are reconstructed" {
    const route: Route = .{ .prefix = "/api/", .authority = "127.0.0.1:8081", .address = try std.net.Address.parseIp4("127.0.0.1", 8081) };
    var output: [16384]u8 = undefined;
    const bytes = try request("GET /api/x?q=1 HTTP/1.1\r\nHost: attacker\r\nX-Forwarded-For: fake\r\nForwarded: fake\r\nX-Secret: no\r\nConnection: X-Secret\r\nAccept: text/plain\r\n\r\n", route, .{ 127, 0, 0, 1 }, &output);
    try std.testing.expect(std.mem.startsWith(u8, bytes, "GET /api/x?q=1 HTTP/1.1\r\n"));
    for ([_][]const u8{ "fake", "attacker", "X-Secret" }) |bad| try std.testing.expect(std.mem.indexOf(u8, bytes, bad) == null);
    for ([_][]const u8{ "Host: 127.0.0.1:8081\r\n", "X-Forwarded-For: 127.0.0.1\r\n", "Accept: text/plain\r\n" }) |good| try std.testing.expect(std.mem.indexOf(u8, bytes, good) != null);
}
test "upstream framing rejects ambiguity unsupported encodings and invalid status" {
    var output: [16384]u8 = undefined;
    for ([_][]const u8{
        "HTTP/1.0 200 OK\r\n\r\n",                               "HTTP/1.1 101 Switching\r\n\r\n",                                    "HTTP/1.1 20X OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n",
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    }) |bad| try std.testing.expectError(error.InvalidResponse, response(bad, false, &output));
    const known = try response("HTTP/1.1 200 OK\r\nContent-Length: 123\r\nConnection: X-Hidden\r\nX-Hidden: secret\r\n\r\n", false, &output);
    try std.testing.expectEqual(@as(?u64, 123), known.framing.length);
    try std.testing.expect(std.mem.indexOf(u8, output[0..known.len], "secret") == null);
    try std.testing.expectEqual(@as(?u64, null), (try response("HTTP/1.1 200 OK\r\n\r\n", false, &output)).framing.length);
    try std.testing.expectEqual(@as(?u64, 0), (try response("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n", true, &output)).framing.length);
}

test "upstream header controls folding and connection framing concealment are rejected" {
    var output: [16384]u8 = undefined;
    for ([_][]const u8{
        "HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: x\x00\r\n\r\n",
        "HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nConnection: close,\r\n\r\n",
    }) |bad| try std.testing.expectError(error.InvalidHeaders, response(bad, false, &output));
    for ([_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\n",
    }) |bad| try std.testing.expectError(error.InvalidResponse, response(bad, false, &output));
}
