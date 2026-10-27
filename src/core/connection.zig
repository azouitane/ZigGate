const std = @import("std");
const parser = @import("../http/parser.zig");
const response = @import("../http/response.zig");
const router = @import("../http/router.zig");
const Options = @import("../cli/commands.zig").Options;
pub const State = enum { reading, writing, idle, proxy, tls_handshake, tls_shutdown };
pub const Connection = struct {
    fd: std.posix.socket_t = -1,
    tls: @import("../tls/session.zig").Session = .{},
    generation: u32 = 0,
    slot: usize = 0,
    state: State = .reading,
    deadline: u64 = 0,
    input: [parser.max_header_bytes]u8 = undefined,
    used: usize = 0,
    output: [1024]u8 = undefined,
    output_len: usize = 0,
    sent: usize = 0,
    requests: u16 = 0,
    draining: bool = false,
    started: u64 = 0,
    status: u16 = 0,
    counted: bool = false,
    proxied: bool = false,
    bytes_sent: u64 = 0,
    close: bool = true,
    peer_eof: bool = false,
    peer_ip: [4]u8 = .{ 127, 0, 0, 1 },
    proxy_route: usize = 0,
    upstream: ?usize = null,

    pub fn expired(self: *const Connection, now: u64) bool {
        return now >= self.deadline;
    }
    pub fn respond(self: *Connection, r: response.Response, head: bool, close: bool, now: u64, options: Options) !void {
        self.status = r.status;
        self.output_len = (try r.serializeConnection(&self.output, head, close)).len;
        self.sent = 0;
        self.close = close;
        self.state = .writing;
        self.deadline = now + options.timeout_ms;
    }
    pub fn process(self: *Connection, now: u64, options: Options) !void {
        if (std.mem.indexOf(u8, self.input[0..self.used], "\r\n\r\n")) |end| {
            if (end + 4 > options.header_bytes) return self.respond(response.failure(431), false, true, now, options);
            const bytes = self.input[0 .. end + 4];
            const head = std.mem.startsWith(u8, bytes, "HEAD ");
            const request = parser.parse(bytes) catch |err| {
                return self.respond(response.failure(switch (err) {
                    error.BadRequest => 400,
                    error.VersionNotSupported => 505,
                    error.PayloadTooLarge => 413,
                    error.ExpectationFailed => 417,
                    error.NotImplemented, error.BodyNotSupported => 501,
                }), head, true, now, options);
            };
            self.requests += 1;
            // Never dispatch surplus bytes as another request. Close after the first response.
            const close = self.draining or request.close or self.peer_eof or self.used != end + 4 or self.requests >= options.max_requests;
            const acme = @import("../acme/challenge.zig");
            if (options.challenge_store) |store| {
                if (std.mem.startsWith(u8, request.target, acme.prefix)) {
                    var body: [192]u8 = undefined;
                    if (!std.mem.eql(u8, request.method, "GET") and !head) return self.respond(response.failure(405), head, true, now, options);
                    const value = store.lookup(request.target[acme.prefix.len..], &body, acme.now()) orelse return self.respond(response.failure(404), head, close, now, options);
                    return self.respond(.{ .status = 200, .body = value }, head, close, now, options);
                }
            }
            if (options.proxy.match(request.target)) |route| {
                self.proxied = true;
                self.proxy_route = route;
                self.state = .proxy;
                self.close = true;
                return;
            }
            try self.respond(router.route(request), head, close, now, options);
        } else if (self.used >= options.header_bytes) {
            try self.respond(response.failure(431), std.mem.startsWith(u8, self.input[0..self.used], "HEAD "), true, now, options);
        }
    }
    pub fn pending(self: *const Connection) []const u8 {
        return self.output[self.sent..self.output_len];
    }
    pub fn advance(self: *Connection, count: usize) void {
        std.debug.assert(count <= self.output_len - self.sent);
        self.sent += count;
    }
};
test "deadline expiration" {
    const c: Connection = .{ .deadline = 42 };
    try std.testing.expect(!c.expired(41));
    try std.testing.expect(c.expired(42));
}
test "partial output retains unsent bytes" {
    var c: Connection = .{};
    try c.respond(.{ .status = 200, .body = "hello" }, false, false, 1, .{});
    const total = c.pending().len;
    c.advance(3);
    try std.testing.expectEqual(total - 3, c.pending().len);
    try std.testing.expect(std.mem.startsWith(u8, c.pending(), "P/1.1"));
    c.advance(total - 5);
    try std.testing.expectEqualStrings("lo", c.pending());
    c.advance(2);
    try std.testing.expectEqual(@as(usize, 0), c.pending().len);
}
test "bounded request state and pipelining closes" {
    var c: Connection = .{};
    const raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    @memcpy(c.input[0..raw.len], raw);
    c.used = raw.len;
    try c.process(10, .{});
    try std.testing.expect(!c.close);
    try std.testing.expectEqual(State.writing, c.state);
    c.used += 1;
    c.input[raw.len] = 'X';
    try c.process(20, .{});
    try std.testing.expect(c.close);
    c.used = raw.len;
    try c.process(30, .{ .max_requests = 3 });
    try std.testing.expect(c.close);
}

test "inclusive header boundaries with whole and fragmented input" {
    const prefix = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX: ";
    for ([_]usize{ 8191, 8192, 8193 }) |size| {
        var wire: [8193]u8 = undefined;
        @memcpy(wire[0..prefix.len], prefix);
        @memset(wire[prefix.len .. size - 4], 'a');
        @memcpy(wire[size - 4 .. size], "\r\n\r\n");
        // Check the parser independently of connection buffer capacity.
        if (size <= parser.max_header_bytes) {
            const request = try parser.parse(wire[0..size]);
            try std.testing.expect(request.close);
        } else {
            try std.testing.expectError(error.BadRequest, parser.parse(wire[0..size]));
        }
        // One read, small/large chunks, and a split within CRLFCRLF.
        for ([_]usize{ 8193, 4096, 257, 8191 }) |chunk| {
            var c: Connection = .{};
            var offset: usize = 0;
            while (offset < size and c.state == .reading) {
                const n = @min(chunk, @min(size - offset, c.input.len - c.used));
                try std.testing.expect(n > 0);
                @memcpy(c.input[c.used..][0..n], wire[offset..][0..n]);
                c.used += n;
                offset += n;
                try c.process(1, .{});
                if (offset < @min(size, parser.max_header_bytes)) {
                    try std.testing.expectEqual(State.reading, c.state);
                }
            }
            try std.testing.expectEqual(State.writing, c.state);
            try std.testing.expect(c.close);
            try std.testing.expect(std.mem.startsWith(u8, c.pending(), if (size <= parser.max_header_bytes) "HTTP/1.1 200 OK\r\n" else "HTTP/1.1 431 "));
            try std.testing.expectEqual(@min(size, parser.max_header_bytes), c.used);
        }
    }
}

test "proxy dispatch follows validation and preserves internal routes" {
    var options: Options = .{};
    try options.proxy.add("/=127.0.0.1:8081");
    try options.proxy.add("/api/=127.0.0.1:8082");
    var c: Connection = .{};
    const raw = "GET /api/x?q=1 HTTP/1.1\r\nHost: x\r\n\r\n";
    @memcpy(c.input[0..raw.len], raw);
    c.used = raw.len;
    try c.process(1, options);
    try std.testing.expectEqual(State.proxy, c.state);
    try std.testing.expectEqual(@as(usize, 1), c.proxy_route);
    c = .{};
    const internal = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
    @memcpy(c.input[0..internal.len], internal);
    c.used = internal.len;
    try c.process(2, options);
    try std.testing.expectEqual(State.writing, c.state);
    try std.testing.expect(!c.close);
    try std.testing.expect(std.mem.endsWith(u8, c.pending(), "ok\n"));
    c = .{};
    const body = "POST /api/x HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n";
    @memcpy(c.input[0..body.len], body);
    c.used = body.len;
    try c.process(3, options);
    try std.testing.expectEqual(State.writing, c.state);
    try std.testing.expect(c.close);
    try std.testing.expect(std.mem.startsWith(u8, c.pending(), "HTTP/1.1 501 "));
}

test "configured client header ceiling applies before dispatch" {
    var c: Connection = .{};
    const raw = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
    @memcpy(c.input[0..raw.len], raw);
    c.used = raw.len;
    try c.process(0, .{ .header_bytes = raw.len - 1 });
    try std.testing.expectEqual(@as(u16, 431), c.status);
    try std.testing.expect(c.close);
}

test "HTTP-01 namespace wins proxy routing without affecting other paths" {
    var options: Options = .{};
    var challenges: @import("../acme/challenge.zig").Store = .{};
    options.challenge_store = &challenges;
    try options.proxy.add("/.well-known/=127.0.0.1:9999");
    try challenges.put("abcdefghijklmnopqrstuvwxyz", "expected-key-authorization", @import("../acme/challenge.zig").now() + 10000);
    var c: Connection = .{};
    const wire = "GET /.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz HTTP/1.1\r\nHost: example.com\r\n\r\n";
    @memcpy(c.input[0..wire.len], wire);
    c.used = wire.len;
    try c.process(0, options);
    try std.testing.expectEqual(@as(u16, 200), c.status);
    try std.testing.expect(std.mem.endsWith(u8, c.pending(), "expected-key-authorization"));
    challenges.clear();
    try c.process(0, options);
    try std.testing.expectEqual(@as(u16, 404), c.status);
    const other = "GET /.well-known/other HTTP/1.1\r\nHost: example.com\r\n\r\n";
    @memcpy(c.input[0..other.len], other);
    c.used = other.len;
    try c.process(0, options);
    try std.testing.expectEqual(State.proxy, c.state);
}
