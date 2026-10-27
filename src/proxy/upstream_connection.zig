const std = @import("std");
const p = std.posix;
const E = std.os.linux.EPOLL;
const protocol = @import("reverse_proxy.zig");
const config = @import("proxy_config.zig");
const SocketIO = struct {
    fd: i32,
    fn connected(self: @This()) !void {
        try p.getsockoptError(self.fd);
    }
    fn send(self: @This(), bytes: []const u8) !usize {
        return p.send(self.fd, bytes, p.MSG.NOSIGNAL | p.MSG.DONTWAIT);
    }
    fn recv(self: @This(), bytes: []u8) !usize {
        return p.recv(self.fd, bytes, p.MSG.DONTWAIT);
    }
};
pub const State = enum { connecting, sending, headers, body, done };

/// One bounded transaction; no descriptors or borrowed request slices survive deinit.
pub const Upstream = struct {
    active: bool = false,
    fd: i32 = -1,
    registered: bool = false,
    state: State = .connecting,
    deadline: u64 = 0,
    total_deadline: u64 = 0,
    client_deadline: u64 = 0,
    committed: bool = false,
    head: bool = false,
    request: [16384]u8 = undefined,
    request_len: usize = 0,
    request_sent: usize = 0,
    header: [8192]u8 = undefined,
    header_used: usize = 0,
    output: [16384]u8 = undefined,
    output_len: usize = 0,
    output_sent: usize = 0,
    remaining: ?u64 = null,

    pub fn pending(self: *const Upstream) []const u8 {
        return self.output[self.output_sent..self.output_len];
    }
    pub fn expired(self: *const Upstream, now: u64) bool {
        return now >= self.total_deadline or now >= (if (self.pending().len != 0) self.client_deadline else self.deadline);
    }
    pub fn closeSocket(self: *Upstream, epfd: i32) void {
        if (self.fd == -1) return;
        if (self.registered) p.epoll_ctl(epfd, E.CTL_DEL, self.fd, null) catch {};
        p.close(self.fd);
        self.fd = -1;
        self.registered = false;
    }
    pub fn deinit(self: *Upstream, epfd: i32) void {
        self.closeSocket(epfd);
        self.active = false;
    }
    pub fn start(self: *Upstream, raw: []const u8, route: config.Route, peer: [4]u8, limits: config.Limits, now: u64) !void {
        self.* = .{ .active = true, .head = std.mem.startsWith(u8, raw, "HEAD "), .deadline = now + limits.connect_ms, .total_deadline = now + limits.total_ms };
        self.request_len = (try protocol.request(raw, route, peer, &self.request)).len;
        const fd = try p.socket(p.AF.INET, p.SOCK.STREAM | p.SOCK.NONBLOCK | p.SOCK.CLOEXEC, p.IPPROTO.TCP);
        errdefer p.close(fd);
        p.connect(fd, &route.address.any, route.address.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                self.fd = fd;
                return;
            },
            else => return err,
        };
        self.fd = fd;
        self.state = .sending;
        self.deadline = now + limits.write_ms;
    }
    pub fn feedHeaders(self: *Upstream, now: u64, limits: config.Limits, client_timeout: u16) !void {
        if (std.mem.indexOf(u8, self.header[0..self.header_used], "\r\n\r\n")) |end| {
            const header_len = end + 4;
            const result = try protocol.response(self.header[0..header_len], self.head, &self.output);
            const body = self.header[header_len..self.header_used];
            if (result.framing.length) |length| {
                if (body.len > length) return error.InvalidResponse;
                self.remaining = length - body.len;
            } else self.remaining = null;
            self.state = if (self.remaining != null and self.remaining.? == 0) .done else .body;
            @memcpy(self.output[result.len..][0..body.len], body);
            self.output_len = result.len + body.len;
            self.output_sent = 0;
            self.client_deadline = now + client_timeout;
        } else if (self.header_used == limits.header_bytes) return error.InvalidResponse;
    }
    pub fn bodyReceived(self: *Upstream, n: usize, now: u64, client_timeout: u16) !void {
        std.debug.assert(self.pending().len == 0);
        if (n == 0) {
            if (self.remaining != null and self.remaining.? != 0) return error.TruncatedResponse;
            self.state = .done;
            return;
        }
        if (self.remaining) |remaining| {
            if (n > remaining) return error.InvalidResponse;
            self.remaining = remaining - n;
            if (self.remaining.? == 0) self.state = .done;
        }
        self.output_len = n;
        self.output_sent = 0;
        self.client_deadline = now + client_timeout;
    }
    pub fn onUpstream(self: *Upstream, now: u64, limits: config.Limits, client_timeout: u16) !void {
        try self.onIO(now, limits, client_timeout, SocketIO{ .fd = self.fd });
    }
    fn onIO(self: *Upstream, now: u64, limits: config.Limits, client_timeout: u16, io: anytype) !void {
        if (self.state == .connecting) {
            // Required even on EPOLLERR/HUP: writable readiness alone is not connect success.
            io.connected() catch |err| switch (err) {
                error.WouldBlock, error.ConnectionPending => return,
                else => return err,
            };
            self.state = .sending;
            self.deadline = now + limits.write_ms;
        }
        if (self.state == .sending) {
            const n = io.send(self.request[self.request_sent..self.request_len]) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            if (n == 0) return error.UpstreamClosed;
            self.request_sent += n;
            if (self.request_sent != self.request_len) return;
            self.state = .headers;
            self.deadline = now + limits.read_ms;
        }
        if (self.pending().len != 0) return;
        if (self.state == .headers) {
            const n = io.recv(self.header[self.header_used..limits.header_bytes]) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            if (n == 0) return error.InvalidResponse;
            self.header_used += n;
            // Absolute header deadline: fragments cannot extend it.
            try self.feedHeaders(now, limits, client_timeout);
        } else if (self.state == .body) {
            const capacity: usize = @intCast(@min(@as(u64, 8192), self.remaining orelse 8192));
            const n = io.recv(self.output[0..capacity]) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            try self.bodyReceived(n, now, client_timeout);
        }
    }
    pub fn advanceClient(self: *Upstream, count: usize, now: u64, limits: config.Limits) bool {
        std.debug.assert(count <= self.pending().len);
        self.committed = self.committed or count != 0;
        self.output_sent += count;
        if (self.pending().len == 0) {
            self.output_len = 0;
            self.output_sent = 0;
            self.deadline = now + limits.read_ms;
            return self.state != .done;
        }
        return true;
    }
    pub fn flushClient(self: *Upstream, client_fd: i32, now: u64, limits: config.Limits) !bool {
        return self.flushIO(now, limits, SocketIO{ .fd = client_fd });
    }
    fn flushIO(self: *Upstream, now: u64, limits: config.Limits, io: anytype) !bool {
        if (self.pending().len == 0) return self.state != .done;
        const n = io.send(self.pending()) catch |err| switch (err) {
            error.WouldBlock => return true,
            else => return err,
        };
        if (n == 0) return error.ClientClosed;
        return self.advanceClient(n, now, limits);
    }
};

test "bounded response stream and client backpressure offsets" {
    var u: Upstream = .{ .state = .headers, .total_deadline = 1000 };
    const bytes = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc";
    @memcpy(u.header[0..bytes.len], bytes);
    u.header_used = bytes.len;
    try u.feedHeaders(10, .{}, 100);
    try std.testing.expectEqual(@as(?u64, 5), u.remaining);
    const size = u.pending().len;
    try std.testing.expect(u.advanceClient(2, 20, .{}));
    try std.testing.expect(u.committed);
    try std.testing.expectEqual(size - 2, u.pending().len);
    try std.testing.expect(u.expired(110)); // Short writes never extend the client deadline.
    try std.testing.expect(u.advanceClient(size - 2, 30, .{}));
    @memcpy(u.output[0..5], "defgh");
    try u.bodyReceived(5, 40, 100);
    try std.testing.expectEqual(State.done, u.state);
    try std.testing.expectEqualStrings("defgh", u.pending());
    try std.testing.expect(!u.advanceClient(5, 50, .{}));
}
test "upstream premature EOF invalid framing and inclusive header ceiling" {
    var u: Upstream = .{ .state = .body, .remaining = 3 };
    try std.testing.expectError(error.TruncatedResponse, u.bodyReceived(0, 1, 100));
    u.remaining = null;
    try u.bodyReceived(0, 1, 100);
    try std.testing.expectEqual(State.done, u.state);
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: ";
    for ([_]usize{ 8191, 8192, 8193 }) |size| {
        u = .{ .state = .headers };
        @memcpy(u.header[0..prefix.len], prefix);
        const fit = @min(size, u.header.len);
        @memset(u.header[prefix.len..fit], 'a');
        if (size <= fit) @memcpy(u.header[size - 4 .. size], "\r\n\r\n");
        u.header_used = fit;
        if (size <= fit) {
            try u.feedHeaders(1, .{}, 100);
            try std.testing.expectEqual(State.done, u.state);
        } else try std.testing.expectError(error.InvalidResponse, u.feedHeaders(1, .{}, 100));
    }
}

const TestIO = struct {
    input: []const u8 = "",
    chunk: usize = 3,
    blocked: bool = false,
    connect_error: ?anyerror = null,
    checks: usize = 0,
    result: [16384]u8 = undefined,
    used: usize = 0,
    fn connected(self: *@This()) !void {
        self.checks += 1;
        if (self.connect_error) |err| return err;
    }
    fn send(self: *@This(), bytes: []const u8) !usize {
        if (self.blocked) return error.WouldBlock;
        const n = @min(bytes.len, self.chunk);
        @memcpy(self.result[self.used..][0..n], bytes[0..n]);
        self.used += n;
        return n;
    }
    fn recv(self: *@This(), bytes: []u8) !usize {
        if (self.blocked) return error.WouldBlock;
        const n = @min(bytes.len, @min(self.chunk, self.input.len));
        @memcpy(bytes[0..n], self.input[0..n]);
        self.input = self.input[n..];
        return n;
    }
};
test "upstream driver short IO EAGAIN and backpressure preserve every byte" {
    var u: Upstream = .{ .state = .connecting, .total_deadline = 10000 };
    const raw = "GET /api/x HTTP/1.1\r\nHost: backend\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    @memcpy(u.request[0..raw.len], raw);
    u.request_len = raw.len;
    var io: TestIO = .{ .blocked = true, .input = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" };
    try u.onIO(1, .{}, 100, &io);
    try std.testing.expectEqual(@as(usize, 1), io.checks);
    try std.testing.expectEqual(@as(usize, 0), u.request_sent);
    io.blocked = false;
    while (u.pending().len == 0) try u.onIO(2, .{}, 100, &io);
    try std.testing.expectEqualStrings(raw, io.result[0..io.used]);
    try std.testing.expectEqual(@as(usize, 1), io.checks);
    const unread = io.input.len;
    try u.onIO(3, .{}, 100, &io);
    try std.testing.expectEqual(unread, io.input.len); // No reads while client output is pending.
    var client: TestIO = .{ .blocked = true };
    try std.testing.expect(try u.flushIO(4, .{}, &client));
    try std.testing.expectEqual(@as(usize, 0), u.output_sent);
    client.blocked = false;
    while (true) {
        while (u.pending().len != 0) {
            if (!try u.flushIO(5, .{}, &client)) break;
        }
        if (u.state == .done) break;
        try u.onIO(6, .{}, 100, &io);
    }
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", client.result[0..client.used]);
}
test "failed asynchronous connect never sends a request" {
    var u: Upstream = .{};
    var io: TestIO = .{ .connect_error = error.ConnectionRefused };
    try std.testing.expectError(error.ConnectionRefused, u.onIO(1, .{}, 100, &io));
    try std.testing.expectEqual(@as(usize, 0), io.used);
    try std.testing.expect(!u.committed);
}
test "stage deadlines and total transaction deadline are independent" {
    var u: Upstream = .{ .deadline = 100, .total_deadline = 300 };
    try std.testing.expect(!u.expired(99));
    try std.testing.expect(u.expired(100));
    u.deadline = 400;
    try std.testing.expect(u.expired(300));
    u.output_len = 1;
    u.client_deadline = 200;
    try std.testing.expect(u.expired(200));
    try std.testing.expect(!u.expired(199));
}

test "large body streams through fixed chunks with no retained history" {
    const chunks = 128;
    var u: Upstream = .{ .state = .body, .remaining = chunks * 8192 };
    for (0..chunks) |index| {
        @memset(u.output[0..8192], @intCast(index));
        try u.bodyReceived(8192, 1, 100);
        var client: TestIO = .{ .chunk = 1023 };
        var alive = true;
        while (u.pending().len != 0) alive = try u.flushIO(2, .{}, &client);
        try std.testing.expectEqual(index + 1 != chunks, alive);
        try std.testing.expectEqual(@as(usize, 8192), client.used);
        for (client.result[0..client.used]) |byte| try std.testing.expectEqual(@as(u8, @intCast(index)), byte);
        try std.testing.expectEqual(@as(?u64, (chunks - index - 1) * 8192), u.remaining);
    }
}

test "pending connect and partial headers cannot extend stage deadlines" {
    var u: Upstream = .{ .state = .connecting, .deadline = 100, .total_deadline = 5000 };
    var io: TestIO = .{ .connect_error = error.WouldBlock };
    for ([_]u64{ 10, 40, 99 }) |now| {
        try u.onIO(now, .{}, 100, &io);
        try std.testing.expectEqual(State.connecting, u.state);
        try std.testing.expectEqual(@as(u64, 100), u.deadline);
        try std.testing.expect(!u.expired(now));
    }
    try std.testing.expect(u.expired(100));
    try std.testing.expectEqual(@as(usize, 0), io.used);
    u = .{ .state = .headers, .deadline = 100, .total_deadline = 5000 };
    io = .{ .blocked = true, .input = "HTTP/1.1 200 OK\r\nX: " };
    try u.onIO(1, .{}, 100, &io);
    io.blocked = false;
    for ([_]u64{ 10, 40, 99 }) |now| {
        try u.onIO(now, .{}, 100, &io);
        try std.testing.expectEqual(State.headers, u.state);
        try std.testing.expectEqual(@as(u64, 100), u.deadline);
        try std.testing.expect(!u.expired(now));
    }
    try std.testing.expect(u.header_used > 0);
    try std.testing.expect(u.expired(100));
    try std.testing.expect(!u.committed);
}
