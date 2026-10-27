const std = @import("std");
const p = std.posix;
const linux = std.os.linux;
const E = linux.EPOLL;
const Connection = @import("connection.zig").Connection;
const Options = @import("../cli/commands.zig").Options;
const response = @import("../http/response.zig");
const Upstream = @import("../proxy/upstream_connection.zig").Upstream;
const upstream_bit: u64 = 1 << 31;
const listener_token = std.math.maxInt(u64);

fn register(epfd: i32, op: u32, fd: i32, events: u32, token: u64) !void {
    var event: linux.epoll_event = .{ .events = events, .data = .{ .u64 = token } };
    try p.epoll_ctl(epfd, op, fd, &event);
}
fn tokenFor(c: *const Connection, index: usize) u64 {
    return (@as(u64, c.generation) << 32) | @as(u64, @intCast(index));
}
fn interest(epfd: i32, c: *const Connection, index: usize) !void {
    try register(epfd, E.CTL_MOD, c.fd, (if (c.state == .writing) @as(u32, E.OUT) else E.IN) | (if (c.peer_eof) @as(u32, 0) else E.RDHUP), tokenFor(c, index));
}
fn release(epfd: i32, c: *Connection, upstreams: []Upstream) void {
    if (c.upstream) |index| {
        upstreams[index].deinit(epfd);
        c.upstream = null;
    }
    p.epoll_ctl(epfd, E.CTL_DEL, c.fd, null) catch {};
    p.close(c.fd);
    c.fd = -1;
}

fn proxyInterest(epfd: i32, c: *Connection, u: *Upstream, index: usize) !void {
    const client_events: u32 = (if (u.pending().len != 0) @as(u32, E.OUT) else 0) | (if (c.peer_eof) @as(u32, 0) else E.RDHUP);
    try register(epfd, E.CTL_MOD, c.fd, client_events, tokenFor(c, index));
    if (u.state == .done) {
        u.closeSocket(epfd);
        return;
    }
    if (u.pending().len != 0) {
        if (u.registered) {
            try p.epoll_ctl(epfd, E.CTL_DEL, u.fd, null);
            u.registered = false;
        }
    } else {
        const events: u32 = if (u.state == .connecting or u.state == .sending) E.OUT else E.IN;
        try register(epfd, if (u.registered) E.CTL_MOD else E.CTL_ADD, u.fd, events, tokenFor(c, index) | upstream_bit);
        u.registered = true;
    }
}
fn proxyFailure(epfd: i32, c: *Connection, u: *Upstream, status: u16, now: u64, options: Options, index: usize) !bool {
    const committed = u.committed;
    u.deinit(epfd);
    c.upstream = null;
    if (committed) return false;
    try c.respond(response.failure(status), std.mem.startsWith(u8, c.input[0..c.used], "HEAD "), true, now, options);
    try interest(epfd, c, index);
    return true;
}

const SocketIO = struct {
    fd: i32,
    fn recv(self: @This(), buffer: []u8) !usize {
        return p.recv(self.fd, buffer, p.MSG.DONTWAIT);
    }
    fn send(self: @This(), bytes: []const u8) !usize {
        return p.send(self.fd, bytes, p.MSG.NOSIGNAL | p.MSG.DONTWAIT);
    }
};

fn drive(c: *Connection, events: u32, now: u64, options: Options, io: anytype) !bool {
    if (events & E.ERR != 0) return false;
    if (events & (E.RDHUP | E.HUP) != 0) c.peer_eof = true;
    if (c.state != .writing and c.state != .proxy) {
        const n = io.recv(c.input[c.used..]) catch |err| switch (err) {
            error.WouldBlock => return !c.peer_eof,
            else => return err,
        };
        if (n == 0) return false;
        if (c.state == .idle) {
            c.state = .reading;
            c.deadline = now + options.timeout_ms;
        }
        c.used += n;
        try c.process(now, options);
    }
    if (c.state == .writing) {
        const n = io.send(c.pending()) catch |err| switch (err) {
            error.WouldBlock => return true,
            else => return err,
        };
        if (n == 0) return false;
        c.advance(n);
        if (c.pending().len == 0) {
            if (c.close or c.peer_eof) return false;
            c.used = 0;
            c.state = .idle;
            c.deadline = now + options.idle_timeout_ms;
        }
    }
    return true;
}

pub fn run(listener: i32, options: Options) !void {
    const epfd = try p.epoll_create1(E.CLOEXEC);
    defer p.close(epfd);
    const slots = try std.heap.page_allocator.alloc(Connection, options.max_connections);
    defer std.heap.page_allocator.free(slots);
    const upstreams = try std.heap.page_allocator.alloc(Upstream, if (options.proxy.count == 0) 0 else options.proxy_limits.max_active);
    defer std.heap.page_allocator.free(upstreams);
    for (upstreams) |*u| u.active = false;
    for (slots) |*c| {
        c.fd = -1;
        c.generation = 0;
    }
    defer for (slots) |*c| {
        if (c.fd != -1) release(epfd, c, upstreams);
    };
    try register(epfd, E.CTL_ADD, listener, E.IN, listener_token);
    var listener_paused = false;
    var retry_at: u64 = 0;
    var timer = try std.time.Timer.start();
    var events: [128]linux.epoll_event = undefined;
    while (true) {
        var now = timer.read() / std.time.ns_per_ms;
        if (listener_paused and now >= retry_at) {
            try register(epfd, E.CTL_ADD, listener, E.IN, listener_token);
            listener_paused = false;
        }
        var wait_ms: u64 = 50;
        // Check deadlines before processing readiness, including continuously ready sockets.
        for (slots, 0..) |*c, index| {
            if (c.fd == -1) continue;
            if (c.state == .proxy) {
                const u = &upstreams[c.upstream.?];
                if (u.expired(now)) {
                    if (!(proxyFailure(epfd, c, u, 504, now, options, index) catch false)) {
                        release(epfd, c, upstreams);
                        continue;
                    }
                } else {
                    const due = @min(u.total_deadline, if (u.pending().len != 0) u.client_deadline else u.deadline);
                    wait_ms = @min(wait_ms, due - now);
                    continue;
                }
            }
            if (c.expired(now)) {
                if (c.state == .reading) {
                    c.respond(response.failure(408), std.mem.startsWith(u8, c.input[0..c.used], "HEAD "), true, now, options) catch {
                        release(epfd, c, upstreams);
                        continue;
                    };
                    interest(epfd, c, index) catch {
                        release(epfd, c, upstreams);
                        continue;
                    };
                } else {
                    release(epfd, c, upstreams);
                    continue;
                }
            }
            wait_ms = @min(wait_ms, c.deadline - now);
        }
        // Use the raw wait so EINTR returns to deadline processing rather than restarting a full wait.
        const rc = linux.epoll_wait(epfd, &events, events.len, @intCast(wait_ms));
        const count: usize = switch (p.errno(rc)) {
            .SUCCESS => rc,
            .INTR => continue,
            else => return error.EpollWaitFailed,
        };
        now = timer.read() / std.time.ns_per_ms;
        for (events[0..count]) |event| {
            if (event.data.u64 == listener_token) {
                if (listener_paused) continue;
                // Bound accept work per batch so a connection flood cannot starve existing clients.
                for (0..64) |_| {
                    var peer: std.net.Address = undefined;
                    var peer_len: p.socklen_t = @sizeOf(std.net.Address);
                    const fd = p.accept(listener, &peer.any, &peer_len, p.SOCK.NONBLOCK | p.SOCK.CLOEXEC) catch |err| switch (err) {
                        error.WouldBlock => break,
                        error.ConnectionAborted => continue,
                        else => {
                            // Quota/resource failure: stop listener readiness spin and retry later.
                            std.log.warn("accept failed: {s}", .{@errorName(err)});
                            try p.epoll_ctl(epfd, E.CTL_DEL, listener, null);
                            listener_paused = true;
                            retry_at = now + 100;
                            break;
                        },
                    };
                    var free: ?usize = null;
                    for (slots, 0..) |*c, index| {
                        if (c.fd == -1) {
                            free = index;
                            break;
                        }
                    }
                    const index = free orelse {
                        p.close(fd);
                        continue;
                    };
                    const c = &slots[index];
                    const generation = c.generation +% 1;
                    c.* = .{ .fd = fd, .generation = generation, .deadline = now + options.timeout_ms, .peer_ip = @bitCast(peer.in.sa.addr) };
                    register(epfd, E.CTL_ADD, fd, E.IN | (if (c.peer_eof) @as(u32, 0) else E.RDHUP), tokenFor(c, index)) catch {
                        p.close(fd);
                        c.fd = -1;
                    };
                }
                continue;
            }
            const is_upstream = event.data.u64 & upstream_bit != 0;
            const client_token = event.data.u64 & ~upstream_bit;
            const index: usize = @intCast(client_token & 0xffffffff);
            if (index >= slots.len) continue;
            const c = &slots[index];
            if (c.fd == -1 or tokenFor(c, index) != client_token) continue;
            if (c.state == .proxy) {
                const u = &upstreams[c.upstream.?];
                if (u.expired(now)) continue;
                var alive = true;
                if (is_upstream) {
                    u.onUpstream(now, options.proxy_limits, options.timeout_ms) catch |err| {
                        alive = proxyFailure(epfd, c, u, if (err == error.ConnectionTimedOut) 504 else 502, now, options, index) catch false;
                    };
                } else {
                    if (event.events & (E.ERR | E.HUP) != 0) {
                        release(epfd, c, upstreams);
                        continue;
                    }
                    if (event.events & E.RDHUP != 0) c.peer_eof = true;
                }
                if (!alive) {
                    release(epfd, c, upstreams);
                    continue;
                }
                if (c.state == .proxy) {
                    alive = u.flushClient(c.fd, now, options.proxy_limits) catch false;
                    if (!alive) {
                        release(epfd, c, upstreams);
                        continue;
                    }
                    proxyInterest(epfd, c, u, index) catch {
                        if (!(proxyFailure(epfd, c, u, 503, now, options, index) catch false)) release(epfd, c, upstreams);
                    };
                }
                continue;
            }
            if (is_upstream) continue;
            // Readiness returned at the deadline must not extend an expired operation.
            if (c.expired(now)) continue;
            const alive = drive(c, event.events, now, options, SocketIO{ .fd = c.fd }) catch false;
            if (!alive) {
                release(epfd, c, upstreams);
                continue;
            }
            if (c.state == .proxy) {
                var free: ?usize = null;
                for (upstreams, 0..) |*u, i| {
                    if (!u.active) {
                        free = i;
                        break;
                    }
                }
                if (free) |i| {
                    c.upstream = i;
                    const u = &upstreams[i];
                    const end = std.mem.indexOf(u8, c.input[0..c.used], "\r\n\r\n").? + 4;
                    u.start(c.input[0..end], options.proxy.routes[c.proxy_route], c.peer_ip, options.proxy_limits, now) catch |err| {
                        const status: u16 = switch (err) {
                            error.InvalidHeaders => 400,
                            error.UnsupportedUpgrade => 501,
                            error.NoSpaceLeft => 431,
                            error.ConnectionTimedOut => 504,
                            error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => 503,
                            else => 502,
                        };
                        if (!(proxyFailure(epfd, c, u, status, now, options, index) catch false)) release(epfd, c, upstreams);
                        continue;
                    };
                    proxyInterest(epfd, c, u, index) catch {
                        if (!(proxyFailure(epfd, c, u, 503, now, options, index) catch false)) release(epfd, c, upstreams);
                    };
                } else {
                    try c.respond(response.failure(503), std.mem.startsWith(u8, c.input[0..c.used], "HEAD "), true, now, options);
                    interest(epfd, c, index) catch {
                        release(epfd, c, upstreams);
                    };
                }
            } else interest(epfd, c, index) catch {
                release(epfd, c, upstreams);
            };
        }
    }
}

test "generation tokens distinguish reused slots" {
    var c: Connection = .{ .generation = 2 };
    const old = tokenFor(&c, 7);
    c.generation += 1;
    try std.testing.expect(old != tokenFor(&c, 7));
    try std.testing.expectEqual(@as(u64, 7), tokenFor(&c, 7) & 0xffffffff);
}

// Script the transport to deterministically exercise short writes and backpressure.
const TestIO = struct {
    input: []const u8 = "",
    chunk: usize = 3,
    blocked: bool = false,
    result: [1024]u8 = undefined,
    used: usize = 0,
    fn recv(self: *@This(), buffer: []u8) !usize {
        if (self.blocked) return error.WouldBlock;
        const n = @min(buffer.len, @min(self.chunk, self.input.len));
        @memcpy(buffer[0..n], self.input[0..n]);
        self.input = self.input[n..];
        return n;
    }
    fn send(self: *@This(), bytes: []const u8) !usize {
        if (self.blocked) return error.WouldBlock;
        const n = @min(bytes.len, self.chunk);
        @memcpy(self.result[self.used..][0..n], bytes[0..n]);
        self.used += n;
        return n;
    }
};
test "partial reads writes and EAGAIN preserve connection state" {
    var c: Connection = .{ .deadline = 1000 };
    var io: TestIO = .{ .input = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n" };
    while (c.state == .reading) try std.testing.expect(try drive(&c, E.IN, 1, .{}, &io));
    try std.testing.expectEqual(@import("connection.zig").State.writing, c.state);
    const sent = c.sent;
    io.blocked = true;
    try std.testing.expect(try drive(&c, E.OUT, 2, .{}, &io));
    try std.testing.expectEqual(sent, c.sent);
    io.blocked = false;
    while (c.state == .writing) try std.testing.expect(try drive(&c, E.OUT, 3, .{}, &io));
    try std.testing.expectEqual(@import("connection.zig").State.idle, c.state);
    try std.testing.expectEqualStrings(c.output[0..c.output_len], io.result[0..io.used]);
    try std.testing.expectEqual(@as(usize, 0), c.used);
    io.blocked = true;
    try std.testing.expect(try drive(&c, E.IN, 4, .{}, &io));
    try std.testing.expectEqual(@as(u64, 5003), c.deadline);
    io.blocked = false;
    try std.testing.expect(!try drive(&c, E.RDHUP, 5, .{}, &io));
}
test "half closed complete request flushes before release" {
    var c: Connection = .{ .deadline = 1000 };
    var io: TestIO = .{ .input = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n", .chunk = 64 };
    try std.testing.expect(try drive(&c, E.IN | E.RDHUP, 1, .{}, &io));
    try std.testing.expect(c.close);
    var alive = true;
    while (alive) alive = try drive(&c, E.OUT, 2, .{}, &io);
    try std.testing.expect(std.mem.endsWith(u8, io.result[0..io.used], "ok\n"));
}

test "half-close drains available fragments before EOF" {
    var c: Connection = .{ .deadline = 1000 };
    var io: TestIO = .{ .input = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n", .chunk = 3 };
    while (c.state == .reading) try std.testing.expect(try drive(&c, E.IN | E.RDHUP, 1, .{}, &io));
    try std.testing.expect(c.close);
    var alive = true;
    while (alive) alive = try drive(&c, E.OUT, 2, .{}, &io);
    try std.testing.expect(std.mem.endsWith(u8, io.result[0..io.used], "ok\n"));
}
