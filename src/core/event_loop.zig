const std = @import("std");
const p = std.posix;
const linux = std.os.linux;
const E = linux.EPOLL;
const Connection = @import("connection.zig").Connection;
const Options = @import("../cli/commands.zig").Options;
const response = @import("../http/response.zig");
const Upstream = @import("../proxy/upstream_connection.zig").Upstream;
const upstream_bit: u64 = 1 << 31;
const signal_token = std.math.maxInt(u64) - 1;
const tls_listener_token = std.math.maxInt(u64) - 2;
const listener_token = std.math.maxInt(u64);

fn register(epfd: i32, op: u32, fd: i32, events: u32, token: u64) !void {
    var event: linux.epoll_event = .{ .events = events, .data = .{ .u64 = token } };
    try p.epoll_ctl(epfd, op, fd, &event);
}
fn tokenFor(c: *const Connection, index: usize) u64 {
    return (@as(u64, c.generation) << 32) | @as(u64, @intCast(index));
}
fn interest(epfd: i32, c: *const Connection, index: usize) !void {
    try register(epfd, E.CTL_MOD, c.fd, c.tls.events(if (c.state == .writing) @as(u32, E.OUT) else E.IN) | (if (c.peer_eof) @as(u32, 0) else E.RDHUP), tokenFor(c, index));
}
fn release(epfd: i32, c: *Connection, upstreams: []Upstream, metrics: *@import("../observability/metrics.zig").Metrics) void {
    if (c.upstream) |index| {
        upstreams[index].deinit(epfd);
        c.upstream = null;
    }
    p.epoll_ctl(epfd, E.CTL_DEL, c.fd, null) catch {};
    if (c.tls.ssl != null and c.tls.failed) metrics.tls_connection_closure_errors +|= 1;
    c.tls.deinit();
    p.close(c.fd);
    c.fd = -1;
}

fn proxyInterest(epfd: i32, c: *Connection, u: *Upstream, index: usize) !void {
    const client_events: u32 = c.tls.events(if (u.pending().len != 0) @as(u32, E.OUT) else 0) | (if (c.peer_eof) @as(u32, 0) else E.RDHUP);
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
    if (c.tls.write_retry or (c.tls.ssl != null and c.tls.want == .write)) {
        c.tls.failed = true;
        return false;
    }
    const committed = u.committed;
    c.bytes_sent = u.bytes_sent;
    c.status = if (committed) u.status else status;
    u.deinit(epfd);
    c.upstream = null;
    if (committed) return false;
    try c.respond(response.failure(status), std.mem.startsWith(u8, c.input[0..c.used], "HEAD "), true, now, options);
    try interest(epfd, c, index);
    return true;
}

fn retire(epfd: i32, c: *Connection, upstreams: []Upstream, metrics: *@import("../observability/metrics.zig").Metrics, logger: *@import("../observability/logger.zig").Logger, now: u64, options: Options) void {
    observe(c, upstreams, metrics, logger, now, options);
    if (c.state == .tls_handshake) {
        metrics.tls_handshake_failures +|= 1;
        if (now >= c.deadline) metrics.tls_handshake_timeouts +|= 1;
        logger.event(.warn, "tls_handshake_failed", .{ .timeout = now >= c.deadline });
    }
    if (c.tls.ssl != null and c.tls.established and !c.tls.failed and !c.tls.write_retry) {
        if (c.state == .tls_shutdown and now >= c.deadline) {
            c.tls.failed = true;
            metrics.tls_shutdown_failures +|= 1;
        } else {
            const done = c.tls.shutdown() catch |err| blk: {
                if (err == error.WouldBlock) break :blk false;
                metrics.tls_shutdown_failures +|= 1;
                break :blk true;
            };
            if (!done) {
                if (c.upstream) |i| {
                    upstreams[i].deinit(epfd);
                    c.upstream = null;
                }
                if (c.state != .tls_shutdown) c.deadline = now + 1000;
                c.state = .tls_shutdown;
                // Caller-independent token uses the connection's assigned slot index.
                interest(epfd, c, c.slot) catch {
                    release(epfd, c, upstreams, metrics);
                };
                return;
            }
        }
    }
    release(epfd, c, upstreams, metrics);
}

fn requestCompleted(c: *const Connection, previous_state: @import("connection.zig").State, previous_requests: u16) bool {
    return c.state == .idle and (previous_state != .idle or c.requests != previous_requests);
}

fn observe(c: *Connection, upstreams: []Upstream, metrics: *@import("../observability/metrics.zig").Metrics, logger: *@import("../observability/logger.zig").Logger, now: u64, options: Options) void {
    if (c.counted) return;
    var status = c.status;
    var bytes = c.bytes_sent;
    if (c.upstream) |i| {
        status = upstreams[i].status;
        bytes = upstreams[i].bytes_sent;
    }
    if (status == 0) return;
    c.counted = true;
    const duration = now - c.started;
    metrics.response(status, duration);
    const upstream = if (c.proxied) options.proxy.routes[c.proxy_route].authority else "";
    logger.event(.info, "http_request", .{ .status = status, .duration_ms = duration, .bytes_sent = bytes, .upstream = upstream });
}

const SocketIO = struct {
    fd: i32,
    client: ?*Connection = null,
    pub fn recv(self: @This(), buffer: []u8) !usize {
        if (self.client) |client| {
            if (client.tls.ssl != null) return client.tls.recv(buffer);
        }
        return p.recv(self.fd, buffer, p.MSG.DONTWAIT);
    }
    pub fn send(self: @This(), bytes: []const u8) !usize {
        if (self.client) |client| {
            if (client.tls.ssl != null) return client.tls.send(bytes);
        }
        return p.send(self.fd, bytes, p.MSG.NOSIGNAL | p.MSG.DONTWAIT);
    }
};

fn drive(c: *Connection, events: u32, now: u64, options: Options, io: anytype) !bool {
    if (events & E.ERR != 0) {
        if (c.tls.ssl != null) c.tls.failed = true;
        return false;
    }
    if (events & (E.RDHUP | E.HUP) != 0) c.peer_eof = true;
    if (c.state != .writing and c.state != .proxy) {
        const n = io.recv(c.input[c.used..]) catch |err| switch (err) {
            error.WouldBlock => return !c.peer_eof,
            else => return err,
        };
        if (n == 0) return false;
        if (c.state == .idle) {
            c.state = .reading;
            c.status = 0;
            c.counted = false;
            c.bytes_sent = 0;
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
        c.bytes_sent +|= n;
        if (c.pending().len == 0) {
            if (c.close or c.peer_eof) return false;
            c.used = 0;
            c.state = .idle;
            c.deadline = now + options.idle_timeout_ms;
        }
    }
    return true;
}

pub fn run(listener: i32, https: ?i32, options: Options, contexts: *@import("../tls/context.zig").Contexts, manager: ?*@import("../acme/manager.zig").Manager) !void {
    var https_open = https != null;
    defer if (https_open) p.close(https.?);
    var listener_open = true;
    defer if (listener_open) p.close(listener);
    var shutdown = try @import("shutdown.zig").Shutdown.init();
    defer shutdown.deinit();
    if (manager) |m| try m.start();
    defer if (manager) |m| m.stop();
    var logger = @import("../observability/logger.zig").Logger.init(options.log_level);
    defer logger.deinit();
    defer logger.event(.info, "server_stop", .{ .dropped_logs = logger.dropped });
    var admission: @import("../tls/admission.zig").Admission = .{ .limit = options.tls.max_handshakes };
    defer std.debug.assert(admission.active == 0);
    var metrics: @import("../observability/metrics.zig").Metrics = .{};
    logger.event(.info, "server_start", .{ .port = options.port, .max_connections = options.max_connections });
    var timer = try std.time.Timer.start();
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
    defer {
        if (manager) |m| {
            m.stop();
            m.tick(contexts, options.tls, &metrics, &logger);
        }
        metrics.active_tls_handshakes = admission.active;
        metrics.active_tls = 0;
        metrics.active_clients = 0;
        metrics.active_upstreams = 0;
        metrics.uptime_ms = timer.read() / std.time.ns_per_ms;
        logger.event(.info, "metrics", metrics);
    }
    defer for (slots) |*c| {
        if (c.fd != -1) {
            observe(c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
            if (c.state == .tls_handshake) metrics.tls_handshake_failures +|= 1;
            release(epfd, c, upstreams, &metrics);
        }
    };
    try register(epfd, E.CTL_ADD, listener, E.IN, listener_token);
    if (https) |fd| try register(epfd, E.CTL_ADD, fd, E.IN, tls_listener_token);
    try register(epfd, E.CTL_ADD, shutdown.fd, E.IN, signal_token);
    var tls_paused = false;
    var tls_retry_at: u64 = 0;
    var listener_paused = false;
    var retry_at: u64 = 0;

    var events: [128]linux.epoll_event = undefined;
    var next_metrics: u64 = 1000;
    var reload_after: u64 = 0;
    while (true) {
        var now = timer.read() / std.time.ns_per_ms;
        metrics.active_tls_handshakes = admission.active;
        metrics.active_tls = 0;
        metrics.active_clients = 0;
        metrics.active_upstreams = 0;
        for (slots) |c| {
            if (c.fd != -1) {
                metrics.active_clients += 1;
                if (c.tls.ssl != null) metrics.active_tls += 1;
            }
        }
        for (upstreams) |u| {
            if (u.active and u.fd != -1) metrics.active_upstreams += 1;
        }
        metrics.uptime_ms = now;
        if (manager) |m| m.tick(contexts, options.tls, &metrics, &logger);
        if (now >= next_metrics) {
            logger.event(.info, "metrics", metrics);
            next_metrics = now + 1000;
        }
        if (shutdown.state != .running) {
            if (shutdown.state == .forced or now >= shutdown.deadline or metrics.active_clients == 0) {
                logger.event(.info, "shutdown_complete", .{ .forced = shutdown.state == .forced or now >= shutdown.deadline, .remaining = metrics.active_clients });
                break;
            }
        }
        if (shutdown.state == .running and listener_paused and now >= retry_at) {
            try register(epfd, E.CTL_ADD, listener, E.IN, listener_token);
            listener_paused = false;
        }
        if (shutdown.state == .running and tls_paused and now >= tls_retry_at) {
            try register(epfd, E.CTL_ADD, https.?, E.IN, tls_listener_token);
            tls_paused = false;
        }
        var wait_ms: u64 = 50;
        // Check deadlines before processing readiness, including continuously ready sockets.
        for (slots, 0..) |*c, index| {
            if (c.fd == -1) continue;
            if (shutdown.state != .running) {
                c.draining = true;
                c.close = true;
                if (c.state == .tls_handshake or c.state == .idle or (c.state == .reading and c.used == 0)) {
                    retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                    continue;
                }
            }
            if (c.state != .idle and c.state != .tls_handshake and c.state != .tls_shutdown and now >= c.started + options.request_ms) {
                retire(epfd, c, upstreams, &metrics, &logger, now, options);
                continue;
            }
            if (c.state != .idle and c.state != .tls_handshake and c.state != .tls_shutdown) wait_ms = @min(wait_ms, c.started + options.request_ms - now);
            if (c.state == .proxy) {
                const u = &upstreams[c.upstream.?];
                if (u.expired(now)) {
                    metrics.proxy_failures +|= 1;
                    logger.event(.warn, "proxy_failure", .{ .status = @as(u16, 504) });
                    if (!(proxyFailure(epfd, c, u, 504, now, options, index) catch false)) {
                        retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                        continue;
                    }
                } else {
                    const due = @min(u.total_deadline, if (u.pending().len != 0) u.client_deadline else u.deadline);
                    wait_ms = @min(wait_ms, due - now);
                    continue;
                }
            }
            if (c.expired(now)) {
                if (c.state == .reading and !(c.tls.ssl != null and c.tls.want == .write)) {
                    c.respond(response.failure(408), std.mem.startsWith(u8, c.input[0..c.used], "HEAD "), true, now, options) catch {
                        retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                        continue;
                    };
                    interest(epfd, c, index) catch {
                        retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                        continue;
                    };
                } else {
                    retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                    continue;
                }
            }
            wait_ms = @min(wait_ms, c.deadline - now);
        }
        if (shutdown.state == .draining) wait_ms = @min(wait_ms, shutdown.deadline - now);
        // Use the raw wait so EINTR returns to deadline processing rather than restarting a full wait.
        var synthetic: usize = 0;
        for (slots, 0..) |*client, index| {
            if (synthetic == 64) break;
            if (client.fd != -1 and (client.state == .reading or client.state == .idle) and client.tls.pending()) {
                events[synthetic] = .{ .events = E.IN, .data = .{ .u64 = tokenFor(client, index) } };
                synthetic += 1;
            }
        }
        const rc = linux.epoll_wait(epfd, events[synthetic..].ptr, @intCast(events.len - synthetic), if (synthetic > 0) 0 else @intCast(wait_ms));
        const count: usize = switch (p.errno(rc)) {
            .SUCCESS => rc + synthetic,
            .INTR => continue,
            else => return error.EpollWaitFailed,
        };
        now = timer.read() / std.time.ns_per_ms;
        var reload_requested = false;
        // Process termination before any accepts in this readiness batch.
        for (events[0..count]) |event| {
            if (event.data.u64 != signal_token) continue;
            var records: [128]u8 = undefined;
            for (0..64) |_| {
                const n = p.read(shutdown.fd, &records) catch break;
                if (n == 0) break;
                const signo = std.mem.bytesToValue(u32, records[0..4]);
                if (signo == p.SIG.HUP) {
                    reload_requested = true;
                    continue;
                }
                const was_running = shutdown.state == .running;
                shutdown.signal(now, options.shutdown_ms);
                if (manager) |m| m.requestStop();
                if (was_running) {
                    if (!listener_paused) try p.epoll_ctl(epfd, E.CTL_DEL, listener, null);
                    listener_paused = true;
                    p.close(listener);
                    listener_open = false;
                    if (https_open) {
                        if (!tls_paused) try p.epoll_ctl(epfd, E.CTL_DEL, https.?, null);
                        p.close(https.?);
                        https_open = false;
                    }
                    logger.event(.info, "shutdown_begin", .{ .grace_ms = options.shutdown_ms });
                }
            }
        }
        if (reload_requested and shutdown.state == .running) {
            const reload_started = timer.read() / std.time.ns_per_ms;
            if (reload_started < reload_after) {
                metrics.tls_reload_failures +|= 1;
                logger.event(.warn, "tls_reload_failed", .{ .reason = "rate_limited", .retry_after_ms = reload_after - reload_started });
            } else {
                const success = blk: {
                    contexts.reload() catch |err| {
                        metrics.tls_reload_failures +|= 1;
                        logger.event(.warn, "tls_reload_failed", .{ .reason = @errorName(err), .retry_after_ms = @as(u16, 1000) });
                        break :blk false;
                    };
                    break :blk true;
                };
                now = timer.read() / std.time.ns_per_ms;
                reload_after = now + 1000;
                if (success) {
                    metrics.tls_reload_successes +|= 1;
                    logger.event(.info, "tls_reload_success", .{ .duration_ms = now - reload_started, .retry_after_ms = @as(u16, 1000) });
                }
            }
            now = timer.read() / std.time.ns_per_ms;
        }
        if (shutdown.state == .forced) continue;
        for (events[0..count]) |event| {
            now = timer.read() / std.time.ns_per_ms;
            if (shutdown.state == .draining and now >= shutdown.deadline) break;
            if (event.data.u64 == signal_token) continue;
            if (event.data.u64 == listener_token or event.data.u64 == tls_listener_token) {
                const secure = event.data.u64 == tls_listener_token;
                if ((if (secure) tls_paused else listener_paused) or shutdown.state != .running) continue;
                const accept_fd = if (secure) https.? else listener;
                // Bound accept work per batch so a connection flood cannot starve existing clients.
                for (0..64) |_| {
                    var peer: std.net.Address = undefined;
                    var peer_len: p.socklen_t = @sizeOf(std.net.Address);
                    const fd = p.accept(accept_fd, &peer.any, &peer_len, p.SOCK.NONBLOCK | p.SOCK.CLOEXEC) catch |err| switch (err) {
                        error.WouldBlock => break,
                        error.ConnectionAborted => continue,
                        else => {
                            // Quota/resource failure: stop listener readiness spin and retry later.
                            logger.event(.warn, "accept_failure", .{});
                            try p.epoll_ctl(epfd, E.CTL_DEL, accept_fd, null);
                            if (secure) {
                                tls_paused = true;
                                tls_retry_at = now + 100;
                            } else {
                                listener_paused = true;
                                retry_at = now + 100;
                            }
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
                        metrics.connection_rejections +|= 1;
                        if (secure) metrics.tls_handshake_rejections +|= 1;
                        logger.event(.warn, "connection_rejected", .{});
                        p.close(fd);
                        continue;
                    };
                    const c = &slots[index];
                    const generation = c.generation +% 1;
                    c.* = .{ .slot = index, .fd = fd, .generation = generation, .started = now, .deadline = now + options.timeout_ms, .peer_ip = @bitCast(peer.in.sa.addr) };
                    if (secure) {
                        if (contexts.active().default == null) {
                            release(epfd, c, upstreams, &metrics);
                            continue;
                        }
                        c.tls = @import("../tls/session.zig").Session.init(contexts.active(), fd, &admission) catch |err| {
                            if (err == error.TlsAdmissionRejected) {
                                metrics.tls_handshake_rejections +|= 1;
                                logger.event(.warn, "tls_handshake_rejected", .{});
                            } else metrics.tls_handshake_failures +|= 1;
                            release(epfd, c, upstreams, &metrics);
                            continue;
                        };
                        c.state = .tls_handshake;
                        c.deadline = now + options.tls.handshake_ms;
                        logger.event(.debug, "tls_accepted", .{});
                    }
                    register(epfd, E.CTL_ADD, fd, E.IN | (if (c.peer_eof) @as(u32, 0) else E.RDHUP), tokenFor(c, index)) catch {
                        release(epfd, c, upstreams, &metrics);
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
            if (c.state != .idle and c.state != .tls_handshake and c.state != .tls_shutdown and now >= c.started + options.request_ms) {
                retire(epfd, c, upstreams, &metrics, &logger, now, options);
                continue;
            }
            if (c.state == .tls_handshake) {
                if (c.expired(now)) {
                    retire(epfd, c, upstreams, &metrics, &logger, now, options);
                    continue;
                }
                c.tls.handshake() catch |err| {
                    if (err == error.WouldBlock) {
                        interest(epfd, c, index) catch {
                            retire(epfd, c, upstreams, &metrics, &logger, now, options);
                        };
                    } else retire(epfd, c, upstreams, &metrics, &logger, now, options);
                    continue;
                };
                metrics.tls_handshake_successes +|= 1;
                if (c.tls.version() == 0x0303) metrics.tls_1_2 +|= 1;
                if (c.tls.version() == 0x0304) metrics.tls_1_3 +|= 1;
                logger.event(.info, "tls_handshake", .{ .duration_ms = now - c.started, .version = c.tls.version() });
                c.state = .reading;
                c.started = now;
                c.deadline = now + options.timeout_ms;
            }
            if (c.state == .tls_shutdown) {
                retire(epfd, c, upstreams, &metrics, &logger, now, options);
                continue;
            }
            if (c.state == .proxy) {
                const u = &upstreams[c.upstream.?];
                if (u.expired(now)) continue;
                var alive = true;
                if (is_upstream) {
                    u.onUpstream(now, options.proxy_limits, options.timeout_ms) catch |err| {
                        metrics.proxy_failures +|= 1;
                        logger.event(.warn, "proxy_failure", .{});
                        alive = proxyFailure(epfd, c, u, if (err == error.ConnectionTimedOut) 504 else 502, now, options, index) catch false;
                    };
                } else {
                    if (event.events & (E.ERR | E.HUP) != 0) {
                        if (c.tls.ssl != null) c.tls.failed = true;
                        retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                        continue;
                    }
                    if (event.events & E.RDHUP != 0) c.peer_eof = true;
                }
                if (!alive) {
                    retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                    continue;
                }
                if (c.state == .proxy) {
                    alive = u.flushIO(now, options.proxy_limits, SocketIO{ .fd = c.fd, .client = c }) catch false;
                    if (!alive) {
                        retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                        continue;
                    }
                    u.total_deadline = @min(u.total_deadline, c.started + options.request_ms);
                    proxyInterest(epfd, c, u, index) catch {
                        if (!(proxyFailure(epfd, c, u, 503, now, options, index) catch false)) retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                    };
                }
                continue;
            }
            if (is_upstream) continue;
            // Readiness returned at the deadline must not extend an expired operation.
            if (c.expired(now)) continue;
            if (shutdown.state != .running and (c.state == .tls_handshake or c.state == .idle or (c.state == .reading and c.used == 0))) {
                retire(epfd, c, upstreams, &metrics, &logger, now, options);
                continue;
            }
            if (shutdown.state != .running) {
                c.draining = true;
                c.close = true;
            }
            const previous_state = c.state;
            const previous_requests = c.requests;
            const previous_used = c.used;
            if (previous_state == .idle) c.started = now;
            const alive = drive(c, event.events, now, options, SocketIO{ .fd = c.fd, .client = c }) catch false;
            if (previous_used == 0 and c.used != 0) logger.event(.debug, "request_started", .{});
            if (c.requests != previous_requests or (c.status != 0 and previous_state == .reading)) metrics.requests +|= 1;
            if (requestCompleted(c, previous_state, previous_requests)) observe(c, upstreams, &metrics, &logger, now, options);
            if (!alive) {
                retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
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
                    u.startSecure(c.input[0..end], options.proxy.routes[c.proxy_route], c.peer_ip, options.proxy_limits, now, c.tls.ssl != null) catch |err| {
                        metrics.proxy_failures +|= 1;
                        logger.event(.warn, "proxy_failure", .{ .upstream = options.proxy.routes[c.proxy_route].authority });
                        const status: u16 = switch (err) {
                            error.InvalidHeaders => 400,
                            error.UnsupportedUpgrade => 501,
                            error.NoSpaceLeft => 431,
                            error.ConnectionTimedOut => 504,
                            error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => 503,
                            else => 502,
                        };
                        if (!(proxyFailure(epfd, c, u, status, now, options, index) catch false)) retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                        continue;
                    };
                    u.total_deadline = @min(u.total_deadline, c.started + options.request_ms);
                    proxyInterest(epfd, c, u, index) catch {
                        if (!(proxyFailure(epfd, c, u, 503, now, options, index) catch false)) retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                    };
                } else {
                    logger.event(.warn, "upstream_capacity", .{});
                    try c.respond(response.failure(503), std.mem.startsWith(u8, c.input[0..c.used], "HEAD "), true, now, options);
                    interest(epfd, c, index) catch {
                        retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
                    };
                }
            } else interest(epfd, c, index) catch {
                retire(epfd, c, upstreams, &metrics, &logger, timer.read() / std.time.ns_per_ms, options);
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

test "fast sequential keep-alive responses are each observed once" {
    var c: Connection = .{ .deadline = 1000 };
    var metrics: @import("../observability/metrics.zig").Metrics = .{};
    var logger: @import("../observability/logger.zig").Logger = .{};
    for (0..2) |_| {
        const previous_state = c.state;
        const previous_requests = c.requests;
        var io: TestIO = .{ .input = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n", .chunk = 1024 };
        try std.testing.expect(try drive(&c, E.IN, 1, .{}, &io));
        if (requestCompleted(&c, previous_state, previous_requests)) observe(&c, &.{}, &metrics, &logger, 1, .{});
    }
    try std.testing.expectEqual(@as(u64, 2), metrics.responses_2xx);
    try std.testing.expectEqual(@as(u16, 2), c.requests);
}
