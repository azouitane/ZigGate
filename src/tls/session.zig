const c = @import("context.zig").c;
const E = @import("std").os.linux.EPOLL;
pub const Session = struct {
    ssl: ?*c.SSL = null,
    generation: ?*@import("context.zig").Generation = null,
    permit: ?*@import("admission.zig").Admission = null,
    want: enum { none, read, write } = .none,
    failed: bool = false,
    write_retry: bool = false,
    established: bool = false,
    closing: bool = false,
    pub fn init(generation: *@import("context.zig").Generation, fd: i32, admission: *@import("admission.zig").Admission) !Session {
        if (!admission.acquire()) return error.TlsAdmissionRejected;
        errdefer admission.release();
        c.ERR_clear_error();
        const ssl = c.SSL_new(generation.default) orelse return error.TlsAllocationFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, fd) != 1) return error.TlsSocketFailed;
        c.SSL_set_accept_state(ssl);
        generation.retain();
        return .{ .ssl = ssl, .generation = generation, .permit = admission };
    }
    pub fn deinit(self: *Session) void {
        if (self.ssl) |ssl| c.SSL_free(ssl);
        self.ssl = null;
        self.finishHandshake();
        if (self.generation) |generation| generation.release();
        self.generation = null;
        c.ERR_clear_error();
    }
    fn finishHandshake(self: *Session) void {
        if (self.permit) |permit| permit.release();
        self.permit = null;
    }
    fn result(self: *Session, rc: c_int) !void {
        const err = c.SSL_get_error(self.ssl, rc);
        switch (err) {
            c.SSL_ERROR_WANT_READ => self.want = .read,
            c.SSL_ERROR_WANT_WRITE => self.want = .write,
            else => {
                self.failed = true;
                c.ERR_clear_error();
                return error.TlsProtocolError;
            },
        }
        return error.WouldBlock;
    }
    pub fn handshake(self: *Session) !void {
        c.ERR_clear_error();
        const rc = c.SSL_accept(self.ssl);
        if (rc != 1) return self.result(rc);
        self.want = .none;
        self.established = true;
        self.finishHandshake();
    }
    pub fn recv(self: *Session, bytes: []u8) !usize {
        c.ERR_clear_error();
        var n: usize = 0;
        const rc = c.SSL_read_ex(self.ssl, bytes.ptr, bytes.len, &n);
        if (rc != 1) {
            if (c.SSL_get_error(self.ssl, rc) == c.SSL_ERROR_ZERO_RETURN) {
                self.want = .none;
                return 0;
            }
            try self.result(rc);
        }
        self.want = .none;
        return n;
    }
    pub fn send(self: *Session, bytes: []const u8) !usize {
        c.ERR_clear_error();
        var n: usize = 0;
        const rc = c.SSL_write_ex(self.ssl, bytes.ptr, bytes.len, &n);
        if (rc != 1) {
            self.write_retry = true;
            try self.result(rc);
        }
        self.write_retry = false;
        self.want = .none;
        return n;
    }
    /// Complete when our close_notify is sent. Do not wait for the peer's reply.
    pub fn shutdown(self: *Session) !bool {
        if (self.failed or self.write_retry or (self.want == .write and !self.closing) or !self.established) return true;
        c.ERR_clear_error();
        self.closing = true;
        const rc = c.SSL_shutdown(self.ssl);
        if (rc >= 0) {
            self.want = .none;
            return true;
        }
        try self.result(rc);
        return false;
    }
    pub fn events(self: *const Session, fallback: u32) u32 {
        return switch (self.want) {
            .none => fallback,
            .read => E.IN,
            .write => E.OUT,
        };
    }
    pub fn pending(self: *const Session) bool {
        return self.ssl != null and c.SSL_pending(self.ssl) > 0;
    }
    pub fn version(self: *const Session) c_int {
        return c.SSL_version(self.ssl);
    }
};

test "opposite readiness directions override HTTP interests" {
    const std = @import("std");
    var session: Session = .{ .want = .read };
    try std.testing.expectEqual(@as(u32, E.IN), session.events(E.OUT));
    session.want = .write;
    try std.testing.expectEqual(@as(u32, E.OUT), session.events(E.IN));
}

test "real OpenSSL bounded BIO pair retries and partial writes preserve bytes" {
    const std = @import("std");
    const server_ctx = c.SSL_CTX_new(c.TLS_server_method()).?;
    defer c.SSL_CTX_free(server_ctx);
    try std.testing.expectEqual(@as(c_int, 1), c.zg_tls_policy(server_ctx));
    const key = c.EVP_PKEY_Q_keygen(null, null, "EC", @as([*:0]const u8, "prime256v1")).?;
    defer c.EVP_PKEY_free(key);
    const cert = c.X509_new().?;
    defer c.X509_free(cert);
    _ = c.X509_set_version(cert, 2);
    _ = c.ASN1_INTEGER_set(c.X509_get_serialNumber(cert), 1);
    _ = c.X509_gmtime_adj(c.X509_getm_notBefore(cert), -60);
    _ = c.X509_gmtime_adj(c.X509_getm_notAfter(cert), 3600);
    _ = c.X509_set_pubkey(cert, key);
    const name = c.X509_get_subject_name(cert);
    _ = c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, "transport.test", -1, -1, 0);
    _ = c.X509_set_issuer_name(cert, name);
    try std.testing.expect(c.X509_sign(cert, key, c.EVP_sha256()) > 0);
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_CTX_use_certificate(server_ctx, cert));
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_CTX_use_PrivateKey(server_ctx, key));
    const client_ctx = c.SSL_CTX_new(c.TLS_client_method()).?;
    defer c.SSL_CTX_free(client_ctx);
    const server_ssl = c.SSL_new(server_ctx).?;
    var server: Session = .{ .ssl = server_ssl };
    defer server.deinit();
    const client = c.SSL_new(client_ctx).?;
    defer c.SSL_free(client);
    var server_bio: ?*c.BIO = null;
    var client_bio: ?*c.BIO = null;
    try std.testing.expectEqual(@as(c_int, 1), c.BIO_new_bio_pair(&server_bio, 20000, &client_bio, 20000));
    c.SSL_set_bio(server_ssl, server_bio, server_bio);
    c.SSL_set_bio(client, client_bio, client_bio);
    c.SSL_set_accept_state(server_ssl);
    c.SSL_set_connect_state(client);
    var client_ready = false;
    for (0..1000) |_| {
        if (!client_ready) {
            c.ERR_clear_error();
            const rc = c.SSL_connect(client);
            if (rc == 1) client_ready = true else {
                const err = c.SSL_get_error(client, rc);
                try std.testing.expect(err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE);
            }
        }
        if (!server.established) server.handshake() catch |err| {
            try std.testing.expectEqual(error.WouldBlock, err);
        };
        if (server.established and client_ready) break;
    }
    try std.testing.expect(server.established and client_ready);
    const payload: [32768]u8 = @splat('z');
    var sent: usize = 0;
    var received: usize = 0;
    var retries: usize = 0;
    var partials: usize = 0;
    var buffer: [1024]u8 = undefined;
    for (0..10000) |_| {
        if (sent < payload.len) {
            const n = server.send(payload[sent..]) catch |err| blk: {
                try std.testing.expectEqual(error.WouldBlock, err);
                retries += 1;
                break :blk 0;
            };
            if (n > 0 and n < payload.len - sent) partials += 1;
            sent += n;
            // Queue until WANT_WRITE before draining the peer: guarantee backpressure.
            if (n > 0) continue;
        }
        c.ERR_clear_error();
        var n: usize = 0;
        const rc = c.SSL_read_ex(client, &buffer, buffer.len, &n);
        if (rc != 1) {
            const err = c.SSL_get_error(client, rc);
            try std.testing.expect(err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE);
        } else {
            for (buffer[0..n]) |byte| try std.testing.expectEqual(@as(u8, 'z'), byte);
            received += n;
        }
        if (received == payload.len) break;
    }
    try std.testing.expectEqual(payload.len, sent);
    try std.testing.expectEqual(payload.len, received);
    try std.testing.expect(retries > 0 and partials > 0);
    // Fill the transport without generating TLS records, then discard the filler
    // at the peer BIO. This isolates close_notify WANT_WRITE deterministically.
    var filler: [20000]u8 = @splat(0);
    try std.testing.expectEqual(@as(c_int, filler.len), c.BIO_write(server_bio, &filler, filler.len));
    try std.testing.expectError(error.WouldBlock, server.shutdown());
    try std.testing.expect(server.closing and server.want == .write);
    try std.testing.expectEqual(@as(c_int, filler.len), c.BIO_read(client_bio, &filler, filler.len));
    try std.testing.expect(try server.shutdown());
    c.ERR_clear_error();
    var closed_n: usize = 0;
    const closed_rc = c.SSL_read_ex(client, &buffer, buffer.len, &closed_n);
    try std.testing.expectEqual(@as(c_int, c.SSL_ERROR_ZERO_RETURN), c.SSL_get_error(client, closed_rc));
}

test "handshake permit release is idempotent on success and cleanup" {
    const std = @import("std");
    var admission: @import("admission.zig").Admission = .{ .limit = 1 };
    try std.testing.expect(admission.acquire());
    var session: Session = .{ .permit = &admission };
    session.finishHandshake();
    session.finishHandshake();
    session.deinit();
    try std.testing.expectEqual(@as(u16, 0), admission.active);
}

test "rejected handshakes allocate no SSL and cannot release another permit" {
    const std = @import("std");
    var admission: @import("admission.zig").Admission = .{ .limit = 1 };
    try std.testing.expect(admission.acquire());
    var generation: @import("context.zig").Generation = .{};
    try std.testing.expectError(error.TlsAdmissionRejected, Session.init(&generation, -1, &admission));
    try std.testing.expectEqual(@as(u16, 1), admission.active);
    try std.testing.expectEqual(@as(usize, 0), generation.references);
    admission.release();
    try std.testing.expect(admission.acquire());
    generation.retain();
    var session: Session = .{ .permit = &admission, .generation = &generation };
    session.deinit();
    session.deinit();
    try std.testing.expectEqual(@as(u16, 0), admission.active);
    try std.testing.expectEqual(@as(usize, 0), generation.references);
}
