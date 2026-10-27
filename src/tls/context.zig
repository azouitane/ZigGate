const std = @import("std");
pub const c = @cImport({
    @cInclude("openssl_shim.h");
});
const Config = @import("config.zig").Config;
pub const Generation = struct {
    references: usize = 0,
    retired: bool = false,
    default: ?*c.SSL_CTX = null,
    hosts: [8]?*c.SSL_CTX = @splat(null),
    config: Config = .{},
    /// Must be initialized at its final address: callback arguments borrow self.
    pub fn init(self: *Generation, config: Config) !void {
        self.* = .{ .config = config };
        errdefer self.deinit();
        if (config.listen == null) return;
        if (config.cert == null or config.key == null) return error.TlsCertificateUnavailable;
        self.default = try load(config.cert.?, config.key.?);
        for (config.hosts[0..config.count], 0..) |entry, i| self.hosts[i] = try load(entry.cert, entry.key);
        c.zg_tls_sni(self.default, sni, self);
    }
    pub fn retain(self: *Generation) void {
        self.references += 1;
    }
    pub fn release(self: *Generation) void {
        std.debug.assert(self.references > 0);
        self.references -= 1;
        if (self.references == 0 and self.retired) self.deinit();
    }
    pub fn deinit(self: *Generation) void {
        std.debug.assert(self.references == 0);
        for (&self.hosts) |*ctx| {
            if (ctx.*) |ptr| c.SSL_CTX_free(ptr);
            ctx.* = null;
        }
        if (self.default) |ctx| c.SSL_CTX_free(ctx);
        self.default = null;
        c.ERR_clear_error();
    }
    fn load(cert: []const u8, key: []const u8) !*c.SSL_CTX {
        c.ERR_clear_error();
        defer c.ERR_clear_error();
        if (c.OpenSSL_version_num() < 0x30000000) return error.OpenSsl3Required;
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsContextCreationFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (c.zg_tls_policy(ctx) != 1) return error.TlsPolicyFailed;
        const cert_bytes = try readPem(cert, 1024 * 1024);
        defer std.heap.page_allocator.free(cert_bytes);
        const key_bytes = try readPem(key, 64 * 1024);
        defer std.heap.page_allocator.free(key_bytes);
        if (c.zg_tls_certificate_pem(ctx, cert_bytes.ptr, @intCast(cert_bytes.len)) != 1) return error.TlsCertificateLoadFailed;
        if (c.zg_tls_key_pem(ctx, key_bytes.ptr, @intCast(key_bytes.len)) != 1) return error.TlsPrivateKeyLoadFailed;
        if (c.SSL_CTX_check_private_key(ctx) != 1) return error.TlsCertificateKeyMismatch;
        return ctx;
    }
    fn readPem(path: []const u8, limit: usize) ![]u8 {
        // NONBLOCK rejects FIFO/device paths without waiting. fstat checks the opened
        // object, not an earlier path lookup; replacement symlinks are supported.
        const fd = try std.posix.open(path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true, .NOCTTY = true }, 0);
        const file: std.fs.File = .{ .handle = fd };
        defer file.close();
        const stat = try file.stat();
        if (stat.kind != .file or stat.size == 0 or stat.size > limit) return error.InvalidTlsPemFile;
        return file.readToEndAlloc(std.heap.page_allocator, limit);
    }
    fn sni(ssl: ?*c.SSL, alert: [*c]c_int, arg: ?*anyopaque) callconv(.c) c_int {
        const self: *Generation = @ptrCast(@alignCast(arg.?));
        const name = c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name);
        if (name == null) return c.SSL_TLSEXT_ERR_OK;
        const text = std.mem.span(name);
        if (!@import("config.zig").hostname(text)) {
            alert.* = c.SSL_AD_UNRECOGNIZED_NAME;
            return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        for (self.config.hosts[0..self.config.count], 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(text, entry.hostname)) {
                if (c.SSL_set_SSL_CTX(ssl, self.hosts[i]) == null) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
                return c.SSL_TLSEXT_ERR_OK;
            }
        }
        return c.SSL_TLSEXT_ERR_OK;
    }
};

/// Two stable callback registries: active and retired/candidate. No generation
/// allocation or unbounded history, and failed preparation never changes active.
pub const Contexts = struct {
    generations: [2]Generation = .{ .{}, .{} },
    current: u1 = 0,
    config: Config = .{},
    pub fn init(self: *Contexts, config: Config) !void {
        self.* = .{ .config = config };
        try self.generations[0].init(config);
    }
    pub fn active(self: *Contexts) *Generation {
        return &self.generations[self.current];
    }
    pub fn reload(self: *Contexts) !void {
        return self.reloadWith(self.config);
    }
    pub fn reloadWith(self: *Contexts, config: Config) !void {
        if (config.listen == null) return error.TlsNotEnabled;
        const next = self.current ^ 1;
        const candidate = &self.generations[next];
        if (candidate.references != 0) return error.TlsReloadBusy;
        candidate.deinit();
        try candidate.init(config);
        const previous = self.active();
        self.current = next;
        self.config = config;
        previous.retired = true;
        if (previous.references == 0) previous.deinit();
    }
    pub fn deinit(self: *Contexts) void {
        for (&self.generations) |*generation| generation.deinit();
    }
};
test "retired generation ownership and repeated release cleanup" {
    var generation: Generation = .{};
    generation.retain();
    generation.retired = true;
    generation.release();
    generation.deinit();
    try std.testing.expectEqual(@as(usize, 0), generation.references);
}
