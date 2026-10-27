const std = @import("std");
pub const c = @cImport({
    @cInclude("openssl_shim.h");
});
const Config = @import("config.zig").Config;
pub const Contexts = struct {
    default: ?*c.SSL_CTX = null,
    hosts: [8]?*c.SSL_CTX = @splat(null),
    config: Config = .{},
    /// Must be initialized at its final address: callback arguments borrow self.
    pub fn init(self: *Contexts, config: Config) !void {
        self.* = .{ .config = config };
        errdefer self.deinit();
        if (config.listen == null) return;
        self.default = try load(config.cert.?, config.key.?);
        for (config.hosts[0..config.count], 0..) |entry, i| self.hosts[i] = try load(entry.cert, entry.key);
        c.zg_tls_sni(self.default, sni, self);
    }
    pub fn deinit(self: *Contexts) void {
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
        const cert_z = try std.heap.page_allocator.dupeZ(u8, cert);
        defer std.heap.page_allocator.free(cert_z);
        const key_z = try std.heap.page_allocator.dupeZ(u8, key);
        defer std.heap.page_allocator.free(key_z);
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_z) != 1) return error.TlsCertificateLoadFailed;
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z, c.SSL_FILETYPE_PEM) != 1) return error.TlsPrivateKeyLoadFailed;
        if (c.SSL_CTX_check_private_key(ctx) != 1) return error.TlsCertificateKeyMismatch;
        return ctx;
    }
    fn sni(ssl: ?*c.SSL, alert: [*c]c_int, arg: ?*anyopaque) callconv(.c) c_int {
        const self: *Contexts = @ptrCast(@alignCast(arg.?));
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
