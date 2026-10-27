const std = @import("std");
pub const c = @cImport({
    @cInclude("shim.h");
});
pub const allocator = std.heap.page_allocator;
pub const Key = struct {
    ptr: *c.EVP_PKEY,
    pub fn generate() !Key {
        c.ERR_clear_error();
        return .{ .ptr = c.zg_acme_key_new() orelse return error.AcmeKeyGenerationFailed };
    }
    pub fn read(bytes: []const u8) !Key {
        return .{ .ptr = c.zg_acme_key_read(bytes.ptr, @intCast(bytes.len)) orelse return error.InvalidAcmeKey };
    }
    pub fn deinit(self: Key) void {
        c.EVP_PKEY_free(self.ptr);
        c.ERR_clear_error();
    }
    pub fn pem(self: Key) ![]u8 {
        var buffer: [4096]u8 = undefined;
        defer c.OPENSSL_cleanse(&buffer, buffer.len);
        const n = c.zg_acme_key_pem(self.ptr, &buffer, buffer.len);
        if (n <= 0) return error.AcmeKeyEncodingFailed;
        return allocator.dupe(u8, buffer[0..@intCast(n)]);
    }
    pub fn jwk(self: Key) ![]u8 {
        var buffer: [256]u8 = undefined;
        const n = c.zg_acme_jwk(self.ptr, &buffer, buffer.len);
        if (n <= 0) return error.AcmeJwkFailed;
        return allocator.dupe(u8, buffer[0..@intCast(n)]);
    }
    pub fn thumb(self: Key) ![]u8 {
        var buffer: [64]u8 = undefined;
        const n = c.zg_acme_thumb(self.ptr, &buffer, buffer.len);
        if (n <= 0) return error.AcmeThumbprintFailed;
        return allocator.dupe(u8, buffer[0..@intCast(n)]);
    }
    pub fn csr(self: Key, domains: []const []const u8) ![]u8 {
        var names = try Names.init(domains);
        defer names.deinit();
        var buffer: [16384]u8 = undefined;
        const n = c.zg_acme_csr(self.ptr, &names.pointers, @intCast(domains.len), &buffer, buffer.len);
        if (n <= 0) return error.AcmeCsrFailed;
        return allocator.dupe(u8, buffer[0..@intCast(n)]);
    }
};
pub fn secretFree(bytes: []u8) void {
    c.OPENSSL_cleanse(bytes.ptr, bytes.len);
    allocator.free(bytes);
}
pub const Names = struct {
    pointers: [8][*c]const u8 = @splat(null),
    strings: [8]?[:0]u8 = @splat(null),
    pub fn init(domains: []const []const u8) !Names {
        var names: Names = .{};
        errdefer names.deinit();
        for (domains, 0..) |domain, i| {
            names.strings[i] = try allocator.dupeZ(u8, domain);
            names.pointers[i] = names.strings[i].?.ptr;
        }
        return names;
    }
    pub fn deinit(self: *Names) void {
        for (self.strings) |s| if (s) |bytes| allocator.free(bytes);
    }
};
pub const Validity = struct { before: i64, after: i64 };
pub fn validate(chain: []const u8, key: Key, domains: []const []const u8, issuer: ?[]const u8) !Validity {
    return validateStored(chain, key, domains, issuer, false);
}
pub fn validateStored(chain: []const u8, key: Key, domains: []const []const u8, issuer: ?[]const u8, allow_expired: bool) !Validity {
    var names = try Names.init(domains);
    defer names.deinit();
    const ca = if (issuer) |path| try allocator.dupeZ(u8, path) else null;
    defer if (ca) |bytes| allocator.free(bytes);
    var result: Validity = undefined;
    if (c.zg_acme_validate(chain.ptr, @intCast(chain.len), key.ptr, &names.pointers, @intCast(domains.len), if (ca) |path| path.ptr else null, @intFromBool(allow_expired), &result.before, &result.after) != 1) return error.InvalidAcmeCertificate;
    return result;
}
pub fn random() !u64 {
    var number: u64 = 0;
    if (c.RAND_bytes(@ptrCast(&number), @sizeOf(u64)) != 1) return error.AcmeEntropyUnavailable;
    return number;
}
pub fn base64(bytes: []const u8) ![]u8 {
    const codec = std.base64.url_safe_no_pad.Encoder;
    const out = try allocator.alloc(u8, codec.calcSize(bytes.len));
    _ = codec.encode(out, bytes);
    return out;
}
pub fn json(value: anytype) ![]u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})});
}
pub fn parse(bytes: []const u8) !std.json.Parsed(std.json.Value) {
    if (bytes.len > 65536) return error.AcmeJsonTooLarge;
    var depth: usize = 0;
    var in_string = false;
    var escape = false;
    for (bytes) |byte| {
        if (in_string) {
            if (escape) {
                escape = false;
            } else if (byte == '\\') {
                escape = true;
            } else if (byte == '"') {
                in_string = false;
            }
        } else if (byte == '"') {
            in_string = true;
        } else if (byte == '{' or byte == '[') {
            depth += 1;
            if (depth > 32) return error.AcmeJsonTooDeep;
        } else if (byte == '}' or byte == ']') {
            if (depth == 0) return error.InvalidAcmeJson;
            depth -= 1;
        }
    }
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .duplicate_field_behavior = .@"error", .allocate = .alloc_always });
}
pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.UnexpectedAcmeResponse;
    return value.object.get(name) orelse error.UnexpectedAcmeResponse;
}
pub fn text(value: std.json.Value) ![]const u8 {
    if (value != .string) return error.UnexpectedAcmeResponse;
    return value.string;
}
pub fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    return text(try field(value, name));
}
pub fn Text(comptime capacity: usize) type {
    return struct {
        buffer: [capacity]u8 = undefined,
        length: usize = 0,
        pub fn set(self: *@This(), bytes: []const u8) !void {
            if (bytes.len > capacity) return error.AcmeValueTooLarge;
            @memcpy(self.buffer[0..bytes.len], bytes);
            self.length = bytes.len;
        }
        pub fn get(self: *const @This()) []const u8 {
            return self.buffer[0..self.length];
        }
    };
}
test "OpenSSL account encoding CSR and bounded JSON" {
    const key = try Key.generate();
    defer key.deinit();
    const pem = try key.pem();
    defer secretFree(pem);
    const other = try Key.read(pem);
    defer other.deinit();
    const jwk = try key.jwk();
    defer allocator.free(jwk);
    const thumb = try key.thumb();
    defer allocator.free(thumb);
    try std.testing.expectEqual(@as(usize, 43), thumb.len);
    const csr = try other.csr(&.{"example.com"});
    defer allocator.free(csr);
    try std.testing.expect(csr.len > 100);
    try std.testing.expectError(error.DuplicateField, parse("{\"a\":1,\"a\":2}"));
}

pub fn checkTrustFile(path: []const u8) !void {
    const fd = try std.posix.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true }, 0);
    const file: std.fs.File = .{ .handle = fd };
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size == 0 or stat.size > 1048576) return error.InvalidAcmeTrustFile;
    const bytes = try file.readToEndAlloc(allocator, 1048576);
    defer allocator.free(bytes);
    if (c.zg_acme_ca_pem(bytes.ptr, @intCast(bytes.len)) != 1) return error.InvalidAcmeTrustFile;
}
