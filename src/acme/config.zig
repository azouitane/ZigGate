const std = @import("std");
pub const staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const production = "https://acme-v02.api.letsencrypt.org/directory";
pub const Config = struct {
    enabled: bool = false,
    agree: bool = false,
    environment: enum { unset, staging, production, local } = .unset,
    directory: []const u8 = "",
    email: []const u8 = "",
    storage: []const u8 = "",
    ca_file: ?[]const u8 = null,
    issuer_ca: ?[]const u8 = null,
    domains: [8][]const u8 = undefined,
    count: usize = 0,
    pub fn add(self: *Config, name: []const u8) !void {
        if (self.count == self.domains.len or !domain(name)) return error.InvalidAcmeDomain;
        for (self.domains[0..self.count]) |other| if (std.ascii.eqlIgnoreCase(other, name)) return error.DuplicateAcmeDomain;
        self.domains[self.count] = name;
        self.count += 1;
    }
    pub fn validate(self: *Config) !void {
        if (!self.enabled) {
            if (self.count != 0 or self.storage.len != 0 or self.email.len != 0 or self.environment != .unset or self.agree or self.ca_file != null or self.issuer_ca != null) return error.AcmeRequiresExplicitEnable;
            return;
        }
        if (!self.agree or self.count == 0 or self.environment == .unset or self.email.len == 0) return error.IncompleteAcmeConfiguration;
        if (self.storage.len < 2 or self.storage.len > 1024 or self.storage[0] != '/') return error.InvalidAcmeStorage;
        var parts = std.mem.splitScalar(u8, self.storage[1..], '/');
        while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidAcmeStorage;
        if (self.email.len > 254 or std.mem.indexOfScalar(u8, self.email, '@') == null) return error.InvalidAcmeEmail;
        const at = std.mem.indexOfScalar(u8, self.email, '@').?;
        if (at == 0 or at + 1 == self.email.len or std.mem.indexOfScalarPos(u8, self.email, at + 1, '@') != null) return error.InvalidAcmeEmail;
        for (self.email) |byte| if (byte <= 0x20 or byte >= 0x7f or byte == '"' or byte == '\\' or byte == ':') return error.InvalidAcmeEmail;
        switch (self.environment) {
            .staging => self.directory = staging,
            .production => self.directory = production,
            .local => {
                if (!std.mem.startsWith(u8, self.directory, "https://127.0.0.1:")) return error.InvalidAcmeDirectory;
                const authority_end = std.mem.indexOfScalarPos(u8, self.directory, 8, '/') orelse return error.InvalidAcmeDirectory;
                const port_text = self.directory[18..authority_end];
                if (port_text.len == 0) return error.InvalidAcmeDirectory;
                for (port_text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidAcmeDirectory;
                const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidAcmeDirectory;
                if (port == 0) return error.InvalidAcmeDirectory;
                if (self.ca_file == null or self.issuer_ca == null) return error.AcmeLocalTrustRequired;
            },
            .unset => unreachable,
        }
        _ = try origin(self.directory);
    }
};
pub fn domain(name: []const u8) bool {
    if (!@import("../tls/config.zig").hostname(name) or std.mem.indexOfScalar(u8, name, '.') == null) return false;
    for (name) |byte| if (std.ascii.isUpper(byte)) return false;
    if (std.net.Address.parseIp4(name, 0)) |_| return false else |_| {}
    return true;
}
pub fn origin(url: []const u8) ![]const u8 {
    if (url.len > 2048 or !std.mem.startsWith(u8, url, "https://")) return error.InvalidAcmeUrl;
    for (url) |byte| if (byte <= 0x20 or byte >= 0x7f or byte == '\\' or byte == '#' or byte == '@') return error.InvalidAcmeUrl;
    const end = std.mem.indexOfScalarPos(u8, url, 8, '/') orelse return error.InvalidAcmeUrl;
    if (end == 8 or std.mem.indexOfScalar(u8, url[8..end], '?') != null or std.mem.indexOfScalar(u8, url[8..end], '%') != null) return error.InvalidAcmeUrl;
    return url[0..end];
}
pub fn endpoint(directory: []const u8, url: []const u8) !void {
    if (!std.mem.eql(u8, try origin(directory), try origin(url))) return error.CrossOriginAcmeUrl;
}
test "ACME opt-in domains and endpoint origin boundaries" {
    for ([_][]const u8{ "localhost", "*.example.com", "Example.com", "127.0.0.1", "a..com", "a.com/evil" }) |bad| try std.testing.expect(!domain(bad));
    try std.testing.expect(domain("example.com"));
    try endpoint(staging, "https://acme-staging-v02.api.letsencrypt.org/acme/1");
    try std.testing.expectError(error.CrossOriginAcmeUrl, endpoint(staging, "https://attacker.test/acme/1"));
    try std.testing.expectError(error.InvalidAcmeUrl, origin("https://name@attacker.test/path"));
    var config: Config = .{};
    try config.add("example.com");
    try std.testing.expectError(error.AcmeRequiresExplicitEnable, config.validate());
}
