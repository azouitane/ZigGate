const std = @import("std");
pub const Certificate = struct { hostname: []const u8, cert: []const u8, key: []const u8 };
pub const Config = struct {
    listen: ?std.net.Address = null,
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    handshake_ms: u16 = 5000,
    hosts: [8]Certificate = undefined,
    count: usize = 0,
    pub fn validate(self: Config) !void {
        if (self.listen == null and self.cert == null and self.key == null and self.count == 0) return;
        if (self.listen == null or self.cert == null or self.key == null) return error.IncompleteTlsConfiguration;
        if (self.cert.?.len == 0 or self.key.?.len == 0) return error.InvalidTlsPath;
    }
    pub fn add(self: *Config, text: []const u8) !void {
        if (self.count == self.hosts.len) return error.TooManyTlsHosts;
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse return error.InvalidTlsHost;
        const comma = std.mem.indexOfScalarPos(u8, text, eq + 1, ',') orelse return error.InvalidTlsHost;
        const host = text[0..eq];
        if (!hostname(host) or comma == eq + 1 or comma + 1 == text.len or std.mem.indexOfScalarPos(u8, text, comma + 1, ',') != null) return error.InvalidTlsHost;
        for (self.hosts[0..self.count]) |entry| if (std.ascii.eqlIgnoreCase(host, entry.hostname)) return error.DuplicateTlsHost;
        self.hosts[self.count] = .{ .hostname = host, .cert = text[eq + 1 .. comma], .key = text[comma + 1 ..] };
        self.count += 1;
    }
};
pub fn address(text: []const u8) !std.net.Address {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return error.InvalidTlsListen;
    const port = text[colon + 1 ..];
    if (port.len == 0) return error.InvalidTlsListen;
    for (port) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidTlsListen;
    const value = std.fmt.parseInt(u16, port, 10) catch return error.InvalidTlsListen;
    if (value == 0) return error.InvalidTlsListen;
    return std.net.Address.parseIp4(text[0..colon], value) catch error.InvalidTlsListen;
}
pub fn hostname(text: []const u8) bool {
    if (text.len == 0 or text.len > 253) return false;
    var labels = std.mem.splitScalar(u8, text, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    }
    return true;
}
test "TLS configuration is opt-in bounded and unambiguous" {
    var config: Config = .{};
    try config.validate();
    config.cert = "cert";
    try std.testing.expectError(error.IncompleteTlsConfiguration, config.validate());
    try config.add("example.test=cert,key");
    try std.testing.expectError(error.DuplicateTlsHost, config.add("EXAMPLE.TEST=cert,key"));
    for ([_][]const u8{ "*.test=c,k", "a..test=c,k", "-a.test=c,k", "a.test=,k" }) |bad| try std.testing.expectError(error.InvalidTlsHost, config.add(bad));
    try std.testing.expectError(error.InvalidTlsListen, address("127.0.0.1:0"));
}
