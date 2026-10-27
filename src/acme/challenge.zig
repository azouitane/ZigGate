const std = @import("std");
pub const prefix = "/.well-known/acme-challenge/";
pub fn now() u64 {
    const time = std.posix.clock_gettime(std.posix.CLOCK.MONOTONIC) catch unreachable;
    return @as(u64, @intCast(time.sec)) * 1000 + @as(u64, @intCast(time.nsec)) / 1000000;
}
pub fn tokenValid(token: []const u8) bool {
    if (token.len < 22 or token.len > 128) return false;
    for (token) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    return true;
}
pub const Store = struct {
    mutex: std.Thread.Mutex = .{},
    entries: [8]Entry = @splat(.{}),
    const Entry = struct { token: [128]u8 = undefined, length: usize = 0, authorization: [192]u8 = undefined, auth_length: usize = 0, expires: u64 = 0 };
    pub fn put(self: *Store, token: []const u8, authorization: []const u8, expires: u64) !void {
        if (!tokenValid(token) or authorization.len > 192) return error.InvalidAcmeToken;
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| if (entry.length == 0 or entry.expires <= now() or std.mem.eql(u8, entry.token[0..entry.length], token)) {
            @memcpy(entry.token[0..token.len], token);
            @memcpy(entry.authorization[0..authorization.len], authorization);
            entry.length = token.len;
            entry.auth_length = authorization.len;
            entry.expires = expires;
            return;
        };
        return error.AcmeChallengeCapacity;
    }
    pub fn remove(self: *Store, token: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| if (entry.length != 0 and std.mem.eql(u8, entry.token[0..entry.length], token)) {
            entry.length = 0;
        };
    }
    pub fn clear(self: *Store) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| entry.length = 0;
    }
    pub fn lookup(self: *Store, token: []const u8, buffer: *[192]u8, instant: u64) ?[]const u8 {
        if (!tokenValid(token)) return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| if (entry.length != 0 and entry.expires > instant and std.mem.eql(u8, entry.token[0..entry.length], token)) {
            @memcpy(buffer[0..entry.auth_length], entry.authorization[0..entry.auth_length]);
            return buffer[0..entry.auth_length];
        };
        return null;
    }
};
test "bounded HTTP-01 lookup expires and never reads files" {
    var store: Store = .{};
    const token = "abcdefghijklmnopqrstuvwxyz012345";
    try store.put(token, "expected.authorization", now() + 5000);
    var buffer: [192]u8 = undefined;
    try std.testing.expectEqualStrings("expected.authorization", store.lookup(token, &buffer, now()).?);
    try std.testing.expect(store.lookup(token, &buffer, now() + 6000) == null);
    try std.testing.expect(store.lookup("../account.key", &buffer, now()) == null);
    store.clear();
    try std.testing.expect(store.lookup(token, &buffer, now()) == null);
}
