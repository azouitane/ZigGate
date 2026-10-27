const std = @import("std");
const p = std.posix;
pub const Level = enum { debug, info, warn, err };
/// Only static event names and numeric fields enter the logger. No request headers,
/// targets, query strings or upstream credentials are retained.
pub const Logger = struct {
    fd: i32 = -1,
    level: Level = .info,
    dropped: u64 = 0,
    pub fn init(level: Level) Logger {
        // Reopen rather than dup: O_NONBLOCK must not change the caller's stderr flags.
        const fd = p.open("/proc/self/fd/2", .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true }, 0) catch -1;
        if (fd != -1) {
            const st = p.fstat(fd) catch {
                p.close(fd);
                return .{ .level = level };
            };
            // Regular files can block on storage despite O_NONBLOCK. Disable that sink.
            if (!p.S.ISFIFO(st.mode)) {
                p.close(fd);
                return .{ .level = level };
            }
        }
        return .{ .fd = fd, .level = level };
    }
    pub fn deinit(self: *Logger) void {
        if (self.fd != -1) p.close(self.fd);
    }
    pub fn event(self: *Logger, level: Level, comptime name: []const u8, fields: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.level)) return;
        var buffer: [2048]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{{\"timestamp_unix_ms\":{d},\"level\":\"{s}\",\"event\":\"{s}\",\"data\":{f}}}\n", .{ std.time.milliTimestamp(), if (level == .err) "error" else @tagName(level), name, std.json.fmt(fields, .{}) }) catch {
            self.dropped +|= 1;
            return;
        };
        if (self.fd == -1) {
            self.dropped +|= 1;
            return;
        }
        // <= PIPE_BUF: pipe writes are atomic, or fail EAGAIN. No queued allocation.
        const n = p.write(self.fd, line) catch {
            self.dropped +|= 1;
            return;
        };
        if (n != line.len) self.dropped +|= 1;
    }
};

test "JSON escaping and bounded nonblocking pipe output" {
    const fds = try p.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer p.close(fds[0]);
    var logger: Logger = .{ .fd = fds[1], .level = .debug };
    defer logger.deinit();
    logger.event(.info, "test", .{ .value = "quote\" newline\n control\x01" });
    var buffer: [2048]u8 = undefined;
    const n = try p.read(fds[0], &buffer);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buffer[0..n], .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("quote\" newline\n control\x01", parsed.value.object.get("data").?.object.get("value").?.string);
    for (0..10000) |_| logger.event(.info, "fill", .{});
    try std.testing.expect(logger.dropped > 0);
}
