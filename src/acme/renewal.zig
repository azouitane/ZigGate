const std = @import("std");
const crypto = @import("crypto.zig");
pub const State = struct {
    version: u8 = 1,
    slot: u2 = 0,
    has_certificate: bool = false,
    before: i64 = 0,
    after: i64 = 0,
    renew_at: i64 = 0,
    next_attempt: i64 = 0,
    failures: u8 = 0,
    ari_check: i64 = 0,
    directory: []const u8,
    domains: []const []const u8,
};
pub fn eligibility(before: i64, after: i64, randomness: u64) i64 {
    const lifetime = @max(@as(i64, 1), after - before);
    const jitter = @as(i64, @intCast(randomness % @as(u64, @intCast(@max(1, @divTrunc(lifetime, 20))))));
    return before + @divTrunc(lifetime * 2, 3) - jitter;
}
pub fn retry(failures: u8, randomness: u64, retry_after: i64) i64 {
    const delay: i64 = @min(86400, @as(i64, 60) << @as(u6, @intCast(@min(failures, 10))));
    return @max(retry_after, delay + @as(i64, @intCast(randomness % 30)));
}
test "renewal windows and retries never become a tight loop" {
    try std.testing.expectEqual(@as(i64, 600), eligibility(0, 900, 0));
    try std.testing.expect(eligibility(0, 900, 44) >= 555);
    try std.testing.expect(retry(0, 0, 0) >= 60);
    try std.testing.expectEqual(@as(i64, 100000), retry(10, 0, 100000));
}

/// A third disk slot keeps both the committed selector and currently served
/// bundle immutable, even if a stored candidate expires before TLS activation.
pub fn bundleSlot(current: ?u2, active: ?u2) u2 {
    for (0..3) |index| {
        const slot: u2 = @intCast(index);
        if (current != slot and active != slot) return slot;
    }
    unreachable;
}
test "new bundles never overwrite committed or currently served material" {
    for (0..3) |c| for (0..3) |v| {
        const current: u2 = @intCast(c);
        const active: u2 = @intCast(v);
        const next = bundleSlot(current, active);
        try std.testing.expect(next != current and next != active);
    };
}
