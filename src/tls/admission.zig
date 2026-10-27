const std = @import("std");
/// Event-loop owned. Session holds the sole permit until success or deinit.
pub const Admission = struct {
    limit: u16,
    active: u16 = 0,
    pub fn acquire(self: *Admission) bool {
        if (self.active >= self.limit) return false;
        self.active += 1;
        return true;
    }
    pub fn release(self: *Admission) void {
        std.debug.assert(self.active > 0);
        self.active -= 1;
    }
};
test "admission is bounded and permits can be reused" {
    var admission: Admission = .{ .limit = 2 };
    try std.testing.expect(admission.acquire());
    try std.testing.expect(admission.acquire());
    try std.testing.expect(!admission.acquire());
    admission.release();
    try std.testing.expect(admission.acquire());
    admission.release();
    admission.release();
    try std.testing.expectEqual(@as(u16, 0), admission.active);
}
