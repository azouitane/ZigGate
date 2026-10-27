const std = @import("std");
const p = std.posix;
/// Signals stay blocked while the descriptor and all event-loop resources are owned.
pub const Shutdown = struct {
    fd: i32,
    previous: p.sigset_t,
    state: enum { running, draining, forced } = .running,
    deadline: u64 = 0,
    pub fn init() !Shutdown {
        var mask = p.sigemptyset();
        p.sigaddset(&mask, p.SIG.INT);
        p.sigaddset(&mask, p.SIG.TERM);
        p.sigaddset(&mask, p.SIG.HUP);
        var previous: p.sigset_t = undefined;
        p.sigprocmask(p.SIG.BLOCK, &mask, &previous);
        errdefer p.sigprocmask(p.SIG.SETMASK, &previous, null);
        return .{ .fd = try p.signalfd(-1, &mask, std.os.linux.SFD.NONBLOCK | std.os.linux.SFD.CLOEXEC), .previous = previous };
    }
    pub fn deinit(self: *Shutdown) void {
        p.close(self.fd);
        // This executable exits after a requested shutdown. Keep these signals
        // blocked through final context cleanup: pending HUP/TERM must not turn
        // an orderly return into default-signal termination during teardown.
        if (self.state == .running) p.sigprocmask(p.SIG.SETMASK, &self.previous, null);
    }
    pub fn signal(self: *Shutdown, now: u64, grace: u16) void {
        if (self.state == .running) {
            self.state = .draining;
            self.deadline = now + grace;
        } else self.state = .forced;
    }
};
test "second termination forces shutdown and grace is absolute" {
    var s: Shutdown = .{ .fd = -1, .previous = undefined };
    s.signal(100, 500);
    try std.testing.expectEqual(@as(u64, 600), s.deadline);
    s.signal(101, 500);
    try std.testing.expectEqual(.forced, s.state);
}
