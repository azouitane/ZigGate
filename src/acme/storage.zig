const std = @import("std");
const p = std.posix;
pub const Storage = struct {
    dir: std.fs.Dir,
    lock: i32,
    pub fn open(path: []const u8) !Storage {
        var fd = try p.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        errdefer p.close(fd);
        var segments = std.mem.splitScalar(u8, path[1..], '/');
        while (segments.next()) |segment| {
            if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.UnsafeAcmeStorage;
            const next = p.openat(fd, segment, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch |err| blk: {
                if (err != error.FileNotFound) return err;
                try p.mkdirat(fd, segment, 0o700);
                break :blk try p.openat(fd, segment, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
            };
            p.close(fd);
            fd = next;
        }
        const stat = try p.fstat(fd);
        if (stat.uid != p.geteuid() or stat.mode & 0o777 != 0o700) return error.UnsafeAcmeStorage;
        const lock = try p.openat(fd, "lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, 0o600);
        errdefer p.close(lock);
        try checkFile(lock);
        try p.flock(lock, p.LOCK.EX | p.LOCK.NB);
        return .{ .dir = .{ .fd = fd }, .lock = lock };
    }
    pub fn deinit(self: *Storage) void {
        p.close(self.lock);
        self.dir.close();
    }
    fn checkFile(fd: i32) !void {
        const stat = try p.fstat(fd);
        if (!p.S.ISREG(stat.mode) or stat.uid != p.geteuid() or stat.mode & 0o077 != 0 or stat.nlink != 1) return error.UnsafeAcmeStorage;
    }
    pub fn read(self: *Storage, name: []const u8, max: usize) !?[]u8 {
        if (std.mem.indexOfScalar(u8, name, '/') != null or std.mem.eql(u8, name, "..")) return error.UnsafeAcmeStorage;
        const fd = p.openat(self.dir.fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, 0) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        const file: std.fs.File = .{ .handle = fd };
        defer file.close();
        try checkFile(fd);
        return try file.readToEndAlloc(std.heap.page_allocator, max);
    }
    pub fn write(self: *Storage, name: []const u8, bytes: []const u8) !void {
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null or std.mem.eql(u8, name, "..") or std.mem.eql(u8, name, ".temporary")) return error.UnsafeAcmeStorage;
        // A fixed private temporary name is safe under our exclusive directory lock.
        // Existing symlinks/hardlinks are never followed or overwritten in place.
        self.dir.deleteFile(".temporary") catch |err| {
            if (err != error.FileNotFound) return err;
        };
        const fd = try p.openat(self.dir.fd, ".temporary", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        const file: std.fs.File = .{ .handle = fd };
        defer file.close();
        errdefer self.dir.deleteFile(".temporary") catch {};
        try file.writeAll(bytes);
        try p.fsync(fd);
        // Validate any existing destination before replacing it, including hardlinks.
        if (p.openat(self.dir.fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, 0)) |old| {
            defer p.close(old);
            try checkFile(old);
        } else |err| {
            if (err != error.FileNotFound) return err;
        }
        try p.renameat(self.dir.fd, ".temporary", self.dir.fd, name);
        try p.fsync(self.dir.fd);
    }
    pub fn readBundle(self: *Storage, slot: u2, name: []const u8, max: usize) ![]u8 {
        const directory = try self.openBundle(slot);
        defer p.close(directory);
        var child: Storage = .{ .dir = .{ .fd = directory }, .lock = -1 };
        return (try child.read(name, max)) orelse error.IncompleteAcmeBundle;
    }
    fn openBundle(self: *Storage, slot: u2) !i32 {
        const fd = try p.openat(self.dir.fd, switch (slot) {
            0 => "bundle0",
            1 => "bundle1",
            2 => "bundle2",
            else => return error.InvalidAcmeBundle,
        }, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        errdefer p.close(fd);
        const stat = try p.fstat(fd);
        if (stat.uid != p.geteuid() or stat.mode & 0o777 != 0o700) return error.UnsafeAcmeStorage;
        return fd;
    }
    pub fn bundle(self: *Storage, slot: u2, key: []const u8, chain: []const u8) !void {
        const name = switch (slot) {
            0 => "bundle0",
            1 => "bundle1",
            2 => "bundle2",
            else => return error.InvalidAcmeBundle,
        };
        if (self.openBundle(slot)) |old| {
            p.close(old);
        } else |err| {
            if (err != error.FileNotFound) return err;
        }
        // Only an inactive slot is passed here; the current bundle remains intact.
        self.dir.deleteTree(name) catch |err| {
            if (err != error.FileNotFound) return err;
        };
        try self.dir.makeDir(name);
        const fd = try p.openat(self.dir.fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer p.close(fd);
        try p.fchmod(fd, 0o700);
        var temporary: Storage = .{ .dir = .{ .fd = fd }, .lock = -1 };
        try temporary.write("key.pem", key);
        try temporary.write("chain.pem", chain);
        try p.fsync(fd);
        try p.fsync(self.dir.fd);
    }
};
test "storage permissions atomic replacement and symlink rejection" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    const readable = try p.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    defer p.close(readable);
    try p.fchmod(readable, 0o700);
    var store = try Storage.open(path);
    defer store.deinit();
    try store.write("state.json", "first");
    try store.write("state.json", "second");
    const bytes = (try store.read("state.json", 100)).?;
    defer std.heap.page_allocator.free(bytes);
    try std.testing.expectEqualStrings("second", bytes);
    try store.dir.symLink("state.json", "link", .{});
    try std.testing.expectError(error.SymLinkLoop, store.read("link", 100));
}
