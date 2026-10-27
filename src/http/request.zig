pub const Request = struct {
    // All slices borrow the connection's header buffer and expire after routing.
    method: []const u8,
    target: []const u8,
    close: bool = false,
};
