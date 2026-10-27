const std = @import("std");
const Request = @import("request.zig").Request;
const response = @import("response.zig");
pub fn route(request: Request) response.Response {
    if (!std.mem.eql(u8, request.method, "GET")) return response.failure(405);
    const end = std.mem.indexOfScalar(u8, request.target, '?') orelse request.target.len;
    const path = request.target[0..end];
    if (std.mem.eql(u8, path, "/")) return .{ .status = 200, .body = "Welcome to ZigGate!\n" };
    if (std.mem.eql(u8, path, "/health")) return .{ .status = 200, .body = "ok\n" };
    if (std.mem.eql(u8, path, "/ready")) return .{ .status = 200, .body = "ready\n" };
    return response.failure(404);
}
test "exact routes and method restriction" {
    for ([_][]const u8{ "/", "/health", "/ready", "/health?q=1" }) |path| try std.testing.expectEqual(@as(u16, 200), route(.{ .method = "GET", .target = path }).status);
    try std.testing.expectEqual(@as(u16, 404), route(.{ .method = "GET", .target = "/health/" }).status);
    try std.testing.expectEqual(@as(u16, 405), route(.{ .method = "POST", .target = "/" }).status);
}
