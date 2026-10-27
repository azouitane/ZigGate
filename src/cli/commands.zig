const std = @import("std");
const proxy = @import("../proxy/proxy_config.zig");
pub const usage = "Usage: ziggate [--bind IPv4] [--port 1..65535] [--timeout-ms 1..60000] [--idle-timeout-ms 1..60000] [--max-connections 1..32768] [--max-requests 1..65535] [--proxy /prefix/=IPv4:port] [--max-upstreams N] [--upstream-connect-ms N] [--upstream-read-ms N] [--upstream-write-ms N] [--proxy-total-ms N] [--upstream-header-bytes N] [--help]\n";
pub const Options = struct { bind: []const u8 = "127.0.0.1", port: u16 = 8080, timeout_ms: u16 = 2000, idle_timeout_ms: u16 = 5000, max_connections: u16 = 1024, max_requests: u16 = 100, proxy: proxy.Config = .{}, proxy_limits: proxy.Limits = .{}, help: bool = false };
pub fn parse(args: []const []const u8) !Options {
    var options: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help")) {
            options.help = true;
            continue;
        }
        i += 1;
        if (i >= args.len) return error.MissingValue;
        if (std.mem.eql(u8, arg, "--bind")) {
            options.bind = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            options.port = try std.fmt.parseInt(u16, args[i], 10);
            if (options.port == 0) return error.InvalidPort;
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            options.timeout_ms = try std.fmt.parseInt(u16, args[i], 10);
            if (options.timeout_ms == 0 or options.timeout_ms > 60000) return error.InvalidTimeout;
        } else if (std.mem.eql(u8, arg, "--idle-timeout-ms")) {
            options.idle_timeout_ms = try std.fmt.parseInt(u16, args[i], 10);
            if (options.idle_timeout_ms == 0 or options.idle_timeout_ms > 60000) return error.InvalidTimeout;
        } else if (std.mem.eql(u8, arg, "--max-connections")) {
            options.max_connections = try std.fmt.parseInt(u16, args[i], 10);
            if (options.max_connections == 0 or options.max_connections > 32768) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--max-requests")) {
            options.max_requests = try std.fmt.parseInt(u16, args[i], 10);
            if (options.max_requests == 0) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--proxy")) {
            try options.proxy.add(args[i]);
        } else if (std.mem.eql(u8, arg, "--max-upstreams")) {
            options.proxy_limits.max_active = try std.fmt.parseInt(u16, args[i], 10);
            if (options.proxy_limits.max_active == 0 or options.proxy_limits.max_active > 32768) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--upstream-header-bytes")) {
            options.proxy_limits.header_bytes = try std.fmt.parseInt(u16, args[i], 10);
            if (options.proxy_limits.header_bytes == 0 or options.proxy_limits.header_bytes > 8192) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--upstream-connect-ms") or std.mem.eql(u8, arg, "--upstream-read-ms") or std.mem.eql(u8, arg, "--upstream-write-ms") or std.mem.eql(u8, arg, "--proxy-total-ms")) {
            const value = try std.fmt.parseInt(u16, args[i], 10);
            if (value == 0 or value > 60000) return error.InvalidTimeout;
            if (std.mem.eql(u8, arg, "--upstream-connect-ms")) options.proxy_limits.connect_ms = value;
            if (std.mem.eql(u8, arg, "--upstream-read-ms")) options.proxy_limits.read_ms = value;
            if (std.mem.eql(u8, arg, "--upstream-write-ms")) options.proxy_limits.write_ms = value;
            if (std.mem.eql(u8, arg, "--proxy-total-ms")) options.proxy_limits.total_ms = value;
        } else return error.UnknownOption;
    }
    _ = try std.net.Address.parseIp4(options.bind, options.port);
    return options;
}
test "CLI defaults and validation" {
    try std.testing.expectEqual(@as(u16, 8080), (try parse(&.{})).port);
    try std.testing.expectError(error.InvalidPort, parse(&.{ "--port", "0" }));
    try std.testing.expectError(error.InvalidTimeout, parse(&.{ "--timeout-ms", "0" }));
    try std.testing.expectError(error.MissingValue, parse(&.{"--bind"}));
    try std.testing.expectError(error.UnknownOption, parse(&.{ "--bad", "x" }));
}

test "concurrency configuration is bounded" {
    const options = try parse(&.{ "--max-connections", "100", "--max-requests", "5", "--idle-timeout-ms", "300" });
    try std.testing.expectEqual(@as(u16, 100), options.max_connections);
    try std.testing.expectEqual(@as(u16, 5), options.max_requests);
    try std.testing.expectEqual(@as(u16, 300), options.idle_timeout_ms);
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--max-connections", "32769" }));
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--max-requests", "0" }));
    try std.testing.expectError(error.InvalidTimeout, parse(&.{ "--idle-timeout-ms", "0" }));
}

test "proxy CLI routes and resource limits" {
    const options = try parse(&.{ "--proxy", "/api/=127.0.0.1:8081", "--max-upstreams", "4", "--upstream-connect-ms", "100", "--upstream-read-ms", "200", "--upstream-write-ms", "300", "--proxy-total-ms", "500", "--upstream-header-bytes", "4096" });
    try std.testing.expectEqual(@as(usize, 1), options.proxy.count);
    try std.testing.expectEqual(@as(u16, 4), options.proxy_limits.max_active);
    try std.testing.expectEqual(@as(u16, 100), options.proxy_limits.connect_ms);
    try std.testing.expectEqual(@as(u16, 200), options.proxy_limits.read_ms);
    try std.testing.expectEqual(@as(u16, 300), options.proxy_limits.write_ms);
    try std.testing.expectEqual(@as(u16, 500), options.proxy_limits.total_ms);
    try std.testing.expectEqual(@as(u16, 4096), options.proxy_limits.header_bytes);
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--max-upstreams", "0" }));
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--upstream-header-bytes", "8193" }));
    try std.testing.expectError(error.InvalidTimeout, parse(&.{ "--upstream-read-ms", "0" }));
}
