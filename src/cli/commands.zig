const std = @import("std");
const proxy = @import("../proxy/proxy_config.zig");
pub const usage = "Usage: ziggate [--bind IPv4] [--port 1..65535] [--timeout-ms 1..60000] [--idle-timeout-ms 1..60000] [--max-connections 1..32768] [--max-requests 1..65535] [--proxy /prefix/=IPv4:port] [--max-upstreams N] [--upstream-connect-ms N] [--upstream-read-ms N] [--upstream-write-ms N] [--proxy-total-ms N] [--upstream-header-bytes N] [--request-ms 1..60000] [--pending-output-bytes 1024..16384] [--header-bytes 1..8192] [--shutdown-ms 1..60000] [--log-level debug|info|warn|error] [--check-config] [--tls-listen IPv4:port --tls-cert PEM --tls-key PEM] [--tls-sni hostname=cert,key] [--tls-handshake-ms 1..60000] [--max-tls-handshakes 1..32768] [--help]\n";
pub const Options = struct { bind: []const u8 = "127.0.0.1", port: u16 = 8080, timeout_ms: u16 = 2000, idle_timeout_ms: u16 = 5000, max_connections: u16 = 1024, max_requests: u16 = 100, proxy: proxy.Config = .{}, proxy_limits: proxy.Limits = .{}, check_config: bool = false, shutdown_ms: u16 = 10000, request_ms: u16 = 60000, header_bytes: u16 = 8192, log_level: @import("../observability/logger.zig").Level = .info, tls: @import("../tls/config.zig").Config = .{}, help: bool = false };
fn decimal(comptime T: type, text: []const u8) !T {
    if (text.len == 0) return error.InvalidNumber;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidNumber;
    return std.fmt.parseInt(T, text, 10);
}
pub fn parse(args: []const []const u8) !Options {
    var options: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help")) {
            options.help = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--check-config")) {
            options.check_config = true;
            continue;
        }
        i += 1;
        if (i >= args.len) return error.MissingValue;
        if (std.mem.eql(u8, arg, "--bind")) {
            options.bind = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            options.port = try decimal(u16, args[i]);
            if (options.port == 0) return error.InvalidPort;
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            options.timeout_ms = try decimal(u16, args[i]);
            if (options.timeout_ms == 0 or options.timeout_ms > 60000) return error.InvalidTimeout;
        } else if (std.mem.eql(u8, arg, "--idle-timeout-ms")) {
            options.idle_timeout_ms = try decimal(u16, args[i]);
            if (options.idle_timeout_ms == 0 or options.idle_timeout_ms > 60000) return error.InvalidTimeout;
        } else if (std.mem.eql(u8, arg, "--max-connections")) {
            options.max_connections = try decimal(u16, args[i]);
            if (options.max_connections == 0 or options.max_connections > 32768) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--max-requests")) {
            options.max_requests = try decimal(u16, args[i]);
            if (options.max_requests == 0) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--proxy")) {
            try options.proxy.add(args[i]);
        } else if (std.mem.eql(u8, arg, "--max-upstreams")) {
            options.proxy_limits.max_active = try decimal(u16, args[i]);
            if (options.proxy_limits.max_active == 0 or options.proxy_limits.max_active > 32768) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--upstream-header-bytes")) {
            options.proxy_limits.header_bytes = try decimal(u16, args[i]);
            if (options.proxy_limits.header_bytes == 0 or options.proxy_limits.header_bytes > 8192) return error.InvalidLimit;
        } else if (std.mem.eql(u8, arg, "--upstream-connect-ms") or std.mem.eql(u8, arg, "--upstream-read-ms") or std.mem.eql(u8, arg, "--upstream-write-ms") or std.mem.eql(u8, arg, "--proxy-total-ms")) {
            const value = try decimal(u16, args[i]);
            if (value == 0 or value > 60000) return error.InvalidTimeout;
            if (std.mem.eql(u8, arg, "--upstream-connect-ms")) options.proxy_limits.connect_ms = value;
            if (std.mem.eql(u8, arg, "--upstream-read-ms")) options.proxy_limits.read_ms = value;
            if (std.mem.eql(u8, arg, "--upstream-write-ms")) options.proxy_limits.write_ms = value;
            if (std.mem.eql(u8, arg, "--proxy-total-ms")) options.proxy_limits.total_ms = value;
        } else if (std.mem.eql(u8, arg, "--shutdown-ms") or std.mem.eql(u8, arg, "--header-bytes")) {
            const value = try decimal(u16, args[i]);
            if (value == 0 or value > (if (std.mem.eql(u8, arg, "--header-bytes")) @as(u16, 8192) else @as(u16, 60000))) return error.InvalidLimit;
            if (std.mem.eql(u8, arg, "--header-bytes")) options.header_bytes = value else options.shutdown_ms = value;
        } else if (std.mem.eql(u8, arg, "--pending-output-bytes")) {
            const value = try decimal(u16, args[i]);
            if (value < 1024 or value > 16384) return error.InvalidLimit;
            options.proxy_limits.pending_bytes = value;
        } else if (std.mem.eql(u8, arg, "--request-ms")) {
            const value = try decimal(u16, args[i]);
            if (value == 0 or value > 60000) return error.InvalidTimeout;
            options.request_ms = value;
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            options.log_level = std.meta.stringToEnum(@import("../observability/logger.zig").Level, if (std.mem.eql(u8, args[i], "error")) "err" else args[i]) orelse return error.InvalidLogLevel;
        } else if (std.mem.eql(u8, arg, "--tls-listen")) {
            options.tls.listen = try @import("../tls/config.zig").address(args[i]);
        } else if (std.mem.eql(u8, arg, "--tls-cert")) {
            options.tls.cert = args[i];
        } else if (std.mem.eql(u8, arg, "--tls-key")) {
            options.tls.key = args[i];
        } else if (std.mem.eql(u8, arg, "--tls-sni")) {
            try options.tls.add(args[i]);
        } else if (std.mem.eql(u8, arg, "--max-tls-handshakes")) {
            const value = try decimal(u16, args[i]);
            if (value == 0 or value > 32768) return error.InvalidLimit;
            options.tls.max_handshakes = value;
        } else if (std.mem.eql(u8, arg, "--tls-handshake-ms") or std.mem.eql(u8, arg, "--tls-handshake-timeout-ms")) {
            const value = try decimal(u16, args[i]);
            if (value == 0 or value > 60000) return error.InvalidTimeout;
            options.tls.handshake_ms = value;
        } else return error.UnknownOption;
    }
    const http_address = try std.net.Address.parseIp4(options.bind, options.port);
    if (options.tls.listen) |tls_address| {
        if (tls_address.getPort() == options.port and (http_address.in.sa.addr == 0 or tls_address.in.sa.addr == 0 or http_address.in.sa.addr == tls_address.in.sa.addr)) return error.ConflictingListeners;
    }
    try options.tls.validate();
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

test "hardening CLI bounds and validation-only mode" {
    const options = try parse(&.{ "--check-config", "--shutdown-ms", "300", "--request-ms", "1000", "--header-bytes", "512", "--pending-output-bytes", "1024", "--log-level", "error" });
    try std.testing.expect(options.check_config);
    try std.testing.expectEqual(@as(u16, 300), options.shutdown_ms);
    try std.testing.expectEqual(@as(u16, 512), options.header_bytes);
    try std.testing.expectEqual(@as(u16, 1024), options.proxy_limits.pending_bytes);
    try std.testing.expectEqual(.err, options.log_level);
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--header-bytes", "8193" }));
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--pending-output-bytes", "16385" }));
    try std.testing.expectError(error.InvalidTimeout, parse(&.{ "--request-ms", "0" }));
}

test "TLS CLI rejects incomplete or overlapping listener configuration" {
    try std.testing.expectError(error.IncompleteTlsConfiguration, parse(&.{ "--tls-cert", "cert" }));
    try std.testing.expectError(error.ConflictingListeners, parse(&.{ "--tls-listen", "127.0.0.1:8080", "--tls-cert", "cert", "--tls-key", "key" }));
    const options = try parse(&.{ "--tls-listen", "127.0.0.1:8443", "--tls-cert", "cert", "--tls-key", "key", "--tls-handshake-ms", "1000" });
    try std.testing.expectEqual(@as(u16, 1000), options.tls.handshake_ms);
}

test "TLS admission bounds preserve handshake timeout option compatibility" {
    const options = try parse(&.{ "--max-tls-handshakes", "7", "--tls-handshake-timeout-ms", "900" });
    try std.testing.expectEqual(@as(u16, 7), options.tls.max_handshakes);
    try std.testing.expectEqual(@as(u16, 900), options.tls.handshake_ms);
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--max-tls-handshakes", "0" }));
    try std.testing.expectError(error.InvalidLimit, parse(&.{ "--max-tls-handshakes", "32769" }));
}
