//! RFC 9773 renewal windows; all URLs retain the directory origin restriction.
const std = @import("std");
const crypto = @import("crypto.zig");
const Client = @import("client.zig").Client;
pub fn id(chain: []const u8) ![]u8 {
    var buffer: [512]u8 = undefined;
    const n = crypto.c.zg_acme_cert_id(chain.ptr, @intCast(chain.len), &buffer, buffer.len);
    if (n <= 0) return error.AcmeAriIdentifierUnavailable;
    return crypto.allocator.dupe(u8, buffer[0..@intCast(n)]);
}
fn timestamp(text: []const u8) !i64 {
    // RFC 3339 date/time with numeric offsets, optional fraction and strict ranges.
    if (text.len < 20 or text[4] != '-' or text[7] != '-' or (text[10] != 'T' and text[10] != 't') or text[13] != ':' or text[16] != ':') return error.InvalidAcmeAriTimestamp;
    for ([_][]const u8{ text[0..4], text[5..7], text[8..10], text[11..13], text[14..16], text[17..19] }) |part| for (part) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidAcmeAriTimestamp;
    const year = std.fmt.parseInt(u16, text[0..4], 10) catch return error.InvalidAcmeAriTimestamp;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return error.InvalidAcmeAriTimestamp;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return error.InvalidAcmeAriTimestamp;
    const hour = std.fmt.parseInt(u8, text[11..13], 10) catch return error.InvalidAcmeAriTimestamp;
    const minute = std.fmt.parseInt(u8, text[14..16], 10) catch return error.InvalidAcmeAriTimestamp;
    const second = std.fmt.parseInt(u8, text[17..19], 10) catch return error.InvalidAcmeAriTimestamp;
    if (year < 1970 or year > 2100 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59) return error.InvalidAcmeAriTimestamp;
    const leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
    const lengths = [_]u8{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (day == 0 or day > lengths[month - 1]) return error.InvalidAcmeAriTimestamp;
    var days: i64 = 0;
    for (1970..year) |y| days += if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) @as(i64, 366) else 365;
    for (lengths[0 .. month - 1]) |n| days += n;
    days += day - 1;
    var index: usize = 19;
    if (text[index] == '.') {
        index += 1;
        const begin = index;
        while (index < text.len and std.ascii.isDigit(text[index])) : (index += 1) {}
        if (index == begin or index - begin > 9) return error.InvalidAcmeAriTimestamp;
    }
    const zone = text[index..];
    var offset: i64 = 0;
    if (!std.mem.eql(u8, zone, "Z") and !std.mem.eql(u8, zone, "z")) {
        if (zone.len != 6 or (zone[0] != '+' and zone[0] != '-') or zone[3] != ':') return error.InvalidAcmeAriTimestamp;
        const h = std.fmt.parseInt(u8, zone[1..3], 10) catch return error.InvalidAcmeAriTimestamp;
        const m = std.fmt.parseInt(u8, zone[4..6], 10) catch return error.InvalidAcmeAriTimestamp;
        if (h > 23 or m > 59) return error.InvalidAcmeAriTimestamp;
        offset = (@as(i64, h) * 60 + m) * 60 * @as(i64, if (zone[0] == '+') 1 else -1);
    }
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second - offset;
}
pub fn suggested(client: *Client, chain: []const u8, before: i64, after: i64) !i64 {
    if (client.renewal_info.length == 0) return error.AcmeAriUnavailable;
    const identifier = try id(chain);
    defer crypto.allocator.free(identifier);
    const url = try std.fmt.allocPrint(crypto.allocator, "{s}/{s}", .{ std.mem.trimEnd(u8, client.renewal_info.get(), "/"), identifier });
    defer crypto.allocator.free(url);
    try client.raw(url, 0, "");
    if (client.response.status != 200) return error.AcmeAriUnavailable;
    const document = try client.parsed();
    defer document.deinit();
    const window = try crypto.field(document.value, "suggestedWindow");
    const start = try timestamp(try crypto.string(window, "start"));
    const end = try timestamp(try crypto.string(window, "end"));
    if (end <= start or end > after or start < before) return error.InvalidAcmeAriWindow;
    return @min(after - 60, start + @as(i64, @intCast((try crypto.random()) % @as(u64, @intCast(end - start)))));
}
test "ARI timestamps validate calendar and timezone offsets" {
    try std.testing.expectEqual(@as(i64, 0), try timestamp("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(i64, 0), try timestamp("1970-01-01T01:00:00.123+01:00"));
    try std.testing.expectError(error.InvalidAcmeAriTimestamp, timestamp("2026-02-30T00:00:00Z"));
}
