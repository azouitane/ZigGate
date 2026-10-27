const std = @import("std");
const crypto = @import("crypto.zig");
const a = crypto.allocator;
const Client = @import("client.zig").Client;
const challenge = @import("challenge.zig");
const endpoint = @import("config.zig").endpoint;
pub const Result = struct {
    key: []u8,
    chain: []u8,
    validity: crypto.Validity,
    pub fn deinit(self: Result) void {
        crypto.secretFree(self.key);
        a.free(self.chain);
    }
};
pub fn issue(client: *Client, store: *challenge.Store) !Result {
    defer store.clear();
    const domains = client.config.domains[0..client.config.count];
    var identifiers: [8]struct { type: []const u8 = "dns", value: []const u8 } = undefined;
    for (domains, 0..) |domain, i| identifiers[i] = .{ .value = domain };
    const payload = if (client.replaces.length != 0) try crypto.json(.{ .identifiers = identifiers[0..domains.len], .replaces = client.replaces.get() }) else try crypto.json(.{ .identifiers = identifiers[0..domains.len] });
    defer a.free(payload);
    try client.signed(client.new_order.get(), payload, false);
    if (client.response.status != 201) return error.InvalidAcmeOrder;
    const order_url = try client.location();
    defer a.free(order_url);
    var auth_urls: [8]crypto.Text(2048) = @splat(.{});
    var finalize: crypto.Text(2048) = .{};
    {
        const document = try client.parsed();
        defer document.deinit();
        const value = document.value;
        const status = try crypto.string(value, "status");
        if (!std.mem.eql(u8, status, "pending") and !std.mem.eql(u8, status, "ready")) return error.InvalidAcmeOrder;
        const auths = try crypto.field(value, "authorizations");
        if (auths != .array or auths.array.items.len != domains.len) return error.InvalidAcmeAuthorizations;
        const order_identifiers = try crypto.field(value, "identifiers");
        if (order_identifiers != .array or order_identifiers.array.items.len != domains.len) return error.InvalidAcmeOrder;
        for (domains) |domain| {
            var found: usize = 0;
            for (order_identifiers.array.items) |id| if (std.mem.eql(u8, try crypto.string(id, "type"), "dns") and std.mem.eql(u8, try crypto.string(id, "value"), domain)) {
                found += 1;
            };
            if (found != 1) return error.InvalidAcmeOrder;
        }
        const final_url = try crypto.string(value, "finalize");
        try endpoint(client.config.directory, final_url);
        try finalize.set(final_url);
        for (auths.array.items, 0..) |item, i| {
            const url = try crypto.text(item);
            try endpoint(client.config.directory, url);
            try auth_urls[i].set(url);
        }
    }
    var authorized: [8]bool = @splat(false);
    const thumb = try client.key.thumb();
    defer a.free(thumb);
    for (auth_urls[0..domains.len]) |*url| {
        try client.postGet(url.get());
        var token: crypto.Text(128) = .{};
        var challenge_url: crypto.Text(2048) = .{};
        var already_valid = false;
        {
            const document = try client.parsed();
            defer document.deinit();
            const identifier = try crypto.field(document.value, "identifier");
            if (!std.mem.eql(u8, try crypto.string(identifier, "type"), "dns")) return error.InvalidAcmeAuthorization;
            const domain = try crypto.string(identifier, "value");
            var matched: ?usize = null;
            for (domains, 0..) |expected, i| if (std.mem.eql(u8, domain, expected)) {
                matched = i;
            };
            const index = matched orelse return error.InvalidAcmeAuthorization;
            if (authorized[index]) return error.InvalidAcmeAuthorization;
            authorized[index] = true;
            if (document.value.object.get("wildcard")) |wildcard| if (wildcard != .bool or wildcard.bool) return error.InvalidAcmeAuthorization;
            const status = try crypto.string(document.value, "status");
            already_valid = std.mem.eql(u8, status, "valid");
            if (!already_valid and !std.mem.eql(u8, status, "pending")) return error.AcmeAuthorizationFailed;
            if (!already_valid) {
                const challenges = try crypto.field(document.value, "challenges");
                if (challenges != .array or challenges.array.items.len > 16) return error.InvalidAcmeAuthorization;
                for (challenges.array.items) |item| if (std.mem.eql(u8, try crypto.string(item, "type"), "http-01")) {
                    if (token.length != 0) return error.InvalidAcmeAuthorization;
                    const value = try crypto.string(item, "token");
                    if (!challenge.tokenValid(value)) return error.InvalidAcmeToken;
                    try token.set(value);
                    const address = try crypto.string(item, "url");
                    try endpoint(client.config.directory, address);
                    try challenge_url.set(address);
                };
                if (token.length == 0) return error.AcmeHttp01Unavailable;
            }
        }
        if (already_valid) {
            client.challenges_validated += 1;
            continue;
        }
        const key_auth = try std.fmt.allocPrint(a, "{s}.{s}", .{ token.get(), thumb });
        defer a.free(key_auth);
        client.challenges_started += 1;
        try store.put(token.get(), key_auth, challenge.now() + 600000);
        try client.signed(challenge_url.get(), "{}", false);
        if (client.poll_delay > 0) try client.wait(client.poll_delay);
        var valid = false;
        for (0..30) |_| {
            try client.postGet(url.get());
            const document = try client.parsed();
            defer document.deinit();
            const status = try crypto.string(document.value, "status");
            if (std.mem.eql(u8, status, "valid")) {
                valid = true;
                break;
            }
            if (!std.mem.eql(u8, status, "pending") and !std.mem.eql(u8, status, "processing")) return error.AcmeAuthorizationFailed;
            try client.wait(@max(1, client.retry_after));
        }
        if (!valid) return error.AcmeAuthorizationTimeout;
        client.challenges_validated += 1;
        store.remove(token.get());
    }
    store.clear();
    const key = try crypto.Key.generate();
    defer key.deinit();
    const csr = try key.csr(domains);
    defer a.free(csr);
    const encoded = try crypto.base64(csr);
    defer a.free(encoded);
    const final_payload = try crypto.json(.{ .csr = encoded });
    defer a.free(final_payload);
    // The order must be ready before finalization (authorizations may converge later).
    var ready = false;
    for (0..30) |_| {
        try client.postGet(order_url);
        const document = try client.parsed();
        defer document.deinit();
        const status = try crypto.string(document.value, "status");
        if (std.mem.eql(u8, status, "ready")) {
            ready = true;
            break;
        }
        if (!std.mem.eql(u8, status, "pending")) return error.AcmeOrderNotReady;
        try client.wait(@max(1, client.retry_after));
    }
    if (!ready) return error.AcmeOrderNotReady;
    try client.signed(finalize.get(), final_payload, false);
    if (client.poll_delay > 0) try client.wait(client.poll_delay);
    {
        const document = try client.parsed();
        defer document.deinit();
        const status = try crypto.string(document.value, "status");
        if (!std.mem.eql(u8, status, "processing") and !std.mem.eql(u8, status, "valid")) return error.AcmeOrderFailed;
    }
    var certificate: crypto.Text(2048) = .{};
    for (0..30) |_| {
        try client.postGet(order_url);
        const document = try client.parsed();
        defer document.deinit();
        const status = try crypto.string(document.value, "status");
        if (std.mem.eql(u8, status, "valid")) {
            const address = try crypto.string(document.value, "certificate");
            try endpoint(client.config.directory, address);
            try certificate.set(address);
            break;
        }
        if (!std.mem.eql(u8, status, "processing") and !std.mem.eql(u8, status, "ready")) return error.AcmeOrderFailed;
        try client.wait(@max(1, client.retry_after));
    }
    if (certificate.length == 0) return error.AcmeOrderTimeout;
    try client.postGet(certificate.get());
    const validity = try crypto.validate(client.body(), key, domains, client.config.issuer_ca);
    const pem = try key.pem();
    errdefer crypto.secretFree(pem);
    return .{ .key = pem, .chain = try a.dupe(u8, client.body()), .validity = validity };
}
