const std = @import("std");
const crypto = @import("crypto.zig");
const c = crypto.c;
const a = crypto.allocator;
const Config = @import("config.zig");
const monotonic = @import("challenge.zig").now;
pub const Client = struct {
    config: Config.Config,
    key: crypto.Key,
    cancel: *std.atomic.Value(u8),
    response: *c.zg_acme_response,
    nonce: crypto.Text(511) = .{},
    account: crypto.Text(2048) = .{},
    new_nonce: crypto.Text(2048) = .{},
    new_account: crypto.Text(2048) = .{},
    new_order: crypto.Text(2048) = .{},
    renewal_info: crypto.Text(2048) = .{},
    replaces: crypto.Text(512) = .{},
    calls: u16 = 0,
    deadline: u64,
    retry_after: i64 = 0,
    poll_delay: i64 = 0,
    rate_limits: u64 = 0,
    challenges_started: u64 = 0,
    challenges_validated: u64 = 0,
    pub fn init(config: Config.Config, key: crypto.Key, cancel: *std.atomic.Value(u8)) !Client {
        return .{ .config = config, .key = key, .cancel = cancel, .response = try a.create(c.zg_acme_response), .deadline = monotonic() + 600000 };
    }
    pub fn deinit(self: *Client) void {
        a.destroy(self.response);
    }
    pub fn stopped(self: *Client) bool {
        return self.cancel.load(.acquire) != 0;
    }
    pub fn wait(self: *Client, seconds: i64) !void {
        const duration: u64 = @intCast(@max(1, seconds));
        if (duration > 600 or monotonic() + duration * 1000 >= self.deadline) return error.AcmeRetryDeferred;
        const end = monotonic() + duration * 1000;
        while (monotonic() < end) {
            if (self.stopped()) return error.AcmeCancelled;
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }
    pub fn raw(self: *Client, url: []const u8, method: c_int, request_body: []const u8) !void {
        if (self.stopped()) return error.AcmeCancelled;
        if (self.calls >= 256 or monotonic() >= self.deadline) return error.AcmeTransactionLimit;
        try Config.endpoint(self.config.directory, url);
        self.calls += 1;
        self.poll_delay = 0;
        const address = try a.dupeZ(u8, url);
        defer a.free(address);
        const ca = if (self.config.ca_file) |path| try a.dupeZ(u8, path) else null;
        defer if (ca) |path| a.free(path);
        if (c.zg_acme_http(address, method, request_body.ptr, request_body.len, if (ca) |path| path.ptr else null, self.response, &self.cancel.raw) != 1) return error.AcmeTransportFailed;
        if (self.response.nonce[0] != 0) {
            const nonce = std.mem.sliceTo(&self.response.nonce, 0);
            for (nonce) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidAcmeNonce;
            try self.nonce.set(nonce);
        }
        if (self.response.retry[0] != 0) {
            const text = std.mem.sliceTo(&self.response.retry, 0);
            const numeric = std.fmt.parseInt(u32, text, 10) catch null;
            const seconds = if (numeric) |n| @as(i64, n) else blk: {
                const date = c.zg_acme_http_date(&self.response.retry);
                if (date < 0 or std.mem.indexOfScalar(u8, text, ',') == null) return error.InvalidAcmeRetryAfter;
                break :blk @max(0, date - std.time.timestamp());
            };
            self.retry_after = @max(self.retry_after, seconds);
            self.poll_delay = seconds;
        }
        if (self.response.status == 429) self.rate_limits +|= 1;
        if (self.response.status >= 300 and self.response.status < 400) return error.AcmeRedirectRejected;
    }
    pub fn body(self: *Client) []const u8 {
        return self.response.body[0..self.response.length];
    }
    pub fn parsed(self: *Client) !std.json.Parsed(std.json.Value) {
        return crypto.parse(self.body());
    }
    pub fn location(self: *Client) ![]const u8 {
        const url = std.mem.sliceTo(&self.response.location, 0);
        try Config.endpoint(self.config.directory, url);
        return a.dupe(u8, url);
    }
    pub fn directory(self: *Client) !void {
        try self.raw(self.config.directory, 0, "");
        if (self.response.status != 200) return error.AcmeDirectoryFailed;
        const document = try self.parsed();
        defer document.deinit();
        for ([_]struct { name: []const u8, target: *crypto.Text(2048) }{ .{ .name = "newNonce", .target = &self.new_nonce }, .{ .name = "newAccount", .target = &self.new_account }, .{ .name = "newOrder", .target = &self.new_order } }) |entry| {
            const url = try crypto.string(document.value, entry.name);
            try Config.endpoint(self.config.directory, url);
            try entry.target.set(url);
        }
        if (document.value.object.get("meta")) |meta| {
            if (meta != .object) return error.UnexpectedAcmeResponse;
            if (meta.object.get("externalAccountRequired")) |required| {
                if (required != .bool) return error.UnexpectedAcmeResponse;
                if (required.bool) return error.AcmeExternalAccountBindingUnsupported;
            }
        }
        if (document.value.object.get("renewalInfo")) |entry| {
            const url = try crypto.text(entry);
            try Config.endpoint(self.config.directory, url);
            try self.renewal_info.set(url);
        }
    }
    pub fn signed(self: *Client, url: []const u8, payload: []const u8, jwk_header: bool) !void {
        for (0..3) |_| {
            if (self.nonce.length == 0) {
                try self.raw(self.new_nonce.get(), 1, "");
                if ((self.response.status != 200 and self.response.status != 204) or self.nonce.length == 0) return error.AcmeNonceFailed;
            }
            const protected = if (jwk_header) blk: {
                const jwk = try self.key.jwk();
                defer a.free(jwk);
                break :blk try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":{f},\"url\":{f}}}", .{ jwk, std.json.fmt(self.nonce.get(), .{}), std.json.fmt(url, .{}) });
            } else try crypto.json(.{ .alg = "ES256", .kid = self.account.get(), .nonce = self.nonce.get(), .url = url });
            defer a.free(protected);
            self.nonce.length = 0; // every nonce is consumed once, even if transport fails
            const header64 = try crypto.base64(protected);
            defer a.free(header64);
            const payload64 = try crypto.base64(payload);
            defer a.free(payload64);
            const input = try std.fmt.allocPrint(a, "{s}.{s}", .{ header64, payload64 });
            defer a.free(input);
            var signature: [64]u8 = undefined;
            if (c.zg_acme_sign(self.key.ptr, input.ptr, input.len, &signature) != 1) return error.AcmeSigningFailed;
            const signature64 = try crypto.base64(&signature);
            defer a.free(signature64);
            const request = try crypto.json(.{ .protected = header64, .payload = payload64, .signature = signature64 });
            defer a.free(request);
            try self.raw(url, 2, request);
            if (self.response.status >= 200 and self.response.status < 300) return;
            const problem = self.parsed() catch return error.MalformedAcmeProblem;
            defer problem.deinit();
            const kind = try crypto.string(problem.value, "type");
            if (self.response.status == 400 and std.mem.eql(u8, kind, "urn:ietf:params:acme:error:badNonce")) continue;
            if (self.response.status == 429 or std.mem.eql(u8, kind, "urn:ietf:params:acme:error:rateLimited")) {
                if (self.response.status != 429) self.rate_limits +|= 1;
                return error.AcmeRateLimited;
            }
            if (std.mem.eql(u8, kind, "urn:ietf:params:acme:error:accountDoesNotExist")) return error.AcmeAccountMissing;
            return error.AcmeRejected;
        }
        return error.AcmeBadNonceLimit;
    }
    pub fn postGet(self: *Client, url: []const u8) !void {
        return self.signed(url, "", false);
    }
};
