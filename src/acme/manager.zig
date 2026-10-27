const std = @import("std");
const crypto = @import("crypto.zig");
const a = crypto.allocator;
const Config = @import("config.zig").Config;
const Storage = @import("storage.zig").Storage;
const Client = @import("client.zig").Client;
const renewal = @import("renewal.zig");
const challenge = @import("challenge.zig");
const State = renewal.State;
pub const Counters = struct { accounts: u64 = 0, orders: u64 = 0, order_failures: u64 = 0, challenges: u64 = 0, challenge_failures: u64 = 0, renewals: u64 = 0, renewal_failures: u64 = 0, rate_limits: u64 = 0 };
pub const Manager = struct {
    config: Config,
    storage: Storage,
    state: State,
    challenges: challenge.Store = .{},
    cancel: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
    mutex: std.Thread.Mutex = .{},
    thread: ?std.Thread = null,
    counters: Counters = .{},
    pending: bool = false,
    active_slot: ?u2 = null,
    active_expiry: i64 = 0,
    pending_slot: u2 = 0,
    pending_expiry: i64 = 0,
    event: enum { none, success, failure, expiring } = .none,
    reason: crypto.Text(96) = .{},
    activation_due: u64 = 0,
    activation_attempts: u8 = 0,
    cert_paths: [3]crypto.Text(256) = @splat(.{}),
    key_paths: [3]crypto.Text(256) = @splat(.{}),
    pub fn init(self: *Manager, config: Config) !void {
        self.* = .{ .config = config, .storage = try Storage.open(config.storage), .state = .{ .directory = config.directory, .domains = undefined } };
        self.state.domains = self.config.domains[0..self.config.count];
        errdefer self.storage.deinit();
        if (crypto.c.zg_acme_http_probe() != 1) return error.OpenSslLibcurlWithAsyncDnsRequired;
        if (config.ca_file) |path| try crypto.checkTrustFile(path);
        if (config.issuer_ca) |path| try crypto.checkTrustFile(path);
        for (0..3) |i| {
            var path: [256]u8 = undefined;
            try self.cert_paths[i].set(try std.fmt.bufPrint(&path, "/proc/self/fd/{d}/bundle{d}/chain.pem", .{ self.storage.dir.fd, i }));
            try self.key_paths[i].set(try std.fmt.bufPrint(&path, "/proc/self/fd/{d}/bundle{d}/key.pem", .{ self.storage.dir.fd, i }));
        }
        const account_key_exists = blk: {
            if (try self.storage.read("account.key", 65536)) |bytes| {
                defer crypto.secretFree(bytes);
                const key = try crypto.Key.read(bytes);
                key.deinit();
                break :blk true;
            }
            break :blk false;
        };
        if (try self.storage.read("account.json", 8192)) |bytes| {
            defer a.free(bytes);
            if (!account_key_exists) return error.AcmeAccountKeyMissing;
            const document = try crypto.parse(bytes);
            defer document.deinit();
            if (!std.mem.eql(u8, try crypto.string(document.value, "directory"), config.directory)) return error.AcmeAccountEnvironmentMismatch;
            try @import("config.zig").endpoint(config.directory, try crypto.string(document.value, "kid"));
        }
        if (try self.storage.read("state.json", 65536)) |bytes| {
            defer a.free(bytes);
            const parsed = try std.json.parseFromSlice(State, a, bytes, .{ .duplicate_field_behavior = .@"error" });
            defer parsed.deinit();
            const saved = parsed.value;
            if (saved.version != 1 or saved.slot > 2 or !std.mem.eql(u8, saved.directory, config.directory) or saved.domains.len != config.count or saved.failures > 16 or saved.next_attempt < 0) return error.AcmeStorageConfigurationMismatch;
            for (saved.domains, self.config.domains[0..config.count]) |old, domain| if (!std.mem.eql(u8, old, domain)) return error.AcmeStorageConfigurationMismatch;
            self.state.slot = saved.slot;
            self.state.has_certificate = saved.has_certificate;
            self.state.before = saved.before;
            self.state.after = saved.after;
            self.state.renew_at = saved.renew_at;
            self.state.next_attempt = saved.next_attempt;
            self.state.failures = saved.failures;
            self.state.ari_check = saved.ari_check;
            if (saved.has_certificate) {
                const pem = try self.storage.readBundle(saved.slot, "key.pem", 65536);
                defer crypto.secretFree(pem);
                const key = try crypto.Key.read(pem);
                defer key.deinit();
                const chain = try self.storage.readBundle(saved.slot, "chain.pem", 1048576);
                defer a.free(chain);
                const validity = try crypto.validateStored(chain, key, self.config.domains[0..config.count], config.issuer_ca, true);
                if (validity.before != saved.before or validity.after != saved.after or saved.renew_at < saved.before or saved.renew_at > saved.after) return error.InvalidAcmeRenewalState;
                if (saved.before <= std.time.timestamp() and saved.after > std.time.timestamp()) {
                    self.active_slot = saved.slot;
                    self.active_expiry = saved.after;
                }
            }
        }
    }
    pub fn configure(self: *Manager, options: *@import("../cli/commands.zig").Options) void {
        options.challenge_store = &self.challenges;
        if (self.active_slot) |slot| {
            options.tls.cert = self.cert_paths[slot].get();
            options.tls.key = self.key_paths[slot].get();
        }
    }
    pub fn start(self: *Manager) !void {
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
    }
    pub fn requestStop(self: *Manager) void {
        self.cancel.store(1, .release);
    }
    pub fn stop(self: *Manager) void {
        self.requestStop();
        if (self.thread) |thread| thread.join();
        self.thread = null;
        self.challenges.clear();
    }
    pub fn deinit(self: *Manager) void {
        self.stop();
        crypto.c.zg_acme_http_cleanup();
        self.storage.deinit();
    }
    fn pause(self: *Manager, milliseconds: u64) bool {
        const deadline = challenge.now() + milliseconds;
        while (challenge.now() < deadline) {
            if (self.cancel.load(.acquire) != 0) return false;
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
        return self.cancel.load(.acquire) == 0;
    }
    fn save(self: *Manager) !void {
        const bytes = try crypto.json(self.state);
        defer a.free(bytes);
        try self.storage.write("state.json", bytes);
    }
    fn announce(self: *Manager, event: @TypeOf(self.event), reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.event = event;
        self.reason.set(reason) catch unreachable;
    }
    fn account(self: *Manager, client: *Client) !void {
        if (try self.storage.read("account.json", 8192)) |bytes| {
            defer a.free(bytes);
            const document = try crypto.parse(bytes);
            defer document.deinit();
            if (!std.mem.eql(u8, try crypto.string(document.value, "directory"), self.config.directory)) return error.AcmeAccountEnvironmentMismatch;
            const kid = try crypto.string(document.value, "kid");
            try @import("config.zig").endpoint(self.config.directory, kid);
            try client.account.set(kid);
            client.postGet(kid) catch |err| {
                if (err != error.AcmeAccountMissing) return err;
                client.account.length = 0;
            };
            if (client.account.length != 0) {
                const result = try client.parsed();
                defer result.deinit();
                if (!std.mem.eql(u8, try crypto.string(result.value, "status"), "valid")) return error.AcmeAccountInvalid;
                return;
            }
        }
        self.mutex.lock();
        self.counters.accounts +|= 1;
        self.mutex.unlock();
        const contact = try std.fmt.allocPrint(a, "mailto:{s}", .{self.config.email});
        defer a.free(contact);
        const payload = try crypto.json(.{ .termsOfServiceAgreed = true, .contact = [_][]const u8{contact} });
        defer a.free(payload);
        // Re-registering the same persisted JWK recovers an existing account.
        try client.signed(client.new_account.get(), payload, true);
        if (client.response.status != 200 and client.response.status != 201) return error.AcmeAccountInvalid;
        const result = try client.parsed();
        defer result.deinit();
        if (!std.mem.eql(u8, try crypto.string(result.value, "status"), "valid")) return error.AcmeAccountInvalid;
        const kid = try client.location();
        defer a.free(kid);
        try client.account.set(kid);
        const account_json = try crypto.json(.{ .kid = kid, .directory = self.config.directory });
        defer a.free(account_json);
        try self.storage.write("account.json", account_json);
    }
    fn transaction(self: *Manager, key: crypto.Key, retry_after: *i64) !void {
        var client = try Client.init(self.config, key, &self.cancel);
        defer client.deinit();
        defer {
            retry_after.* = client.retry_after;
            self.mutex.lock();
            self.counters.rate_limits +|= client.rate_limits;
            self.counters.challenges +|= client.challenges_validated;
            self.counters.challenge_failures +|= client.challenges_started -| client.challenges_validated;
            self.mutex.unlock();
        }
        try client.directory();
        try self.account(&client);
        if (self.state.has_certificate and client.renewal_info.length != 0) {
            const chain = try self.storage.readBundle(self.state.slot, "chain.pem", 1048576);
            defer a.free(chain);
            const identifier = @import("ari.zig").id(chain) catch null;
            if (identifier) |text| {
                defer a.free(text);
                try client.replaces.set(text);
            }
        }
        const result = try @import("order.zig").issue(&client, &self.challenges);
        defer result.deinit();
        self.mutex.lock();
        const active_slot = self.active_slot;
        self.mutex.unlock();
        const slot = renewal.bundleSlot(if (self.state.has_certificate) self.state.slot else null, active_slot);
        try self.storage.bundle(slot, result.key, result.chain);
        const previous = self.state;
        errdefer self.state = previous;
        self.state.slot = slot;
        self.state.has_certificate = true;
        self.state.before = result.validity.before;
        self.state.after = result.validity.after;
        self.state.renew_at = @import("ari.zig").suggested(&client, result.chain, self.state.before, self.state.after) catch renewal.eligibility(self.state.before, self.state.after, try crypto.random());
        self.state.ari_check = std.time.timestamp() + if (client.renewal_info.length == 0) @as(i64, 86400) else @max(3600, client.poll_delay);
        self.state.next_attempt = std.time.timestamp() + @min(@as(i64, 3600), @max(@as(i64, 60), @divTrunc(self.state.after - self.state.before, 10)));
        self.state.failures = 0;
        self.save() catch |err| {
            self.state = previous;
            return err;
        };
        self.mutex.lock();
        self.counters.orders +|= 1;
        if (previous.has_certificate) self.counters.renewals +|= 1;
        self.pending_slot = slot;
        self.pending_expiry = self.state.after;
        self.pending = true;
        self.mutex.unlock();
        self.announce(.success, "certificate_stored");
    }
    fn refreshAri(self: *Manager, key: crypto.Key) void {
        var client = Client.init(self.config, key, &self.cancel) catch return;
        defer client.deinit();
        self.state.ari_check = std.time.timestamp() + 86400;
        const chain = self.storage.readBundle(self.state.slot, "chain.pem", 1048576) catch return;
        defer a.free(chain);
        client.directory() catch return;
        const suggested = @import("ari.zig").suggested(&client, chain, self.state.before, self.state.after) catch null;
        if (suggested) |value| self.state.renew_at = value;
        self.state.ari_check = std.time.timestamp() + @max(3600, if (client.poll_delay == 0) @as(i64, 86400) else client.poll_delay);
        self.mutex.lock();
        self.counters.rate_limits +|= client.rate_limits;
        self.mutex.unlock();
        self.save() catch self.announce(.failure, "AcmeStorageFailed");
    }
    fn worker(self: *Manager) void {
        defer crypto.c.OPENSSL_thread_stop();
        defer crypto.c.ERR_clear_error();
        if (crypto.c.zg_acme_http_init() != 1) {
            self.announce(.failure, "OpenSslLibcurlWithAsyncDnsRequired");
            return;
        }
        const key = blk: {
            const bytes = self.storage.read("account.key", 65536) catch {
                self.announce(.failure, "AcmeStorageFailed");
                return;
            };
            if (bytes) |pem| {
                defer crypto.secretFree(pem);
                break :blk crypto.Key.read(pem) catch {
                    self.announce(.failure, "InvalidAcmeKey");
                    return;
                };
            }
            const generated = crypto.Key.generate() catch {
                self.announce(.failure, "AcmeKeyGenerationFailed");
                return;
            };
            const pem = generated.pem() catch {
                generated.deinit();
                self.announce(.failure, "AcmeKeyEncodingFailed");
                return;
            };
            defer crypto.secretFree(pem);
            self.storage.write("account.key", pem) catch {
                generated.deinit();
                self.announce(.failure, "AcmeStorageFailed");
                return;
            };
            break :blk generated;
        };
        defer key.deinit();
        defer self.challenges.clear();
        var retry_mono: u64 = 0;
        var activation_mono: u64 = 0;
        var warning_at: u64 = 0;
        while (self.cancel.load(.acquire) == 0) {
            self.mutex.lock();
            const pending = self.pending;
            const active = self.active_slot;
            const expiry = self.active_expiry;
            self.mutex.unlock();
            const wall = std.time.timestamp();
            if (expiry != 0 and expiry - wall < 7 * 86400 and challenge.now() >= warning_at) {
                self.announce(.expiring, "certificate_expires_within_seven_days");
                warning_at = challenge.now() + 3600000;
            }
            if (pending) {
                if (!self.pause(100)) return;
                continue;
            }
            if (self.state.has_certificate and self.state.after > wall and self.state.before <= wall and active != self.state.slot and challenge.now() >= activation_mono) {
                self.mutex.lock();
                self.pending = true;
                self.pending_slot = self.state.slot;
                self.pending_expiry = self.state.after;
                self.mutex.unlock();
                activation_mono = challenge.now() + 1800000;
                if (!self.pause(100)) return;
                continue;
            }
            // Never overwrite the live TLS bundle while activation is outstanding.
            if (self.state.has_certificate and self.state.after > wall and active != self.state.slot) {
                if (!self.pause(1000)) return;
                continue;
            }
            if (self.state.has_certificate and wall < self.state.renew_at and wall >= self.state.ari_check and challenge.now() >= retry_mono and wall >= self.state.next_attempt) self.refreshAri(key);
            if (challenge.now() < retry_mono or wall < self.state.next_attempt or (self.state.has_certificate and wall < self.state.renew_at)) {
                if (!self.pause(1000)) return;
                continue;
            }
            // A durable restart guard precedes every new network transaction.
            // Crashing mid-order must not turn a service restart loop into CA load.
            self.state.next_attempt = std.time.timestamp() + 60;
            self.save() catch {
                self.announce(.failure, "AcmeStorageFailed");
                return;
            };
            var retry_after: i64 = 0;
            self.transaction(key, &retry_after) catch |err| {
                if (self.cancel.load(.acquire) != 0) return;
                self.mutex.lock();
                self.counters.order_failures +|= 1;
                if (self.state.has_certificate) self.counters.renewal_failures +|= 1;
                self.mutex.unlock();
                self.announce(.failure, @errorName(err));
                self.state.failures = @min(16, self.state.failures + 1);
                const delay = renewal.retry(self.state.failures - 1, crypto.random() catch 0, retry_after);
                self.state.next_attempt = std.time.timestamp() + delay;
                retry_mono = challenge.now() + @as(u64, @intCast(delay)) * 1000;
                self.save() catch {
                    self.announce(.failure, "AcmeStorageFailed");
                    return;
                };
                continue;
            };
            retry_mono = challenge.now() + @as(u64, @intCast(@max(0, self.state.next_attempt - std.time.timestamp()))) * 1000;
            activation_mono = challenge.now() + 1800000;
        }
    }
    pub fn tick(self: *Manager, contexts: *@import("../tls/context.zig").Contexts, tls: @import("../tls/config.zig").Config, metrics: *@import("../observability/metrics.zig").Metrics, logger: *@import("../observability/logger.zig").Logger) void {
        self.mutex.lock();
        const counts = self.counters;
        const event = self.event;
        const reason = self.reason;
        const pending = self.pending;
        const slot = self.pending_slot;
        const expires = self.pending_expiry;
        const active_expiry = self.active_expiry;
        self.event = .none;
        self.mutex.unlock();
        metrics.acme_account_attempts = counts.accounts;
        metrics.acme_order_successes = counts.orders;
        metrics.acme_order_failures = counts.order_failures;
        metrics.acme_challenge_successes = counts.challenges;
        metrics.acme_challenge_failures = counts.challenge_failures;
        metrics.acme_renewal_successes = counts.renewals;
        metrics.acme_renewal_failures = counts.renewal_failures;
        metrics.acme_rate_limits = counts.rate_limits;
        metrics.acme_days_until_expiration = if (active_expiry != 0) @divFloor(active_expiry - std.time.timestamp(), 86400) else -1;
        switch (event) {
            .none => {},
            .success => logger.event(.info, "acme_certificate_stored", .{}),
            .failure => logger.event(.warn, "acme_failure", .{ .reason = reason.get() }),
            .expiring => logger.event(.warn, "acme_expiration_warning", .{}),
        }
        if (!pending or challenge.now() < self.activation_due or self.cancel.load(.acquire) != 0) return;
        if (expires <= std.time.timestamp() + 60) {
            metrics.acme_activation_failures +|= 1;
            self.mutex.lock();
            self.pending = false;
            self.mutex.unlock();
            logger.event(.warn, "acme_activation_failed", .{ .reason = "certificate_expired_before_activation" });
            return;
        }
        var config = tls;
        config.cert = self.cert_paths[slot].get();
        config.key = self.key_paths[slot].get();
        contexts.reloadWith(config) catch |err| {
            metrics.acme_activation_failures +|= 1;
            self.activation_attempts += 1;
            self.activation_due = challenge.now() + @min(@as(u64, 60000), @as(u64, 1000) << @intCast(@min(self.activation_attempts, 6)));
            logger.event(.warn, "acme_activation_failed", .{ .reason = @errorName(err) });
            if (self.activation_attempts >= 8) {
                self.mutex.lock();
                self.pending = false;
                self.mutex.unlock();
                self.activation_attempts = 0;
            }
            return;
        };
        self.activation_attempts = 0;
        self.activation_due = 0;
        self.mutex.lock();
        self.active_slot = slot;
        self.active_expiry = expires;
        self.pending = false;
        self.mutex.unlock();
        logger.event(.info, "acme_certificate_activated", .{});
    }
};
