/// Event-loop owned, fixed-size counters. Snapshots are emitted as JSONL.
pub const Metrics = struct {
    active_tls: u64 = 0,
    tls_handshake_successes: u64 = 0,
    tls_handshake_failures: u64 = 0,
    tls_handshake_timeouts: u64 = 0,
    tls_1_2: u64 = 0,
    tls_1_3: u64 = 0,
    tls_shutdown_failures: u64 = 0,
    active_clients: u64 = 0,
    active_upstreams: u64 = 0,
    requests: u64 = 0,
    responses_2xx: u64 = 0,
    responses_4xx: u64 = 0,
    responses_5xx: u64 = 0,
    proxy_failures: u64 = 0,
    connection_rejections: u64 = 0,
    duration_ms_sum: u64 = 0,
    duration_ms_max: u64 = 0,
    uptime_ms: u64 = 0,
    pub fn response(self: *Metrics, status: u16, duration: u64) void {
        switch (status / 100) {
            2 => self.responses_2xx +|= 1,
            4 => self.responses_4xx +|= 1,
            5 => self.responses_5xx +|= 1,
            else => {},
        }
        self.duration_ms_sum +|= duration;
        self.duration_ms_max = @max(self.duration_ms_max, duration);
    }
};
