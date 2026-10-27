//! Public HTTP components; returned request slices borrow the input buffer.
pub const parser = @import("http/parser.zig");
pub const response = @import("http/response.zig");
pub const router = @import("http/router.zig");
