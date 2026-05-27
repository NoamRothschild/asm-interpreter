const std = @import("std");

const config = @import("config.zig");

const reset = "\x1b[0m";
const red = "\x1b[31m";
const green = "\x1b[32m";
const grey = "\x1b[90m";

fn emit(comptime color: []const u8, comptime fmt: []const u8, args: anytype) void {
    std.debug.print(color ++ fmt ++ reset ++ "\n", args);
}

/// Errors: execute failures, register/flags/ram mismatches.
pub fn fail(comptime fmt: []const u8, args: anytype) void {
    emit(red, fmt, args);
}

/// Skips and other non-fatal informational messages.
pub fn skip(comptime fmt: []const u8, args: anytype) void {
    if (config.suppress_skip_logs) return;
    emit(grey, fmt, args);
}

/// Suite summaries and other success-style output.
pub fn ok(comptime fmt: []const u8, args: anytype) void {
    emit(green, fmt, args);
}
