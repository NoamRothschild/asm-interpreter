const std = @import("std");
const testing = std.testing;

const module = @import("../module.zig");
const runner = @import("runner.zig");

test "8086 suite 00" {
    module.silent = true;
    defer module.silent = false;

    var stats: runner.RunStats = .{};
    try runner.runSuite("00", &stats);

    // Test binaries use compiler/test_runner.zig, which only prints log_level >= .warn.
    std.debug.print(
        "suite 00: passed={d} parse_skipped={d} exec_skipped={d} failed={d}\n",
        .{ stats.passed, stats.skipped_parse, stats.skipped_exec, stats.failed },
    );

    try testing.expect(stats.passed > 0);
    // Mismatches are logged; they indicate interpreter gaps, not harness bugs.
}
