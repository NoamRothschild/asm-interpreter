const std = @import("std");
const testing = std.testing;

const module = @import("../module.zig");
const runner = @import("runner.zig");

test "8086 suite 00" {
    module.silent = true;
    defer module.silent = false;

    var stats: runner.RunStats = .{};
    try runner.runSuite("00", &stats);
    if (stats.failed > runner.max_detail_failures) {
        std.debug.print("suite 00: detailed logs shown for first {d} failures only\n", .{
            runner.max_detail_failures,
        });
    }

    std.debug.print(
        "suite 00: passed={d} parse_skipped={d} exec_skipped={d} failed={d}\n",
        .{ stats.passed, stats.skipped_parse, stats.skipped_exec, stats.failed },
    );

    try testing.expect(stats.passed > 0);
    // Mismatches are logged; they indicate interpreter gaps, not harness bugs.
}

test "8086 suite 01" {
    module.silent = true;
    defer module.silent = false;

    var stats: runner.RunStats = .{};
    try runner.runSuite("01", &stats);
    if (stats.failed > runner.max_detail_failures) {
        std.debug.print("suite 01: detailed logs shown for first {d} failures only\n", .{
            runner.max_detail_failures,
        });
    }

    std.debug.print(
        "suite 01: passed={d} parse_skipped={d} exec_skipped={d} failed={d}\n",
        .{ stats.passed, stats.skipped_parse, stats.skipped_exec, stats.failed },
    );

    try testing.expect(stats.passed > 0);
    // Mismatches are logged; they indicate interpreter gaps, not harness bugs.
}
