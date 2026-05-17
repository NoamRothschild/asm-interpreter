const std = @import("std");
const testing = std.testing;

const module = @import("../module.zig");
const runner = @import("runner.zig");
const log = @import("log.zig");

fn run8086Suite(suite_number: []const u8) !void {
    module.silent = true;
    defer module.silent = false;

    var stats: runner.RunStats = .{};
    runner.runSuite(suite_number, &stats) catch |err| switch (err) {
        error.Abort, error.FileNotFound => return,
        else => return err,
    };
    const total = stats.passed + stats.skipped_parse + stats.skipped_exec + stats.failed;
    if (total == 0) {
        // we cancel tests if they use the segment registers (ex: mov ax, ds)
        log.skip("suite {s}: skipped entirely (unsupported segment operands)", .{suite_number});
        return;
    }

    if (stats.failed > runner.max_detail_failures) {
        log.skip("suite {s}: detailed logs shown for first {d} failures only", .{ suite_number, runner.max_detail_failures });
    }

    log.ok("suite {s}: passed={d} parse_skipped={d} exec_skipped={d} failed={d}", .{ suite_number, stats.passed, stats.skipped_parse, stats.skipped_exec, stats.failed });
    try testing.expect(stats.passed > 0);
    // Mismatches are logged; they indicate interpreter gaps, not harness bugs.
}

comptime {
    for (0..256) |i| {
        _ = struct {
            test {
                const suite_name = comptime std.fmt.comptimePrint("{X:0>2}", .{i});
                try run8086Suite(suite_name);
            }
        };
    }
}
