const std = @import("std");
const testing = std.testing;

const Context = @import("../CPU/context.zig").Context;
const executor = @import("../CPU/executor.zig");
const parser_root = @import("../parser/root.zig");
const parser = @import("parser.zig");
const context = @import("context.zig");

pub const max_detail_failures = 50;

pub const RunStats = struct {
    skipped_parse: usize = 0,
    skipped_exec: usize = 0,
    passed: usize = 0,
    failed: usize = 0,
};

pub fn runEntry(entry: parser.TestEntry, stats: *RunStats) void {
    var parser_ctx = parser_root.init(testing.allocator, null);
    const instruction = parser_root.parseInstruction(&parser_ctx, entry.name) catch |err| {
        std.log.warn("parse failed for '{s}' (#{d}): {s}", .{ entry.name, entry.test_num, @errorName(err) });
        stats.skipped_parse += 1;
        return;
    };

    var inst_storage = [_]parser_root.Instruction{instruction};
    var ctx = Context{
        .ip = 0,
        .dataseg = [_]u8{0} ** 65536,
        .instructions = &inst_storage,
    };

    context.applyInitial(&ctx, entry.initial);

    executor.executeInstruction(&ctx) catch |err| {
        std.log.warn("execute failed for '{s}' (#{d}): {s}", .{ entry.name, entry.test_num, @errorName(err) });
        stats.skipped_exec += 1;
        return;
    };

    if (context.findMismatch(&ctx, entry.final)) |mismatch| {
        stats.failed += 1;

        if (stats.failed <= max_detail_failures) {
            var buf: [256]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            context.printMismatch(fbs.writer(), mismatch) catch {};
            std.debug.print("mismatch for '{s}' (#{d}): {s}\n", .{ entry.name, entry.test_num, fbs.getWritten() });
        }

        return;
    }

    stats.passed += 1;
}

pub fn runSuite(suite_name: []const u8, stats: *RunStats) !void {
    const tests = try parser.fromFilename(suite_name);
    for (tests) |entry| {
        runEntry(entry, stats);
    }
}
