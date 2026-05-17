const std = @import("std");

pub const Regs = struct {
    ax: ?usize = null,
    bx: ?usize = null,
    cx: ?usize = null,
    dx: ?usize = null,
    cs: ?usize = null,
    ss: ?usize = null,
    ds: ?usize = null,
    es: ?usize = null,
    sp: ?usize = null,
    bp: ?usize = null,
    si: ?usize = null,
    di: ?usize = null,
    ip: ?usize = null,
    flags: ?usize = null,
};

pub const Ram = [][2]usize;

pub const CpuState = struct {
    regs: Regs,
    ram: Ram,
    queue: []usize,
};

pub const TestEntry = struct {
    name: []const u8,
    bytes: []isize,
    initial: CpuState,
    final: CpuState,
    cycles: std.json.Value,
    test_hash: []const u8,
    test_num: usize,
};

pub const TestJson = []TestEntry;

const flatten = @import("flatten.zig");

pub fn fromFilename(allocator: std.mem.Allocator, name: []const u8) !TestJson {
    const path = try std.fmt.allocPrint(allocator, "test_suite/v1/{s}.json.gz", .{name});
    defer allocator.free(path);

    const compressed = try std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize));
    defer allocator.free(compressed);

    var json_buf = std.ArrayList(u8).init(allocator);
    defer json_buf.deinit();

    var fbs = std.io.fixedBufferStream(compressed);
    try std.compress.gzip.decompress(fbs.reader(), json_buf.writer());
    const json_text = try json_buf.toOwnedSlice();
    defer allocator.free(json_text);

    const parsed = try std.json.parseFromSliceLeaky(TestJson, allocator, json_text, .{});
    var kept = std.ArrayList(TestEntry).init(allocator);
    for (parsed) |*entry| {
        const keep = flatten.flattenTestEntry(allocator, entry) catch |err| {
            if (err == error.UnknownInstruction) {
                std.log.warn("skipping suite set: got UnknownInstruction on `{s}` (assuming unsupported)", .{entry.name});
                return error.Abort;
            }
            return err;
        };
        if (keep) try kept.append(entry.*);
    }
    return try kept.toOwnedSlice();
}

test "fromFilename loads and aligns instruction names" {
    const testing = std.testing;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const tests = try fromFilename(arena.allocator(), "00");
    try testing.expect(tests.len > 0);

    for (tests) |entry| {
        try testing.expect(!std.mem.containsAtLeast(u8, entry.name, "byte [".len, "byte ["));
        try testing.expect(!std.mem.containsAtLeast(u8, entry.name, "word [".len, "word ["));
        for (flatten.segment_prefixes) |pfx| {
            try testing.expect(!std.mem.containsAtLeast(u8, entry.name, pfx.len, pfx));
        }
    }

    const mem_test = blk: {
        for (tests) |entry| {
            if (std.mem.indexOf(u8, entry.name, "[byte ptr ")) |_| break :blk entry;
        }
        break :blk null;
    };
    try testing.expect(mem_test != null);
}
