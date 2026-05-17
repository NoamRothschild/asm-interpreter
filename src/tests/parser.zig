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

const segment_prefixes = [_][]const u8{ "cs:", "ds:", "es:", "ss:" };

/// aligns test names to the format expected by our interpreter
/// example: byte [ds:bx] -> [byte ptr bx]
fn alignTestName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < name.len) {
        if (std.mem.startsWith(u8, name[i..], "byte [")) {
            try out.appendSlice("[byte ptr ");
            i += "byte [".len;
        } else if (std.mem.startsWith(u8, name[i..], "word [")) {
            try out.appendSlice("[word ptr ");
            i += "word [".len;
        } else {
            var skipped: bool = false;
            for (segment_prefixes) |pfx| {
                if (std.mem.startsWith(u8, name[i..], pfx)) {
                    i += pfx.len;
                    skipped = true;
                    break;
                }
            }
            if (!skipped) {
                try out.append(name[i]);
                i += 1;
            }
        }
    }
    return try out.toOwnedSlice();
}

pub fn fromFilename(name: []const u8) !TestJson {
    const allocator = std.heap.page_allocator;

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

    const tests = try std.json.parseFromSliceLeaky(TestJson, allocator, json_text, .{});
    for (tests) |*entry| {
        entry.name = try alignTestName(allocator, entry.name);
    }
    return tests;
}

test "fromFilename loads and aligns instruction names" {
    const testing = std.testing;
    const tests = try fromFilename("00");
    try testing.expect(tests.len > 0);

    for (tests) |entry| {
        for (segment_prefixes) |pfx| {
            try testing.expect(!std.mem.containsAtLeast(u8, entry.name, pfx.len, pfx));
        }
        try testing.expect(!std.mem.containsAtLeast(u8, entry.name, "byte [".len, "byte ["));
        try testing.expect(!std.mem.containsAtLeast(u8, entry.name, "word [".len, "word ["));
    }

    const mem_test = blk: {
        for (tests) |entry| {
            if (std.mem.indexOf(u8, entry.name, "[byte ptr ")) |_| break :blk entry;
        }
        break :blk null;
    };
    try testing.expect(mem_test != null);
}
