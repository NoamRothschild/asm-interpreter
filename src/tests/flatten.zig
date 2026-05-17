const std = @import("std");
const testing = std.testing;

const operand = @import("../parser/operand.zig");
const parser_root = @import("../parser/root.zig");
const register = @import("../parser/register.zig");
const context = @import("context.zig");

pub const segment_prefixes = [_][]const u8{ "cs:", "ds:", "es:", "ss:" };

pub const Segment = enum { cs, ds, es, ss };

const segment_map = [_]struct { prefix: []const u8, segment: Segment }{
    .{ .prefix = "cs:", .segment = .cs },
    .{ .prefix = "ds:", .segment = .ds },
    .{ .prefix = "es:", .segment = .es },
    .{ .prefix = "ss:", .segment = .ss },
};

pub const Regs = @import("parser.zig").Regs;
pub const Ram = @import("parser.zig").Ram;
pub const CpuState = @import("parser.zig").CpuState;
pub const TestEntry = @import("parser.zig").TestEntry;

pub fn detectSegmentInName(name: []const u8) ?Segment {
    const l_bracket = std.mem.indexOfScalar(u8, name, '[') orelse return null;
    const r_bracket = std.mem.indexOfScalar(u8, name, ']') orelse return null;
    const inner = name[l_bracket + 1 .. r_bracket];
    for (segment_map) |entry| {
        if (std.mem.indexOf(u8, inner, entry.prefix) != null) {
            return entry.segment;
        }
    }
    return null;
}

/// aligns test names to the format expected by our interpreter
/// example: byte [ds:bx] -> [byte ptr bx]
pub fn alignTestName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
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

fn segmentBase(regs: Regs, segment: Segment) u16 {
    const raw: usize = switch (segment) {
        .cs => regs.cs orelse 0,
        .ds => regs.ds orelse 0,
        .ss => regs.ss orelse 0,
        .es => regs.es orelse 0,
    };
    return @truncate(raw << 4);
}

fn regFromState(regs: Regs, id: register.RegisterIdentifier) u16 {
    const raw: usize = switch (id.base) {
        .ax => regs.ax,
        .bx => regs.bx,
        .cx => regs.cx,
        .dx => regs.dx,
        .si => regs.si,
        .di => regs.di,
        .bp => regs.bp,
        .sp => regs.sp,
    } orelse 0;
    const value: u16 = @truncate(raw);
    return switch (id.selector) {
        .low => value & 0xFF,
        .high => value >> 8,
        .full => value,
    };
}

fn flatEffectiveAddr(mem: operand.MemoryExpr, regs: Regs) u16 {
    var addr = mem.displacement;
    if (mem.base) |base| addr +%= regFromState(regs, base);
    if (mem.index) |index| addr +%= regFromState(regs, index);
    return addr;
}

fn findMemoryOperand(inst: parser_root.Instruction) ?operand.MemoryExpr {
    if (inst.left_operand) |op| {
        if (op == .mem) return op.mem;
    }
    if (inst.right_operand) |op| {
        if (op == .mem) return op.mem;
    }
    return null;
}

fn remapOperandRam(state: *CpuState, segmented: u16, flat: u16, width: usize) void {
    for (state.ram) |*entry| {
        const truncated = context.truncateAddr(entry[0]);
        if (truncated == segmented) {
            entry[0] = flat;
        } else if (width == 2 and truncated == segmented +% 1) {
            entry[0] = flat +% 1;
        }
    }
}

/// Strips segment overrides from the mnemonic and rewrites operand RAM to flat addresses.
pub fn flattenTestEntry(allocator: std.mem.Allocator, entry: *TestEntry) !void {
    const segment = detectSegmentInName(entry.name);
    entry.name = try alignTestName(allocator, entry.name);
    const segment_val = segment orelse return;

    var parser_ctx = parser_root.init(allocator, null);
    const inst = try parser_root.parseInstruction(&parser_ctx, entry.name);

    const mem = findMemoryOperand(inst) orelse return;
    const flat = flatEffectiveAddr(mem, entry.initial.regs);
    const segmented = flat +% segmentBase(entry.initial.regs, segment_val);
    const width: usize = if (mem.ptr_type == .word_ptr) 2 else 1;

    remapOperandRam(&entry.initial, segmented, flat, width);
    remapOperandRam(&entry.final, segmented, flat, width);
}

test "detect segment in memory operand" {
    try testing.expectEqual(Segment.ss, detectSegmentInName("add byte [ss:bp+si+5AFBh], al").?);
    try testing.expectEqual(Segment.ds, detectSegmentInName("mov word [ds:bx], ax").?);
    try testing.expect(detectSegmentInName("mov ax, bx") == null);
}
