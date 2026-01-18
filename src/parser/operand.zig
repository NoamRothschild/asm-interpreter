const std = @import("std");
const testing = std.testing;
const register = @import("register.zig");
const RegisterIdentifier = register.RegisterIdentifier;
const IndexMode = @import("instruction.zig").IndexMode;
const Context = @import("../CPU/context.zig").Context;
const ParseError = @import("../errors.zig").ParseError;

pub const Operand = union(enum) {
    imm: u16,
    reg: RegisterIdentifier,
    mem: MemoryExpr,
    unverified_label: []const u8, // a temporary value that will either be replaced with imm later or result in an err
};

const MemExprPtrType = enum { unknown, byte_ptr, word_ptr };
const byte_ptr_str = "byte ptr";
const word_ptr_str = "word ptr";
const base_registers = [_][]const u8{ "bx", "bp" };
const index_registers = [_][]const u8{ "si", "di" };
pub const MemoryExpr = struct {
    base: ?RegisterIdentifier = null, // bx or bp
    index: ?RegisterIdentifier = null, // si or di
    displacement: u16 = 0,
    ptr_type: MemExprPtrType = .unknown,

    pub fn finalAddr(self: *const MemoryExpr, ctx: *const Context) u16 {
        var addr = self.displacement;
        addr +%= if (self.base != null) ctx.getRegister(self.base.?) else 0;
        addr +%= if (self.index != null) ctx.getRegister(self.index.?) else 0;
        return addr;
    }
};

fn tryParseInt(comptime T: type, s: []const u8, base: u8) OperandParseErrors!T {
    return std.fmt.parseInt(T, s, base) catch |e| switch (e) {
        error.Overflow => OperandParseErrors.ImmediateOutOfRange,
        error.InvalidCharacter => OperandParseErrors.InvalidExpression,
    };
}

// TODO: OR the parse errors with all the possible error sets
pub const OperandParseErrors = ParseError;

/// parses an operand.
/// returns `null` when raw_op.len == 0
/// fails if an operand was found, but was unable to be diagnosed, or
/// an error had occured while parsig after the operand type had been found.
pub fn parseOperand(allocator: std.mem.Allocator, raw_op: []const u8, mode: *IndexMode, named_offsets: ?*const std.StringHashMap(usize)) (OperandParseErrors || error{OutOfMemory})!?Operand {
    if (raw_op.len == 0) return null;

    const might_offset = try parseOffset(raw_op, named_offsets);
    if (might_offset) |imm| {
        return Operand{ .imm = imm };
    }

    const might_reg = register.fromString(raw_op);
    if (might_reg) |reg| {
        mode.* = if (reg.size() == ._8bit) ._8bit else ._16bit;
        return Operand{ .reg = reg };
    }

    const might_imm = try parseImmediate(raw_op);
    if (might_imm) |imm| {
        return Operand{ .imm = imm };
    }

    const might_mem_expr = try parseMemoryExpr(allocator, raw_op);
    if (might_mem_expr) |mem_expr| {
        if (mem_expr.ptr_type == .byte_ptr) {
            mode.* = ._8bit;
        } else if (mem_expr.ptr_type == .word_ptr) {
            mode.* = ._16bit;
        }
        return Operand{ .mem = mem_expr };
    }

    return Operand{ .unverified_label = try allocator.dupe(u8, raw_op) };
}

fn parseOffset(raw_op: []const u8, named_offsets: ?*const std.StringHashMap(usize)) OperandParseErrors!?u16 {
    if (named_offsets == null) return null;
    if (!std.mem.startsWith(u8, raw_op, "offset")) return null;
    const named_offset_str = std.mem.trim(u8, raw_op[6..], &std.ascii.whitespace);
    if (named_offsets.?.get(named_offset_str)) |imm_value|
        return @truncate(imm_value)
    else
        return OperandParseErrors.UnknownOffsetLabel;
}

fn parseImmediate(immediate: []const u8) OperandParseErrors!?u16 {
    var rvalue: isize = 0;
    if (immediate.len == 0)
        return null;

    const sign: bool = !(immediate[0] == '-');
    const imm = if (sign) immediate else immediate[1..];

    if (imm.len == 3 and imm[0] == imm[2] and imm[0] == '\'') {
        rvalue = imm[1];
    } else if (std.mem.startsWith(u8, imm, "0b")) {
        rvalue = try tryParseInt(isize, imm[2..], 2);
    } else if (std.mem.startsWith(u8, imm, "0x")) {
        rvalue = try tryParseInt(isize, imm[2..], 16);
    } else if ((imm[0] == '0' or imm[0] == '1') and imm[imm.len - 1] == 'b') {
        rvalue = try tryParseInt(isize, imm[0 .. imm.len - 1], 2);
    } else if (std.ascii.isHex(imm[0]) and imm[imm.len - 1] == 'h') {
        rvalue = try tryParseInt(isize, imm[0 .. imm.len - 1], 16);
    } else if (std.ascii.isDigit(imm[0]) and imm[imm.len - 1] == 'd') {
        rvalue = try tryParseInt(isize, imm[0 .. imm.len - 1], 10);
    } else {
        rvalue = std.fmt.parseInt(isize, imm, 10) catch |e| switch (e) {
            error.Overflow => return OperandParseErrors.ImmediateOutOfRange,
            error.InvalidCharacter => return null,
        };
    }
    rvalue *= if (sign) 1 else -1;

    return @bitCast(@as(i16, @truncate(rvalue)));
}

fn parseMemoryExpr(allocator: std.mem.Allocator, expr: []const u8) (OperandParseErrors || error{OutOfMemory})!?MemoryExpr {
    if (expr[0] != '[' or expr[expr.len - 1] != ']') {
        return null;
    }
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var body = std.mem.trim(u8, expr, "[]" ++ std.ascii.whitespace);
    // Normalize: first collapse "- " -> "-", then ensure space before every '-'
    const step1 = try std.mem.replaceOwned(u8, arena.allocator(), body, "- ", "-");
    const step2 = try std.mem.replaceOwned(u8, arena.allocator(), step1, "-", " -");
    body = step2;
    var out_expr = MemoryExpr{};

    if (std.mem.startsWith(u8, body, byte_ptr_str)) {
        out_expr.ptr_type = .byte_ptr;
        body = body[byte_ptr_str.len + 1 ..];
    } else if (std.mem.startsWith(u8, body, word_ptr_str)) {
        out_expr.ptr_type = .word_ptr;
        body = body[word_ptr_str.len + 1 ..];
    }

    var it = std.mem.tokenizeAny(u8, body, "+" ++ std.ascii.whitespace);
    outer: while (it.next()) |value| {
        inline for (base_registers) |reg| {
            if (std.mem.eql(u8, value, reg)) {
                out_expr.base = register.fromString(reg) orelse return OperandParseErrors.InvalidExpression;
                if (out_expr.base.?.size() == ._8bit) return OperandParseErrors.InvalidExpression;
                continue :outer;
            }
        }

        inline for (index_registers) |reg| {
            if (std.mem.eql(u8, value, reg)) {
                out_expr.index = register.fromString(reg) orelse return OperandParseErrors.InvalidExpression;
                if (out_expr.index.?.size() == ._8bit) return OperandParseErrors.InvalidExpression;
                continue :outer;
            }
        }

        out_expr.displacement +%= try parseImmediate(value) orelse return OperandParseErrors.InvalidEffectiveAddress;
    }

    return out_expr;
}

pub fn wrapIntImm(v: i16) u16 {
    return @bitCast(v);
}

pub fn valueOf(operand: Operand, ctx: *const Context) u16 {
    return switch (operand) {
        .imm => |v| v,
        .reg => |v| ctx.*.getRegister(v),
        .mem => |v| {
            const addr = v.finalAddr(ctx);

            const read_value = switch (v.ptr_type) {
                .unknown, .word_ptr => ctx.readWord(addr),
                .byte_ptr => @as(u16, ctx.dataseg[addr]),
            };

            return read_value;
        },
        .unverified_label => unreachable,
    };
}

test "parse immediate" {
    try testing.expectEqual(@as(u16, 0x9876), try parseImmediate("0x9876"));

    try testing.expectEqual(@as(u16, 0b10110111), try parseImmediate("0b10110111"));

    try testing.expectEqual(@as(u16, 12345), try parseImmediate("12345d"));

    try testing.expectEqual(wrapIntImm(-12345), try parseImmediate("-12345d"));

    try testing.expectEqual(@as(u16, 0x77), try parseImmediate("77h"));

    try testing.expectEqual(@as(u16, 0xad), try parseImmediate("adh"));

    try testing.expectEqual(@as(u16, 0b10101), try parseImmediate("10101b"));

    try testing.expectEqual(wrapIntImm(-12345), try parseImmediate("-12345"));

    try testing.expectEqual(@as(u16, 65535), try parseImmediate("65535"));

    try testing.expectEqual(wrapIntImm(-32768), try parseImmediate("-32768"));
}

test "parse memory expression" {
    try testing.expectEqual(null, try parseMemoryExpr(testing.allocator, "bx"));

    try testing.expectEqual(MemoryExpr{}, try parseMemoryExpr(testing.allocator, "[]"));

    try testing.expectEqual(MemoryExpr{
        .index = .{ .base = .si, .selector = .full },
        .ptr_type = .word_ptr,
    }, try parseMemoryExpr(testing.allocator, "[word ptr si]"));

    try testing.expectEqual(MemoryExpr{
        .displacement = 0,
    }, try parseMemoryExpr(testing.allocator, "[0]"));

    try testing.expectEqual(MemoryExpr{
        .base = .{ .base = .bx, .selector = .full },
    }, try parseMemoryExpr(testing.allocator, "[bx ]"));

    try testing.expectEqual(MemoryExpr{
        .index = .{ .base = .si, .selector = .full },
        .ptr_type = .byte_ptr,
    }, try parseMemoryExpr(testing.allocator, "[  byte ptr  si ]"));

    try testing.expectEqual(MemoryExpr{
        .index = .{ .base = .si, .selector = .full },
        .base = .{ .base = .bx, .selector = .full },
    }, try parseMemoryExpr(testing.allocator, "[si + bx]"));

    try testing.expectEqual(MemoryExpr{
        .index = .{ .base = .di, .selector = .full },
        .base = .{ .base = .bp, .selector = .full },
    }, try parseMemoryExpr(testing.allocator, "[di+bp]"));

    try testing.expectEqual(MemoryExpr{
        .index = .{ .base = .di, .selector = .full },
        .displacement = 0b1001,
    }, try parseMemoryExpr(testing.allocator, "[di + 1001b]"));

    try testing.expectEqual(MemoryExpr{
        .base = .{ .base = .bx, .selector = .full },
        .displacement = wrapIntImm(-3),
    }, try parseMemoryExpr(testing.allocator, "[bx-3]"));

    try testing.expectEqual(MemoryExpr{
        .index = .{ .base = .si, .selector = .full },
        .displacement = wrapIntImm(-0x12),
    }, try parseMemoryExpr(testing.allocator, "[si - 0x12]"));
}
