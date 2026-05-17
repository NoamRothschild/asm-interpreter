const std = @import("std");
const Context = @import("../CPU/context.zig").Context;
const FlagsRegister = @import("../CPU/register.zig").FlagsRegister;
const register = @import("../parser/register.zig");
const parser = @import("parser.zig");

pub fn truncateAddr(addr: usize) u16 {
    return @truncate(addr);
}

pub fn flagsFromWord(word: u16) FlagsRegister {
    return .{
        .c = word & 1 != 0,
        .p = (word >> 2) & 1 != 0,
        .ac = (word >> 4) & 1 != 0,
        .z = (word >> 6) & 1 != 0,
        .s = (word >> 7) & 1 != 0,
        .t = (word >> 8) & 1 != 0,
        .i = (word >> 9) & 1 != 0,
        .d = (word >> 10) & 1 != 0,
        .o = (word >> 11) & 1 != 0,
    };
}

pub fn flagsToWord(flags: FlagsRegister) u16 {
    var word: u16 = 0;
    if (flags.c) word |= 1;
    if (flags.p) word |= 1 << 2;
    if (flags.ac) word |= 1 << 4;
    if (flags.z) word |= 1 << 6;
    if (flags.s) word |= 1 << 7;
    if (flags.t) word |= 1 << 8;
    if (flags.i) word |= 1 << 9;
    if (flags.d) word |= 1 << 10;
    if (flags.o) word |= 1 << 11;
    return word;
}

/// Flags the executor currently updates (parity and auxiliary carry are not modeled yet).
const emulated_flags_mask: u16 = (1 << 0) | (1 << 6) | (1 << 7) | (1 << 11);

const supported_regs = [_][]const u8{ "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" };

pub fn applyInitial(ctx: *Context, initial: parser.CpuState) void {
    @memset(&ctx.dataseg, 0);

    inline for (supported_regs) |name| {
        const value = @field(initial.regs, name);
        if (value) |v| {
            const reg_id = register.fromString(name).?;
            ctx.setRegister(reg_id, @truncate(v));
        }
    }

    if (initial.regs.flags) |flags| {
        ctx.flags = flagsFromWord(@truncate(flags));
    }

    for (initial.ram) |entry| {
        const addr = truncateAddr(entry[0]);
        ctx.dataseg[addr] = @truncate(entry[1]);
    }

    ctx.ip = 0;
}

pub const Mismatch = union(enum) {
    register: struct { name: []const u8, expected: u16, actual: u16 },
    flags: struct { expected: u16, actual: u16 },
    ram: struct { addr: usize, expected: u8, actual: u8 },
};

pub fn findMismatch(ctx: *const Context, final: parser.CpuState) ?Mismatch {
    inline for (supported_regs) |name| {
        const expected = @field(final.regs, name);
        if (expected) |exp| {
            const reg_id = register.fromString(name).?;
            const actual = ctx.getRegister(reg_id);
            const exp16: u16 = @truncate(exp);
            if (actual != exp16)
                return .{ .register = .{ .name = name, .expected = exp16, .actual = actual } };
        }
    }

    if (final.regs.flags) |expected| {
        const actual = flagsToWord(ctx.flags);
        const exp: u16 = @truncate(expected);
        const exp_masked = exp & emulated_flags_mask;
        const actual_masked = actual & emulated_flags_mask;
        if (actual_masked != exp_masked)
            return .{ .flags = .{ .expected = exp_masked, .actual = actual_masked } };
    }

    for (final.ram) |entry| {
        const addr = entry[0];
        const truncated = truncateAddr(addr);
        const expected = @as(u8, @truncate(entry[1]));
        const actual = ctx.dataseg[truncated];
        if (actual != expected)
            return .{ .ram = .{ .addr = addr, .expected = expected, .actual = actual } };
    }

    return null;
}

pub fn printMismatch(writer: anytype, mismatch: Mismatch) !void {
    switch (mismatch) {
        .register => |m| try writer.print(
            "register {s} expected=0x{x} got=0x{x}",
            .{ m.name, m.expected, m.actual },
        ),
        .flags => |m| try writer.print(
            "flags (C/Z/S/O) expected=0x{x} got=0x{x}",
            .{ m.expected, m.actual },
        ),
        .ram => |m| try writer.print(
            "ram [0x{x}] expected=0x{x} got=0x{x}",
            .{ m.addr, m.expected, m.actual },
        ),
    }
}

pub const CompareError = error{
    RegisterMismatch,
    FlagsMismatch,
    RamMismatch,
};

pub fn compareFinal(ctx: *const Context, final: parser.CpuState) CompareError!void {
    const m = findMismatch(ctx, final) orelse return;
    return switch (m) {
        .register => error.RegisterMismatch,
        .flags => error.FlagsMismatch,
        .ram => error.RamMismatch,
    };
}
