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

const supported_regs = [_][]const u8{ "ax", "bx", "cx", "dx", "si", "di", "bp" };

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

pub const CompareError = error{
    RegisterMismatch,
    FlagsMismatch,
    RamMismatch,
};

pub fn compareFinal(ctx: *const Context, final: parser.CpuState) CompareError!void {
    inline for (supported_regs) |name| {
        const expected = @field(final.regs, name);
        if (expected) |exp| {
            const reg_id = register.fromString(name).?;
            const actual = ctx.getRegister(reg_id);
            if (actual != @as(u16, @truncate(exp)))
                return error.RegisterMismatch;
        }
    }

    if (final.regs.flags) |expected| {
        const actual = flagsToWord(ctx.flags);
        const exp: u16 = @truncate(expected);
        if ((actual & emulated_flags_mask) != (exp & emulated_flags_mask))
            return error.FlagsMismatch;
    }

    for (final.ram) |entry| {
        const addr = truncateAddr(entry[0]);
        const expected = @as(u8, @truncate(entry[1]));
        if (ctx.dataseg[addr] != expected)
            return error.RamMismatch;
    }
}
