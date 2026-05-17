const std = @import("std");

const Context = @import("context.zig").Context;
const Register = @import("register.zig").Register;
const FlagsRegister = @import("register.zig").FlagsRegister;
const Instruction = @import("../parser/instruction.zig").Instruction;
const InstructionType = @import("../parser/instruction.zig").InstructionType;
const Operand = @import("../parser/operand.zig").Operand;
const registerFromString = @import("../parser/register.zig").fromString;
const valueOf = @import("../parser/operand.zig").valueOf;
const parser_root = @import("../parser/root.zig");
const testing = std.testing;
const ExecError = @import("../errors.zig").ExecError;

pub fn executeInstruction(ctx: *Context) ExecError!void {
    defer ctx.*.ip +%= 1;
    errdefer ctx.*.ip -%= 1; // don't move ip forward on error
    const inst = ctx.instructions[ctx.ip];
    var exit: bool = true;

    // instructions with no operands:
    switch (inst.inst) {
        .hlt => ctx.*.ip -%= 1,
        else => exit = false,
    }
    if (exit) return;
    exit = true;

    // instructions with only left operand:
    const lhs = inst.left_operand orelse return ExecError.MissingOperand;
    switch (inst.inst) {
        .inc, .dec, .not, .neg => {
            switch (inst.indexing_mode) {
                ._8bit => executeUnary8(ctx, inst.inst, lhs),
                ._16bit, .unknown => executeUnary16(ctx, inst.inst, lhs),
            }
        },
        .jmp, .je, .jne, .jg, .jl, .ja, .jb, .jge, .jle, .jae, .jbe, .jc, .jnc, .jz, .jnz, .jcxz, .jnbe, .jnae => {
            if (shouldJump(ctx, inst.inst)) {
                const target_addr = valueOf(lhs, ctx);
                ctx.*.ip = target_addr;
                ctx.*.ip -%= 1;
            }
        },
        .loop => {
            ctx.*.cx.value -%= 1;
            if (ctx.*.cx.getValue() != 0)
                ctx.*.ip = lhs.imm -% 1;
        },
        else => exit = false,
    }
    if (exit) return;

    const rhs = inst.right_operand orelse return ExecError.MissingOperand;
    switch (inst.indexing_mode) {
        ._8bit => executeBinary8(ctx, inst, lhs, rhs),
        ._16bit, .unknown => executeBinary16(ctx, inst, lhs, rhs),
    }
}

fn executeUnary8(ctx: *Context, inst: InstructionType, lhs: Operand) void {
    switch (inst) {
        .inc => {
            const lval = byteVal(lhs, ctx);
            const res = lval +% 1;
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
            ctx.flags.o = @as(i8, @bitCast(lval)) == 0x7F;
        },
        .dec => {
            const lval = byteVal(lhs, ctx);
            const res = lval -% 1;
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
            ctx.flags.o = @as(i8, @bitCast(lval)) == -128;
        },
        .not => {
            const res = ~byteVal(lhs, ctx);
            store(ctx, lhs, res);
        },
        .neg => {
            const val = byteVal(lhs, ctx);
            const res = 0 -% val;
            store(ctx, lhs, res);
            ctx.flags.c = val != 0;
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
            ctx.flags.o = val == 0x80;
        },
        else => {},
    }
}

fn executeUnary16(ctx: *Context, inst: InstructionType, lhs: Operand) void {
    switch (inst) {
        .inc => {
            const lval = valueOf(lhs, ctx);
            const res = lval +% 1;
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
            ctx.flags.o = @as(i16, @bitCast(lval)) == 0x7FFF;
        },
        .dec => {
            const lval = valueOf(lhs, ctx);
            const res = lval -% 1;
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
            ctx.flags.o = @as(i16, @bitCast(lval)) == -32768;
        },
        .not => {
            const res = ~valueOf(lhs, ctx);
            store(ctx, lhs, res);
        },
        .neg => {
            const val = valueOf(lhs, ctx);
            const res = 0 -% val;
            store(ctx, lhs, res);
            ctx.flags.c = val != 0;
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
            ctx.flags.o = val == 0x8000;
        },
        else => {},
    }
}

fn executeBinary8(ctx: *Context, inst: Instruction, lhs: Operand, rhs: Operand) void {
    switch (inst.inst) {
        .mov => store(ctx, lhs, byteVal(rhs, ctx)),
        .lea => {
            const addr = rhs.mem.finalAddr(ctx);
            store(ctx, lhs, addr);
        },
        .@"and" => {
            const res = byteVal(lhs, ctx) & byteVal(rhs, ctx);
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
            ctx.flags.c = false;
            ctx.flags.o = false;
        },
        .@"or" => {
            const res = byteVal(lhs, ctx) | byteVal(rhs, ctx);
            store(ctx, lhs, res);
            ctx.flags.c = false;
            ctx.flags.o = false;
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
        },
        .xor => {
            const res = byteVal(lhs, ctx) ^ byteVal(rhs, ctx);
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
            ctx.flags.c = false;
            ctx.flags.o = false;
        },
        .add => {
            const lval = byteVal(lhs, ctx);
            const rval = byteVal(rhs, ctx);
            const res = lval +% rval;
            store(ctx, lhs, res);
            setAddFlags8(&ctx.flags, lval, rval, res);
        },
        .sub => {
            const lval = byteVal(lhs, ctx);
            const rval = byteVal(rhs, ctx);
            const res = lval -% rval;
            store(ctx, lhs, res);
            setSubFlags8(&ctx.flags, lval, rval, res);
        },
        .cmp => {
            const lval = byteVal(lhs, ctx);
            const rval = byteVal(rhs, ctx);
            const res = lval -% rval;
            setSubFlags8(&ctx.flags, lval, rval, res);
        },
        .@"test" => {
            const res = byteVal(lhs, ctx) & byteVal(rhs, ctx);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 7) != 0;
            ctx.flags.c = false;
            ctx.flags.o = false;
        },
        .shl, .sal => execShift8(ctx, lhs, rhs, .shl),
        .shr => execShift8(ctx, lhs, rhs, .shr),
        .sar => execShift8(ctx, lhs, rhs, .sar),
        .rol => execRotate8(ctx, lhs, rhs, .rol),
        .ror => execRotate8(ctx, lhs, rhs, .ror),
        .rcl => execRotate8(ctx, lhs, rhs, .rcl),
        .rcr => execRotate8(ctx, lhs, rhs, .rcr),
        else => {},
    }
}

fn executeBinary16(ctx: *Context, inst: Instruction, lhs: Operand, rhs: Operand) void {
    switch (inst.inst) {
        .mov => store(ctx, lhs, valueOf(rhs, ctx)),
        .lea => {
            const addr = rhs.mem.finalAddr(ctx);
            store(ctx, lhs, addr);
        },
        .@"and" => {
            const res = valueOf(lhs, ctx) & valueOf(rhs, ctx);
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
            ctx.flags.c = false;
            ctx.flags.o = false;
        },
        .@"or" => {
            const res = valueOf(lhs, ctx) | valueOf(rhs, ctx);
            store(ctx, lhs, res);
            ctx.flags.c = false;
            ctx.flags.o = false;
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
        },
        .xor => {
            const res = valueOf(lhs, ctx) ^ valueOf(rhs, ctx);
            store(ctx, lhs, res);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
            ctx.flags.c = false;
            ctx.flags.o = false;
        },
        .add => {
            const lval = valueOf(lhs, ctx);
            const rval = valueOf(rhs, ctx);
            const res = lval +% rval;
            store(ctx, lhs, res);
            setAddFlags16(&ctx.flags, lval, rval, res);
        },
        .sub => {
            const lval = valueOf(lhs, ctx);
            const rval = valueOf(rhs, ctx);
            const res = lval -% rval;
            store(ctx, lhs, res);
            setSubFlags16(&ctx.flags, lval, rval, res);
        },
        .cmp => {
            const lval = valueOf(lhs, ctx);
            const rval = valueOf(rhs, ctx);
            const res = lval -% rval;
            setSubFlags16(&ctx.flags, lval, rval, res);
        },
        .@"test" => {
            const res = valueOf(lhs, ctx) & valueOf(rhs, ctx);
            ctx.flags.z = res == 0;
            ctx.flags.s = (res >> 15) != 0;
            ctx.flags.c = false;
            ctx.flags.o = false;
        },
        .shl, .sal => execShift16(ctx, lhs, rhs, .shl),
        .shr => execShift16(ctx, lhs, rhs, .shr),
        .sar => execShift16(ctx, lhs, rhs, .sar),
        .rol => execRotate16(ctx, lhs, rhs, .rol),
        .ror => execRotate16(ctx, lhs, rhs, .ror),
        .rcl => execRotate16(ctx, lhs, rhs, .rcl),
        .rcr => execRotate16(ctx, lhs, rhs, .rcr),
        else => {},
    }
}

fn byteVal(op: Operand, ctx: *const Context) u8 {
    return @truncate(valueOf(op, ctx));
}

fn setAddFlags8(flags: *FlagsRegister, lval: u8, rval: u8, res: u8) void {
    flags.c = res < lval;
    flags.z = res == 0;
    flags.s = (res >> 7) != 0;
    const ls: i8 = @bitCast(lval);
    const rs: i8 = @bitCast(rval);
    const rs_res: i8 = @bitCast(res);
    flags.o = (ls > 0 and rs > 0 and rs_res < 0) or (ls < 0 and rs < 0 and rs_res > 0);
}

fn setSubFlags8(flags: *FlagsRegister, lval: u8, rval: u8, res: u8) void {
    flags.c = lval < rval;
    flags.z = res == 0;
    flags.s = (res >> 7) != 0;
    const ls: i8 = @bitCast(lval);
    const rs: i8 = @bitCast(rval);
    const rs_res: i8 = @bitCast(res);
    flags.o = (ls > 0 and rs < 0 and rs_res < 0) or (ls < 0 and rs > 0 and rs_res > 0);
}

fn setAddFlags16(flags: *FlagsRegister, lval: u16, rval: u16, res: u16) void {
    flags.c = res < lval;
    flags.z = res == 0;
    flags.s = (res >> 15) != 0;
    const ls: i16 = @bitCast(lval);
    const rs: i16 = @bitCast(rval);
    const rs_res: i16 = @bitCast(res);
    flags.o = (ls > 0 and rs > 0 and rs_res < 0) or (ls < 0 and rs < 0 and rs_res > 0);
}

fn setSubFlags16(flags: *FlagsRegister, lval: u16, rval: u16, res: u16) void {
    flags.c = lval < rval;
    flags.z = res == 0;
    flags.s = (res >> 15) != 0;
    const ls: i16 = @bitCast(lval);
    const rs: i16 = @bitCast(rval);
    const rs_res: i16 = @bitCast(res);
    flags.o = (ls > 0 and rs < 0 and rs_res < 0) or (ls < 0 and rs > 0 and rs_res > 0);
}

const ShiftKind = enum { shl, shr, sar };

fn execShift8(ctx: *Context, lhs: Operand, rhs: Operand, kind: ShiftKind) void {
    const lval = byteVal(lhs, ctx);
    const shift_count = @as(u4, @truncate(valueOf(rhs, ctx) & 0x1F));
    const res: u8 = switch (kind) {
        .shl => blk: {
            var v: u8 = lval;
            var i: u4 = 0;
            while (i < shift_count) : (i += 1) {
                ctx.flags.c = (v >> 7) != 0;
                v <<= 1;
            }
            break :blk v;
        },
        .shr => blk: {
            var v: u8 = lval;
            var i: u4 = 0;
            while (i < shift_count) : (i += 1) {
                ctx.flags.c = (v & 1) != 0;
                v >>= 1;
            }
            break :blk v;
        },
        .sar => blk: {
            var v: i8 = @bitCast(lval);
            var i: u4 = 0;
            while (i < shift_count) : (i += 1) {
                ctx.flags.c = (@as(u8, @bitCast(v)) & 1) != 0;
                v >>= 1;
            }
            break :blk @as(u8, @bitCast(v));
        },
    };
    store(ctx, lhs, res);
    if (shift_count > 0) {
        ctx.flags.z = res == 0;
        ctx.flags.s = (res >> 7) != 0;
        switch (kind) {
            .shl => ctx.flags.o = (shift_count == 1) and ((lval >> 7) != (res >> 7)),
            .shr => ctx.flags.o = (shift_count == 1) and ((lval >> 7) != 0),
            .sar => ctx.flags.o = false,
        }
    }
}

fn execShift16(ctx: *Context, lhs: Operand, rhs: Operand, kind: ShiftKind) void {
    const lval = valueOf(lhs, ctx);
    const shift_count = @as(u4, @truncate(valueOf(rhs, ctx) & 0xF));
    const res: u16 = switch (kind) {
        .shl => lval << shift_count,
        .shr => lval >> shift_count,
        .sar => @bitCast(@as(i16, @bitCast(lval)) >> shift_count),
    };
    store(ctx, lhs, res);
    if (shift_count > 0) {
        switch (kind) {
            .shl => {
                const rs: u4 = @as(u4, @truncate(15 - (shift_count - 1)));
                ctx.flags.c = (lval >> rs) != 0;
                ctx.flags.z = res == 0;
                ctx.flags.s = (res >> 15) != 0;
                ctx.flags.o = (shift_count == 1) and ((lval >> 15) != (res >> 15));
            },
            .shr => {
                ctx.flags.c = (lval >> (shift_count - 1)) & 1 != 0;
                ctx.flags.z = res == 0;
                ctx.flags.s = (res >> 15) != 0;
                ctx.flags.o = (shift_count == 1) and ((lval >> 15) != 0);
            },
            .sar => {
                ctx.flags.c = (lval >> (shift_count - 1)) & 1 != 0;
                ctx.flags.z = res == 0;
                ctx.flags.s = (res >> 15) != 0;
                ctx.flags.o = false;
            },
        }
    }
}

const RotateKind = enum { rol, ror, rcl, rcr };

fn execRotate8(ctx: *Context, lhs: Operand, rhs: Operand, kind: RotateKind) void {
    const lval = byteVal(lhs, ctx);
    const shift_count = @as(u5, @truncate(valueOf(rhs, ctx) & 0x1F));
    if (shift_count == 0) return;

    const res: u8 = switch (kind) {
        .rol => rol8(lval, shift_count),
        .ror => ror8(lval, shift_count),
        .rcl => blk: {
            const r = rcl8(lval, shift_count, ctx.flags.c);
            ctx.flags.c = r.carry;
            if (shift_count == 1) ctx.flags.o = ((r.value >> 7) & 1) != @intFromBool(r.carry);
            break :blk r.value;
        },
        .rcr => blk: {
            const r = rcr8(lval, shift_count, ctx.flags.c);
            ctx.flags.c = r.carry;
            if (shift_count == 1) ctx.flags.o = ((r.value >> 7) != 0) != r.carry;
            break :blk r.value;
        },
    };
    store(ctx, lhs, res);
    switch (kind) {
        .rol, .ror => {
            const eff = shift_count % 8;
            if (eff == 0) return;
            const c_from: u3 = switch (kind) {
                .rol => if (eff == 0) 7 else @as(u3, @truncate(7 - (eff - 1))),
                .ror => if (eff == 0) 0 else @as(u3, @truncate(eff - 1)),
                else => unreachable,
            };
            ctx.flags.c = ((lval >> c_from) & 1) != 0;
            if (shift_count == 1) ctx.flags.o = ((res >> 7) & 1) != @intFromBool(ctx.flags.c);
        },
        .rcl, .rcr => {},
    }
}

fn execRotate16(ctx: *Context, lhs: Operand, rhs: Operand, kind: RotateKind) void {
    const lval = valueOf(lhs, ctx);
    const shift_count = @as(u5, @truncate(valueOf(rhs, ctx) & 0x1F));
    if (shift_count == 0) return;

    const res: u16 = switch (kind) {
        .rol => rol16(lval, shift_count),
        .ror => ror16(lval, shift_count),
        .rcl => blk: {
            const r = rcl16(lval, shift_count, ctx.flags.c);
            ctx.flags.c = r.carry;
            if (shift_count == 1) ctx.flags.o = ((r.value >> 15) & 1) != @intFromBool(r.carry);
            break :blk r.value;
        },
        .rcr => blk: {
            const r = rcr16(lval, shift_count, ctx.flags.c);
            ctx.flags.c = r.carry;
            if (shift_count == 1) ctx.flags.o = ((r.value >> 15) != 0) != r.carry;
            break :blk r.value;
        },
    };
    store(ctx, lhs, res);
    switch (kind) {
        .rol, .ror => {
            const eff: u4 = @truncate(shift_count % 16);
            const c_from: u4 = switch (kind) {
                .rol => if (eff == 0) 15 else @as(u4, @truncate(15 - (eff - 1))),
                .ror => if (eff == 0) 0 else @as(u4, @truncate(eff - 1)),
                else => unreachable,
            };
            ctx.flags.c = ((lval >> c_from) & 1) != 0;
            if (shift_count == 1) ctx.flags.o = ((res >> 15) & 1) != @intFromBool(ctx.flags.c);
        },
        .rcl, .rcr => {},
    }
}

fn rol8(value: u8, count: u5) u8 {
    const sc: u3 = @truncate(count % 8);
    if (sc == 0) return value;
    const right: u3 = @truncate(7 - (sc - 1));
    return (value << sc) | (value >> right);
}

fn ror8(value: u8, count: u5) u8 {
    const sc: u3 = @truncate(count % 8);
    if (sc == 0) return value;
    const left: u3 = @truncate(7 - (sc - 1));
    return (value >> sc) | (value << left);
}

const RotateResult8 = struct { value: u8, carry: bool };

fn rcl8(value: u8, count: u5, carry: bool) RotateResult8 {
    var result = value;
    var c = carry;
    const shift_count = count % 9;
    var i: u5 = 0;
    while (i < shift_count) : (i += 1) {
        const new_carry = (result >> 7) != 0;
        result = (result << 1) | @as(u8, @intFromBool(c));
        c = new_carry;
    }
    return .{ .value = result, .carry = c };
}

fn rcr8(value: u8, count: u5, carry: bool) RotateResult8 {
    var result = value;
    var c = carry;
    const shift_count = count % 9;
    var i: u5 = 0;
    while (i < shift_count) : (i += 1) {
        const new_carry = (result & 1) != 0;
        result = (result >> 1) | (@as(u8, @intFromBool(c)) << 7);
        c = new_carry;
    }
    return .{ .value = result, .carry = c };
}

fn rol16(value: u16, count: u5) u16 {
    if (count == 0) return value;
    const sc: u4 = @truncate(count % 16);
    if (sc == 0) return value;
    const right: u4 = @truncate(15 - (sc - 1));
    return (value << sc) | (value >> right);
}

fn ror16(value: u16, count: u5) u16 {
    if (count == 0) return value;
    const sc: u4 = @truncate(count % 16);
    if (sc == 0) return value;
    const left: u4 = @truncate(15 - (sc - 1));
    return (value >> sc) | (value << left);
}

const RotateResult16 = struct { value: u16, carry: bool };

fn rcl16(value: u16, count: u5, carry: bool) RotateResult16 {
    if (count == 0) return .{ .value = value, .carry = carry };
    var result = value;
    var c = carry;
    const shift_count = count % 17;
    var i: u5 = 0;
    while (i < shift_count) : (i += 1) {
        const new_carry = (result >> 15) != 0;
        result = (result << 1) | (@as(u16, @intFromBool(c)));
        c = new_carry;
    }
    return .{ .value = result, .carry = c };
}

fn rcr16(value: u16, count: u5, carry: bool) RotateResult16 {
    if (count == 0) return .{ .value = value, .carry = carry };
    var result = value;
    var c = carry;
    const shift_count = count % 17;
    var i: u5 = 0;
    while (i < shift_count) : (i += 1) {
        const new_carry = (result & 1) != 0;
        result = (result >> 1) | (@as(u16, @intFromBool(c)) << 15);
        c = new_carry;
    }
    return .{ .value = result, .carry = c };
}

fn shouldJump(ctx: *Context, inst: InstructionType) bool {
    return switch (inst) {
        .jmp => true,
        .je, .jz => ctx.flags.z,
        .jne, .jnz => !ctx.flags.z,
        .jg, .jnle => !ctx.flags.z and (ctx.flags.s == ctx.flags.o),
        .jl, .jnge => ctx.flags.s != ctx.flags.o,
        .ja, .jnbe => !ctx.flags.c and !ctx.flags.z,
        .jb, .jnae, .jc => ctx.flags.c,
        .jge, .jnl => ctx.flags.s == ctx.flags.o,
        .jle, .jng => ctx.flags.z or (ctx.flags.s != ctx.flags.o),
        .jae, .jnc => !ctx.flags.c,
        .jbe => ctx.flags.c or ctx.flags.z,
        .jcxz => ctx.getRegister(registerFromString("cx").?) == 0,
        else => false,
    };
}

fn store(ctx: *Context, out_operand: Operand, value: u16) void {
    switch (out_operand) {
        .reg => |v| ctx.setRegister(v, value),
        .mem => |v| {
            switch (v.ptr_type) {
                .byte_ptr => ctx.dataseg[v.finalAddr(ctx)] = @as(u8, @truncate(value)),
                .word_ptr => ctx.writeWord(v.finalAddr(ctx), value),
                .unknown => unreachable,
            }
        },
        else => {},
    }
}

fn initTestCtx() Context {
    return Context{
        .ax = .{ .value = 0 },
        .bx = .{ .value = 0 },
        .cx = .{ .value = 0 },
        .dx = .{ .value = 0 },
        .si = .{ .value = 0 },
        .di = .{ .value = 0 },
        .bp = .{ .value = 0 },
        .sp = .{ .value = 0 },
        .ip = 0,
        .flags = std.mem.zeroes(FlagsRegister),
        .dataseg = [_]u8{0} ** 65536,
        .instructions = &[_]parser_root.Instruction{},
    };
}

fn resetCtx(ctx: *Context) void {
    ctx.*.ax.value = 0;
    ctx.*.bx.value = 0;
    ctx.*.cx.value = 0;
    ctx.*.dx.value = 0;
    ctx.*.si.value = 0;
    ctx.*.di.value = 0;
    ctx.*.bp.value = 0;
    ctx.*.sp.value = 0;
    ctx.ip = 0;
    ctx.flags = std.mem.zeroes(FlagsRegister);
    @memset(&ctx.dataseg, 0);
}

fn parseInst(s: []const u8) !parser_root.Instruction {
    var parser = parser_root.init(testing.allocator, null);
    return try parser_root.parseInstruction(&parser, s);
}

test "executor mov/lea" {
    var ctx = initTestCtx();

    resetCtx(&ctx);
    const inst1 = try parseInst("mov ax, 0x1234");
    ctx.instructions = &[_]parser_root.Instruction{inst1};
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x1234), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst2 = try parseInst("mov [bx], ax");
    ctx.instructions = &[_]parser_root.Instruction{inst2};
    ctx.setRegister(registerFromString("ax").?, 0xBEEF);
    ctx.setRegister(registerFromString("bx").?, 0x0100);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xBEEF), ctx.readWord(0x0100));

    resetCtx(&ctx);
    const inst3 = try parseInst("mov dx, [bx]");
    ctx.instructions = &[_]parser_root.Instruction{inst3};
    ctx.setRegister(registerFromString("bx").?, 0x0100);
    ctx.writeWord(0x0100, 0xCAFE);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xCAFE), ctx.getRegister(registerFromString("dx").?));

    resetCtx(&ctx);
    const inst4 = try parseInst("lea bx, [bp+si+4]");
    ctx.instructions = &[_]parser_root.Instruction{inst4};
    ctx.setRegister(registerFromString("bp").?, 3);
    ctx.setRegister(registerFromString("si").?, 5);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 12), ctx.getRegister(registerFromString("bx").?));
}

test "executor logic and/test/or/xor/not" {
    var ctx = initTestCtx();

    resetCtx(&ctx);
    const inst1 = try parseInst("and ax, 0x0F0F");
    ctx.instructions = &[_]parser_root.Instruction{inst1};
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x0000), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.z);
    try testing.expect(!ctx.flags.c and !ctx.flags.o);

    resetCtx(&ctx);
    const inst2 = try parseInst("test ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst2};
    ctx.setRegister(registerFromString("ax").?, 2);
    try executeInstruction(&ctx);
    try testing.expect(ctx.flags.z);

    resetCtx(&ctx);
    const inst3 = try parseInst("or ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst3};
    ctx.setRegister(registerFromString("ax").?, 0);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 1), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst4 = try parseInst("xor ax, 0xFFFF");
    ctx.instructions = &[_]parser_root.Instruction{inst4};
    ctx.setRegister(registerFromString("ax").?, 0x00FF);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xFF00), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst5 = try parseInst("not ax");
    ctx.instructions = &[_]parser_root.Instruction{inst5};
    ctx.setRegister(registerFromString("ax").?, 0x0F0F);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xF0F0), ctx.getRegister(registerFromString("ax").?));
}

test "executor inc/dec/neg" {
    var ctx = initTestCtx();

    resetCtx(&ctx);
    const inst1 = try parseInst("inc ax");
    ctx.instructions = &[_]parser_root.Instruction{inst1};
    ctx.setRegister(registerFromString("ax").?, 0x7FFF);
    ctx.flags.c = true;
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x8000), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.o);
    try testing.expect(ctx.flags.c);

    resetCtx(&ctx);
    const inst2 = try parseInst("dec ax");
    ctx.instructions = &[_]parser_root.Instruction{inst2};
    ctx.setRegister(registerFromString("ax").?, 0);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xFFFF), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst3 = try parseInst("neg ax");
    ctx.instructions = &[_]parser_root.Instruction{inst3};
    ctx.setRegister(registerFromString("ax").?, 1);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xFFFF), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.c);
}

test "executor add/sub/cmp" {
    var ctx = initTestCtx();

    resetCtx(&ctx);
    const inst1 = try parseInst("add ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst1};
    ctx.setRegister(registerFromString("ax").?, 0xFFFF);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x0000), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.c);

    resetCtx(&ctx);
    const inst2 = try parseInst("sub ax, 2");
    ctx.instructions = &[_]parser_root.Instruction{inst2};
    ctx.setRegister(registerFromString("ax").?, 1);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xFFFF), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.c);

    resetCtx(&ctx);
    const inst3 = try parseInst("cmp ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst3};
    ctx.setRegister(registerFromString("ax").?, 1);
    try executeInstruction(&ctx);
    try testing.expect(ctx.flags.z);
}

test "executor shifts and rotates" {
    var ctx = initTestCtx();

    resetCtx(&ctx);
    const inst1 = try parseInst("shl ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst1};
    ctx.setRegister(registerFromString("ax").?, 0x8001);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x0002), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.c);

    resetCtx(&ctx);
    const inst2 = try parseInst("shr ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst2};
    ctx.setRegister(registerFromString("ax").?, 0x0001);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x0000), ctx.getRegister(registerFromString("ax").?));
    try testing.expect(ctx.flags.c);

    resetCtx(&ctx);
    const inst3 = try parseInst("sar ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst3};
    ctx.setRegister(registerFromString("ax").?, 0x8001);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xC000), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst4 = try parseInst("rol ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst4};
    ctx.setRegister(registerFromString("ax").?, 0x8001);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x0003), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst5 = try parseInst("ror ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst5};
    ctx.setRegister(registerFromString("ax").?, 0x0001);
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0x8000), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst6 = try parseInst("rcl ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst6};
    ctx.setRegister(registerFromString("ax").?, 0x7FFF);
    ctx.flags.c = true;
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xFFFF), ctx.getRegister(registerFromString("ax").?));

    resetCtx(&ctx);
    const inst7 = try parseInst("rcr ax, 1");
    ctx.instructions = &[_]parser_root.Instruction{inst7};
    ctx.setRegister(registerFromString("ax").?, 0x8000);
    ctx.flags.c = true;
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(u16, 0xC000), ctx.getRegister(registerFromString("ax").?));
}

test "executor jumps" {
    var ctx = initTestCtx();

    resetCtx(&ctx);
    const inst1 = try parseInst("jmp 3");
    ctx.instructions = &[_]parser_root.Instruction{inst1};
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(usize, 3), ctx.ip);

    resetCtx(&ctx);
    const inst2 = try parseInst("je 5");
    ctx.instructions = &[_]parser_root.Instruction{inst2};
    ctx.flags.z = true;
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(usize, 5), ctx.ip);

    resetCtx(&ctx);
    const inst3 = try parseInst("jnc 2");
    ctx.instructions = &[_]parser_root.Instruction{inst3};
    ctx.flags.c = false;
    try executeInstruction(&ctx);
    try testing.expectEqual(@as(usize, 2), ctx.ip);
}
