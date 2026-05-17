const std = @import("std");
const parser = @import("../parser/root.zig");
const Register = @import("register.zig").Register;
const FlagsRegister = @import("register.zig").FlagsRegister;
const RegisterIdentifier = @import("../parser/register.zig").RegisterIdentifier;
const BaseRegister = @import("../parser/register.zig").BaseRegister;

// NOTE: we could start code execution at the label "_start"'s index instead of 0

// TODO: translate `offset of` to an index inside dataseg
pub const Context = struct {
    ax: Register = Register{ .value = undefined },
    bx: Register = Register{ .value = undefined },
    cx: Register = Register{ .value = undefined },
    dx: Register = Register{ .value = undefined },
    si: Register = Register{ .value = undefined },
    di: Register = Register{ .value = undefined },
    bp: Register = Register{ .value = undefined },
    sp: Register = Register{ .value = undefined },
    ip: usize, // the index into the instruction list
    flags: FlagsRegister = std.mem.zeroes(FlagsRegister),

    dataseg: [65536]u8,
    instructions: []const parser.Instruction,

    pub fn getRegister(self: *const Context, reg_id: RegisterIdentifier) u16 {
        const base_reg = self.getBaseRegister(reg_id.base);
        return base_reg.get(reg_id.selector);
    }

    pub fn setRegister(self: *Context, reg_id: RegisterIdentifier, value: u16) void {
        const base_reg = self.getBaseRegisterPtr(reg_id.base);
        base_reg.set(reg_id.selector, value);
    }

    fn getBaseRegisterPtr(self: *Context, base: BaseRegister) *Register {
        return switch (base) {
            .ax => &self.ax,
            .bx => &self.bx,
            .cx => &self.cx,
            .dx => &self.dx,
            .si => &self.si,
            .di => &self.di,
            .bp => &self.bp,
            .sp => &self.sp,
        };
    }

    fn getBaseRegister(self: *const Context, base: BaseRegister) Register {
        return Context.getBaseRegisterPtr(@constCast(self), base).*;
    }

    pub fn readWord(self: *const Context, addr: u16) u16 {
        const idx: usize = addr;
        const arr_ptr_const: *const [2]u8 = @ptrCast(&self.dataseg[idx]);
        return std.mem.readInt(u16, arr_ptr_const, .little);
    }

    pub fn writeWord(self: *Context, addr: u16, word: u16) void {
        const idx: usize = addr;
        const arr_ptr = @as(*[2]u8, @ptrCast(&self.dataseg[idx]));
        std.mem.writeInt(u16, arr_ptr, word, .little);
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{{ ax = 0x{x}, bx = 0x{x}, cx = 0x{x}, dx = 0x{x}, si = 0x{x}, di = 0x{x}, bp = 0x{x}, sp = 0x{x}, ip = {d}, flags = {} }}", .{
            self.ax.value,
            self.bx.value,
            self.cx.value,
            self.dx.value,
            self.si.value,
            self.di.value,
            self.bp.value,
            self.sp.value,
            self.ip,
            self.flags,
        });
    }
};
