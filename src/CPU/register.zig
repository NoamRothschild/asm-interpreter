const std = @import("std");
const register = @import("../parser/register.zig");

pub const Register = struct {
    const Self = @This();
    value: u16,

    pub inline fn getValue(self: *const Self) u16 {
        return self.value;
    }

    pub inline fn getLow(self: *const Self) u8 {
        return @truncate(self.value);
    }

    pub inline fn getHigh(self: *const Self) u8 {
        return @truncate(self.value >> 8);
    }

    pub fn set(self: *Self, selector: register.ByteSelector, value: u16) void {
        switch (selector) {
            .low => {
                self.*.value = (self.value & 0xFF00) | (@as(u16, @as(u8, @truncate(value))));
            },
            .high => {
                self.*.value = (self.value & 0x00FF) | ((@as(u16, @as(u8, @truncate(value)))) << 8);
            },
            .full => {
                self.*.value = value;
            },
        }
    }

    pub fn get(self: *const Self, selector: register.ByteSelector) u16 {
        return switch (selector) {
            .low => @as(u16, self.getLow()),
            .high => @as(u16, self.getHigh()),
            .full => self.getValue(),
        };
    }
};

pub const FlagsRegister = struct {
    c: bool, // carry flag
    p: bool,
    ac: bool,
    z: bool, // zero flag
    s: bool, // sign flag
    o: bool, // overflow flag
    d: bool, // direction flag
    i: bool,
    t: bool,
};
