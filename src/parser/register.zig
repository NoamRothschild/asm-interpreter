const std = @import("std");

pub const BaseRegister = enum { ax, bx, cx, dx, si, di, bp, sp };

pub const ByteSelector = enum { low, high, full };

pub const RegisterIdentifier = struct {
    base: BaseRegister,
    selector: ByteSelector,

    pub fn size(self: RegisterIdentifier) enum { _8bit, _16bit } {
        return switch (self.selector) {
            .low, .high => ._8bit,
            .full => ._16bit,
        };
    }
};

pub fn fromString(mnemonic: []const u8) ?RegisterIdentifier {
    const mapping_8bit = [_]struct { name: []const u8, base: BaseRegister, sel: ByteSelector }{
        .{ .name = "al", .base = .ax, .sel = .low },
        .{ .name = "ah", .base = .ax, .sel = .high },
        .{ .name = "bl", .base = .bx, .sel = .low },
        .{ .name = "bh", .base = .bx, .sel = .high },
        .{ .name = "cl", .base = .cx, .sel = .low },
        .{ .name = "ch", .base = .cx, .sel = .high },
        .{ .name = "dl", .base = .dx, .sel = .low },
        .{ .name = "dh", .base = .dx, .sel = .high },
    };

    for (mapping_8bit) |map| {
        if (std.mem.eql(u8, mnemonic, map.name)) {
            return RegisterIdentifier{ .base = map.base, .selector = map.sel };
        }
    }

    inline for (std.meta.fields(BaseRegister)) |field| {
        if (std.mem.eql(u8, mnemonic, field.name)) {
            return RegisterIdentifier{ .base = @field(BaseRegister, field.name), .selector = .full };
        }
    }
    return null;
}

pub fn toString(reg_id: RegisterIdentifier) ?[]const u8 {
    const mapping = [_]struct { name: []const u8, base: BaseRegister, sel: ByteSelector }{
        .{ .name = "al", .base = .ax, .sel = .low },
        .{ .name = "ah", .base = .ax, .sel = .high },
        .{ .name = "bl", .base = .bx, .sel = .low },
        .{ .name = "bh", .base = .bx, .sel = .high },
        .{ .name = "cl", .base = .cx, .sel = .low },
        .{ .name = "ch", .base = .cx, .sel = .high },
        .{ .name = "dl", .base = .dx, .sel = .low },
        .{ .name = "dh", .base = .dx, .sel = .high },
        .{ .name = "ax", .base = .ax, .sel = .full },
        .{ .name = "bx", .base = .bx, .sel = .full },
        .{ .name = "cx", .base = .cx, .sel = .full },
        .{ .name = "dx", .base = .dx, .sel = .full },
        .{ .name = "si", .base = .si, .sel = .full },
        .{ .name = "di", .base = .di, .sel = .full },
        .{ .name = "bp", .base = .bp, .sel = .full },
        .{ .name = "sp", .base = .sp, .sel = .full },
    };

    for (mapping) |map| {
        if (reg_id.base == map.base and reg_id.selector == map.sel) {
            return map.name;
        }
    }
    return null;
}
