// const pc = @import("../pc.zig");
const std = @import("std");
// const CPUContext = pc.CPUContext;
const testing = std.testing;
pub const register = @import("register.zig");

pub const Register = @import("register.zig").Register;
pub const Instruction = @import("instruction.zig").Instruction;
pub const InstructionType = @import("instruction.zig").InstructionType;
pub const IndexMode = @import("instruction.zig").IndexMode;
pub const LabelMap = @import("label.zig").LabelMap;
pub const Operand = @import("operand.zig").Operand;
pub const BaseRegister = @import("register.zig").BaseRegister;

const operand = @import("operand.zig");
const ParseError = @import("../errors.zig").ParseError;

pub const ParseErrors = ParseError;

line: usize,
line_slice: []const u8,
pos_in_line: enum { inst, left_op, right_op },
allocator: std.mem.Allocator,
instructions: []Instruction,
label_map: LabelMap,
named_offsets: ?*const std.StringHashMap(usize),
parsing_done: bool,

pub fn init(allocator: std.mem.Allocator, named_offsets: ?*const std.StringHashMap(usize)) @This() {
    return @This(){
        .line = 0,
        .allocator = allocator,
        .instructions = undefined,
        .label_map = undefined,
        .named_offsets = named_offsets,
        .pos_in_line = .inst,
        .line_slice = undefined,
        .parsing_done = false,
    };
}

pub fn deinit(self: *@This()) void {
    if (!self.parsing_done) return;
    self.allocator.free(self.instructions);

    var it = self.label_map.keyIterator();
    while (it.next()) |str|
        self.label_map.allocator.free(str.*);

    self.label_map.deinit();
}

pub fn parse(parser: *@This(), raw_code: []const u8) (ParseErrors || error{OutOfMemory})!void {
    const allocator = parser.allocator;
    parser.label_map = LabelMap.init(allocator);
    parser.parsing_done = true;
    errdefer parser.parsing_done = false;
    var instructions = std.ArrayList(Instruction).init(allocator);
    defer instructions.deinit();
    errdefer {
        var it = parser.label_map.keyIterator();
        while (it.next()) |str|
            allocator.free(str.*);
        parser.label_map.deinit();
    }

    var it = std.mem.splitAny(u8, raw_code, "\r\n");

    parser.line = 0;
    while (it.next()) |raw_line| {
        defer parser.line += 1;
        parser.pos_in_line = .inst;
        parser.line_slice = raw_line;
        const line_no_comment = raw_line[0 .. std.mem.indexOfScalar(u8, raw_line, ';') orelse raw_line.len];
        const line_lowercased: []const u8 = blk: {
            var buff = try allocator.alloc(u8, line_no_comment.len);
            @memcpy(buff, line_no_comment);
            for (0..buff.len) |i|
                buff[i] = std.ascii.toLower(buff[i]);
            break :blk buff;
        };
        defer allocator.free(line_lowercased);

        // parse labels like `hello world:` as a normal expr to avoid accidental cases like `jnz cont:`
        const left_trimmed = std.mem.trimLeft(u8, line_lowercased, &std.ascii.whitespace);
        const might_label = std.mem.indexOfScalar(u8, left_trimmed, ':');
        const first_space = std.mem.indexOfAny(u8, left_trimmed, &std.ascii.whitespace);
        const is_space_in_label = if (first_space != null and might_label != null) first_space.? < might_label.? else false;

        if (might_label != null and !is_space_in_label) {
            const label_end = might_label.?;
            const label_name = std.mem.trim(u8, left_trimmed[0..label_end], &std.ascii.whitespace);
            std.log.info("found a label: {s}.\n", .{label_name});
            const followed_inst = std.mem.trim(u8, left_trimmed[label_end + 1 ..], &std.ascii.whitespace);

            try parser.label_map.put(try allocator.dupe(u8, label_name), instructions.items.len);

            if (followed_inst.len != 0)
                try instructions.append(try parseInstruction(parser, followed_inst));
        } else {
            var instruction: []u8 = @constCast(std.mem.trim(u8, left_trimmed, &std.ascii.whitespace));
            // if the line had a `:` but it was not meant to be a label,
            // remove all of them for parsing. ex: `jnz cont:` -> `jnz cont`
            var should_free = false;
            if (is_space_in_label) {
                instruction = try allocator.dupe(u8, instruction);
                should_free = true;
                while (std.mem.indexOfScalar(u8, instruction, ':')) |index| {
                    @memcpy(instruction[index .. instruction.len - 1], instruction[index + 1 ..]);
                    instruction = instruction[0 .. instruction.len - 1];
                }
            }
            defer {
                if (should_free) allocator.free(instruction);
            }
            if (instruction.len == 0) continue;
            try instructions.append(try parseInstruction(parser, instruction));
        }
    }
    try instructions.append(try parseInstruction(parser, "hlt"));

    parser.instructions = try allocator.alloc(Instruction, instructions.items.len);
    @memcpy(parser.instructions, instructions.items);
    errdefer allocator.free(parser.instructions);

    // TODO: must be cleaned up. perhaps moving some of the code here to label.zig would be fitting.
    var has_invalid_label: bool = false;
    for (parser.instructions) |*inst| {
        inline for (&[_]*?operand.Operand{ &inst.left_operand, &inst.right_operand }) |maybe_operand| {
            if (maybe_operand.* != null and maybe_operand.*.? == .unverified_label) {
                const unverified_label = maybe_operand.*.?.unverified_label;
                if (parser.label_map.get(unverified_label)) |line| {
                    maybe_operand.* = .{ .imm = @truncate(line) };
                } else {
                    std.log.err("Tried to access an unknown label: {s}\n", .{unverified_label});
                    has_invalid_label = true;
                }
                allocator.free(unverified_label);
            }
        }
    }
    if (has_invalid_label)
        return ParseErrors.UnknownLabel;
}

pub fn parseInstruction(parser: *@This(), inst_raw: []const u8) (ParseErrors || error{OutOfMemory})!Instruction {
    const allocator = parser.allocator;
    const named_offsets = parser.named_offsets;
    const inst_type_end = (std.mem.indexOf(u8, inst_raw, " ") orelse inst_raw.len);
    const inst_str_type = inst_raw[0..inst_type_end];
    // std.debug.print("inst_type: {s}\n", .{inst_str_type});
    const might_inst_type = InstructionType.fromString(inst_str_type);
    if (might_inst_type == null) {
        std.log.warn("unknown instruction found: {s}\n", .{inst_raw});
        return ParseErrors.UnknownInstruction;
    }
    const inst_type = might_inst_type.?;

    if (inst_type_end == inst_raw.len) {
        return Instruction{
            .inst = inst_type,
            .left_operand = null,
            .right_operand = null,
            .indexing_mode = .unknown,
        };
    }

    var it = std.mem.splitScalar(u8, inst_raw[inst_type_end + 1 ..], ',');
    const left_op_str = std.mem.trim(u8, it.next() orelse "", &std.ascii.whitespace);
    const right_op_str = std.mem.trim(u8, it.next() orelse "", &std.ascii.whitespace);

    var left_index_mode: IndexMode = .unknown;
    var right_index_mode: IndexMode = .unknown;

    parser.pos_in_line = .left_op;
    var left_op = try operand.parseOperand(allocator, left_op_str, &left_index_mode, null);
    parser.pos_in_line = .right_op;
    var right_op = try operand.parseOperand(allocator, right_op_str, &right_index_mode, named_offsets);

    if (right_op != null and left_op != null and (left_op.? == .imm or left_op.? == .unverified_label))
        return ParseError.InvalidOperandType; // the dst operand cannot me immediate
    if ((left_op != null and left_op.? == .mem) and (right_op != null and right_op.? == .mem))
        return ParseError.InvalidOperandType; // fixes double memory opcoodes

    const indexing_mode: IndexMode = blk: {
        if (left_index_mode != .unknown and right_index_mode != .unknown and left_index_mode != right_index_mode)
            return ParseErrors.MismatchingOperandSizes;

        if (left_index_mode == right_index_mode) {
            if (left_index_mode == .unknown)
                break :blk ._16bit;
            break :blk left_index_mode;
        }

        if (left_index_mode == ._8bit or right_index_mode == ._8bit)
            break :blk ._8bit;

        if (left_index_mode == ._16bit or right_index_mode == ._16bit)
            break :blk ._16bit;

        unreachable;
    };
    // std.debug.print("inst: {s}\nleft: {any}\ninst: {s}\nright: {any}\nfinal: {any}\n\n", .{ left_op_str, left_index_mode, right_op_str, right_index_mode, indexing_mode });
    inline for ([2]*?Operand{ &left_op, &right_op }) |op| {
        if (op.* != null and op.*.? == .mem) {
            op.*.?.mem.ptr_type = switch (indexing_mode) {
                ._16bit => .word_ptr,
                ._8bit => .byte_ptr,
                .unknown => return ParseError.UnknownIndexingMode,
            };
        }
    }

    switch (inst_type) {
        .lea => {
            if (right_op) |rop| {
                switch (rop) {
                    .mem => {},
                    else => return ParseErrors.InvalidOperandType,
                }
            } else return ParseErrors.InvalidOperandType;
        },
        .inc, .dec, .not, .neg => {
            if (left_op) |lop| {
                switch (lop) {
                    .imm => return ParseErrors.InvalidOperandType,
                    else => {},
                }
            }
            if (right_op) |_| return ParseErrors.InvalidExpression;
        },
        else => {},
    }

    // If operation is 8-bit and any immediate is provided, ensure it fits in 8 bits
    if (indexing_mode == ._8bit) {
        if (left_op) |lop| {
            switch (lop) {
                .imm => |v| if (v > 0x00FF) return ParseErrors.ImmediateOutOfRange,
                else => {},
            }
        }
        if (right_op) |rop| {
            switch (rop) {
                .imm => |v| if (v > 0x00FF) return ParseErrors.ImmediateOutOfRange,
                else => {},
            }
        }
    }

    return Instruction{
        .inst = inst_type,
        .left_operand = left_op,
        .right_operand = right_op,
        .indexing_mode = indexing_mode,
    };
}

test "test parse instruction" {
    var parser = init(testing.allocator, null);

    try testing.expectEqual(Instruction{
        .inst = .mov,
        .left_operand = .{ .reg = .{ .base = .ax, .selector = .full } },
        .right_operand = .{ .mem = .{ .base = register.fromString("bx"), .index = null, .displacement = 0, .ptr_type = .word_ptr } },
        .indexing_mode = ._16bit,
    }, try parseInstruction(&parser, "mov ax, [bx]"));

    try testing.expectEqual(Instruction{
        .inst = .add,
        .left_operand = .{ .reg = .{ .base = .cx, .selector = .low } },
        .right_operand = .{ .mem = .{ .base = null, .index = register.fromString("si"), .displacement = operand.wrapIntImm(-4), .ptr_type = .byte_ptr } },
        .indexing_mode = ._8bit,
    }, try parseInstruction(&parser, "add cl, [si - 4]"));

    try testing.expectEqual(Instruction{
        .inst = .mov,
        .left_operand = .{ .mem = .{ .base = register.fromString("bp"), .index = null, .displacement = operand.wrapIntImm(-0x12), .ptr_type = .byte_ptr } },
        .right_operand = .{ .reg = .{ .base = .dx, .selector = .low } },
        .indexing_mode = ._8bit,
    }, try parseInstruction(&parser, "mov [byte ptr bp-12h], dl"));

    try testing.expectEqual(Instruction{
        .inst = .xor,
        .left_operand = .{ .reg = .{ .base = .cx, .selector = .full } },
        .right_operand = .{ .imm = 0b10101010 },
        .indexing_mode = ._16bit,
    }, try parseInstruction(&parser, "xor cx, 10101010b"));

    // NOTE: using multiple displacements is VERY BUGGY and should not be done.
    try testing.expectEqual(Instruction{
        .inst = .lea,
        .left_operand = .{ .reg = .{ .base = .bx, .selector = .full } },
        .right_operand = .{ .mem = .{ .base = register.fromString("bp"), .index = register.fromString("si"), .displacement = operand.wrapIntImm(0x8 - 2), .ptr_type = .word_ptr } },
        .indexing_mode = ._16bit,
    }, try parseInstruction(&parser, "lea bx, [bp + 8h + si-2d]"));

    try testing.expectEqual(Instruction{
        .inst = .hlt,
        .left_operand = null,
        .right_operand = null,
        .indexing_mode = .unknown,
    }, try parseInstruction(&parser, "hlt"));
}
