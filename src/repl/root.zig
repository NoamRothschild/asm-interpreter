const std = @import("std");
const executor = @import("../CPU/executor.zig");
const parser = @import("../parser/root.zig");
const Context = @import("../CPU/context.zig").Context;

var stdin_buff: [1024]u8 = undefined;
pub fn main(config: anytype) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    _ = config;

    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();
    var ctx: Context = std.mem.zeroes(Context);
    var instruction: []const u8 = undefined;
    var running: bool = true;
    var inst_list = std.ArrayList(parser.Instruction).init(allocator);

    while (running) {
        _ = try stdout.write(">>> ");
        const raw_line = try stdin.reader().readUntilDelimiter(&stdin_buff, '\n');

        const line_no_comment = raw_line[0 .. std.mem.indexOfScalar(u8, raw_line, ';') orelse raw_line.len];
        const line_lowercased: []const u8 = blk: {
            var buff = try allocator.alloc(u8, line_no_comment.len);
            @memcpy(buff, line_no_comment);
            for (0..buff.len) |i|
                buff[i] = std.ascii.toLower(buff[i]);
            break :blk buff;
        };
        defer allocator.free(line_lowercased);
        instruction = std.mem.trim(u8, line_lowercased, &std.ascii.whitespace);
        if (instruction.len == 0) continue;

        if (std.mem.eql(u8, instruction, "exit")) {
            running = false;
            continue;
        }

        var parser_ = parser.init(allocator, null);
        try inst_list.append(parser.parseInstruction(&parser_, instruction) catch |err| {
            std.log.warn("Errored while parsing instruction \"{s}\"\n{s}", .{ instruction, @errorName(err) });
            continue;
        });
        ctx.instructions = inst_list.items;

        executor.executeInstruction(&ctx) catch |err| {
            std.log.warn("Errored while executing instruction in line {d}\n{s}", .{ ctx.ip, @errorName(err) });
            continue;
        };

        try outInstruction(&ctx, stdout.writer(), ctx.instructions[ctx.ip - 1].left_operand orelse continue);
    }
}

fn outInstruction(ctx: *const Context, writer: anytype, out_operand: parser.Operand) !void {
    switch (out_operand) {
        .reg => |v| try writer.print("{s} = 0x{x}\n", .{ parser.register.toString(v) orelse return, ctx.getRegister(v) }),
        .mem => |v| {
            const addr = v.finalAddr(ctx);
            switch (v.ptr_type) {
                .byte_ptr => try writer.print("[byte ptr 0x{x}] = 0x{x}\n", .{ addr, ctx.dataseg[addr] }),
                .unknown, .word_ptr => try writer.print("[word ptr 0x{x}] = 0x{x}\n", .{ addr, ctx.readWord(addr) }),
            }
        },
        else => {},
    }
}
