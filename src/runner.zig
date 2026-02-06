const std = @import("std");
const parser = @import("parser/root.zig");
const executor = @import("CPU/executor.zig");
const Context = @import("CPU/context.zig").Context;

pub fn run(parser_ctx: *parser, ctx: *Context, code: []const u8, timeout: ?usize) !void {
    parser_ctx.parse(code) catch |err| {
        std.log.warn("parser failed on line {d}!, error: {s}\nline:\n{s}", .{ parser_ctx.line, @errorName(err), parser_ctx.line_slice });
        return err;
    };
    defer parser_ctx.deinit();
    ctx.instructions = parser_ctx.instructions;

    var inst_ran_count: usize = 0;
    while ((if (timeout) |tm| inst_ran_count != tm else true) and parser_ctx.instructions[ctx.ip].inst != .hlt) : (inst_ran_count += 1) {
        try executor.executeInstruction(ctx);
    }
}

pub fn run_file(parser_ctx: *parser, ctx: *Context, file_path: []const u8) !void {
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
    defer file.close();

    const code = try file.readToEndAlloc(parser_ctx.allocator, std.math.maxInt(usize));
    defer parser_ctx.allocator.free(code);
    try run(parser_ctx, ctx, code, null);
}
