const std = @import("std");
const parser = @import("parser/root.zig");
const executor = @import("CPU/executor.zig");
const Context = @import("CPU/context.zig").Context;

pub fn run(allocator: std.mem.Allocator, ctx: *Context, code: []const u8, named_offsets: ?*const std.StringHashMap(usize)) !void {
    var parser_result = parser.parse(allocator, code, named_offsets) catch |err| {
        std.log.warn("parser failed!, error: {s}\n", .{@errorName(err)});
        return err;
    };
    defer parser_result.deinit();
    ctx.instructions = parser_result.instructions;

    while (parser_result.instructions[ctx.ip].inst != .hlt) {
        try executor.executeInstruction(ctx);
    }
}

pub fn run_file(allocator: std.mem.Allocator, ctx: *Context, file_path: []const u8) !void {
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
    defer file.close();

    const code = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(code);
    try run(allocator, ctx, code, null);
}
