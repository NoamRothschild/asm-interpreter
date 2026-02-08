const std = @import("std");
const parser = @import("parser/root.zig");
const runner = @import("runner.zig");
const executor = @import("CPU/executor.zig");
const repl = @import("repl/root.zig");

const Context = @import("CPU/context.zig").Context;

const name_message: []const u8 = "\x1b[1masm interpreter 1.0.0\x1b[0m\n";
const help_message: []const u8 =
    \\usage: {s} [-s] [--run code_file | --test test_file | --execute "code"]
    \\
    \\  -h, --help                 shows this help menu
    \\  -v, --version              display the interpreters version
    \\  -s, --silent               whether to write output stdout (always ignored on err)
    \\  -r, --run  [code_file]     execute the given assembly code
    \\  -t, --test [test_file]     execute the given .yaml test file (exist code is success indicator)
    \\  -e, --execute "code"       executes the given lines of assembly
    \\
    \\
;
const repl_message: []const u8 =
    \\Type assembly commands like "mov ax, [di]" to execute, or run "exit" to abort.
    \\Execute again with "--help" for a detailed usage overview
    \\
;

pub var silent: *bool = &(@import("module.zig").silent);

pub fn main() !void {
    var args_iterator = std.process.args();
    _ = args_iterator.next(); // skip program name
    const stdout = std.io.getStdOut();
    var ctx = std.mem.zeroes(Context);

    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        if (gpa.deinit() == .leak) @panic("Memory was leaked!");
    }
    var arg_ctx = struct {
        arg: []const u8,
        fn eql(self: @This(), to: []const u8) bool {
            return std.mem.eql(u8, self.arg, to);
        }
    }{ .arg = args_iterator.next() orelse "" };

    if (arg_ctx.eql("-s") or arg_ctx.eql("--silent")) {
        silent.* = true;
        arg_ctx.arg = args_iterator.next() orelse "";
    }

    if (arg_ctx.eql("")) {
        _ = try stdout.write(repl_message);
        try repl.main(null);
    } else if (arg_ctx.eql("-h") or arg_ctx.eql("--help")) {
        _ = try stdout.write(help_message);
    } else if (arg_ctx.eql("-v") or arg_ctx.eql("--version")) {
        _ = try stdout.write(name_message ++ help_message);
        return;
    } else if (arg_ctx.eql("-t") or arg_ctx.eql("--test")) {
        @panic("not implemeted"); // TODO: implement
    } else if (arg_ctx.eql("-r") or arg_ctx.eql("--run")) {
        if (args_iterator.next()) |tested_file| {
            var parser_ctx = parser.init(allocator, null);
            try runner.run_file(&parser_ctx, &ctx, tested_file);
            if (!silent.*) try stdout.writer().print("CPU Context: {}\n", .{ctx});
            return;
        }
    } else if (arg_ctx.eql("-e") or arg_ctx.eql("--execute")) {
        if (args_iterator.next()) |code| {
            const fixed_code = try allocator.alloc(u8, std.mem.replacementSize(u8, code, "\\n", "\n"));
            _ = std.mem.replace(u8, code, "\\n", "\n", fixed_code);
            defer allocator.free(fixed_code);

            var parser_ctx = parser.init(allocator, null);
            try runner.run(&parser_ctx, &ctx, fixed_code, null);
            if (!silent.*) try stdout.writer().print("CPU Context: {}\n", .{ctx});
            return;
        }
    } else {
        try stdout.writer().print("Unknown option {s}\n", .{arg_ctx.arg});
        _ = try stdout.write(help_message);
        std.process.exit(1);
    }
}

// use default logging only when `silent` is set to false
fn _logFn(comptime message_level: std.log.Level, comptime scope: @TypeOf(.enum_literal), comptime format: []const u8, args: anytype) void {
    if (silent.*) return;
    _ = scope;
    std.debug.print("[{s}] ", .{@tagName(message_level)});
    std.debug.print(format, args);
    std.debug.print("\n", .{});
}
pub const std_options: std.Options = .{
    .logFn = _logFn,
};

test "all tests" {
    _ = @import("parser/instruction.zig");
    _ = @import("parser/root.zig");
    _ = @import("parser/operand.zig");
    _ = @import("CPU/executor.zig");
}
