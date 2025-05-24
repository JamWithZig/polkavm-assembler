const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const NonZeroU32 = @import("non_zero.zig").NonZeroU32;

pub const Label = struct {
    const Self = @This();

    non_zero: NonZeroU32,

    pub inline fn raw(self: *Self) u32 {
        return self.non_zero.get() - 1;
    }

    pub inline fn fromRaw(value: u32) ?Self {
        if (value == 0) return null;
        return Self{ .non_zero = NonZeroU32.new(value + 1) };
    }
};

pub const Fixup = struct {
    label: Label,
    kind: FixupKind,
};

pub fn Instruction(comptime T: type) type {
    return struct {
        const Self = @This();

        instruction: T,
        bytes: InstBuf,
        fixup: ?Fixup,

        pub inline fn len(self: *Self) u32 {
            return self.bytes.len();
        }
    };
}

pub const FixupKind = struct {
    const Self = @This();

    inner: u32,

    pub inline fn offset(self: *Self) u32 {
        return (self.inner >> 24) & 0b11;
    }

    pub inline fn length(self: *Self) u32 {
        return self.inner >> 28;
    }

    pub inline fn new1(opcode: u32, len: u32) Self {
        return Self{ .inner = (1 << 24) | (len << 28) | opcode };
    }

    pub inline fn new2(opcode: [2]u32, len: u32) Self {
        const opcode_u32 = opcode[0] | (opcode[1] << 8);
        return Self{ .inner = (2 << 24) | (len << 28) | opcode_u32 };
    }

    pub inline fn new3(opcode: [3]u32, len: u32) Self {
        const opcode_u32 = opcode[0] | (opcode[1] << 8) | (opcode[2] << 16);
        return Self{ .inner = (3 << 24) | (len << 28) | opcode_u32 };
    }
};

const MAXIMUM_INSTRUCTION_SIZE: usize = 16;

pub const InstBuf = struct {
    const Self = @This();

    out: u128,
    len: u32,

    pub inline fn new() Self {
        return Self{ .out = 0, .len = 0 };
    }

    pub inline fn length(self: *Self) usize {
        return @as(usize, self.len >> 3);
    }

    pub inline fn append(self: *Self, byte: u8) void {
        self.out |= @as(u128, byte) <<| @as(u128, self.len);
        self.len += 8;
    }

    pub inline fn appendPackedBytes(self: *Self, value: u32, len: u32) void {
        self.out |= @as(u128, value) <<| @as(u128, self.len);
        self.len += len;
    }

    pub inline fn encodeIntoRaw(self: Self, output: [*]u8) void {
        // Convert the 128-bit value to two 64-bit values in little-endian format
        const lower_bytes = std.mem.nativeToLittle(u64, @as(u64, @truncate(self.out)));
        const higher_bytes = std.mem.nativeToLittle(u64, @as(u64, @truncate(self.out >> 64)));

        // Copy the bytes to the output buffer
        @memcpy(output[0..8], std.mem.asBytes(&lower_bytes));
        @memcpy(output[8..16], std.mem.asBytes(&higher_bytes));
    }

    pub inline fn encodeIntoVecUnsafe(self: *Self, output: *ArrayList(u8)) void {
        // Ensure we have enough capacity
        const available_space = output.capacity - output.items.len;
        std.debug.assert(available_space >= MAXIMUM_INSTRUCTION_SIZE);

        self.encodeIntoRaw(output.items[output.items.len..].ptr);
        const new_length = output.items.len + (self.len >> 3);
        output.items.len = new_length;
    }

    inline fn reserveImpl(output: *ArrayList(u8), len: usize) void {
        output.ensureTotalCapacity(output.items.len + len);
    }

    // TODO: check usage, decide if instructions is comptime
    pub inline fn reserveConst(instructions: usize, output: *ArrayList(u8)) void {
        Self.reserveImpl(output, instructions);
    }

    pub inline fn reserve(output: *ArrayList(u8), count: usize) !void {
        // TODO: fix return
        const count_mul = @mulWithOverflow(count, MAXIMUM_INSTRUCTION_SIZE);
        if (count_mul[1] != 0) return error.Overflow;
        if (output.capacity - output.items.len < count_mul[0]) {
            Self.reserveImpl(output, count_mul[0]);
            if (output.capacity - output.items.len < count_mul[0]) {
                // SAFETY: `reserve` made sure that we have this much capacity, so this is safe.
                unreachable;
            }
        }
    }

    pub inline fn fromArray(array: []const u8) *Self {
        if (array.len > MAXIMUM_INSTRUCTION_SIZE) {
            unreachable;
        }

        var out = Self.new();
        for (array) |value| {
            out.append(value);
        }
        return &out;
    }

    pub fn toVec(self: *Self, allocator: Allocator) !ArrayList(u8) {
        var vec = try ArrayList(u8).initCapacity(allocator, MAXIMUM_INSTRUCTION_SIZE);

        // SAFETY: We've reserved space for at least one instruction.
        self.encodeIntoVecUnsafe(&vec);

        return vec;
    }
};

// Test InstBuf operations
fn testInstBuf(allocator: Allocator, input: []const u8, expected: []const u8) !void {
    var actual = try InstBuf.fromArray(input).toVec(allocator);
    defer actual.deinit();
    try std.testing.expectEqualSlices(u8, expected, actual.items);
}
fn testAfterAppendPackedBytes(allocator: Allocator, buf: *InstBuf, expected: []const u8) !void {
    const arr = try buf.toVec(allocator);
    defer arr.deinit();
    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "InstBuf operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test fromArray and toVec with different array sizes
    try testInstBuf(allocator, &[_]u8{0x01}, &[_]u8{0x01});
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02 }, &[_]u8{ 0x01, 0x02 });
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02, 0x03 }, &[_]u8{ 0x01, 0x02, 0x03 });
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 }, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A });
    try testInstBuf(allocator, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 }, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 });

    // Test appendPackedBytes with 32-bit values
    var buf = InstBuf.fromArray(&[_]u8{0x01});
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{0x01});
    buf.appendPackedBytes(0x05040302, 32);
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 });
    buf.appendPackedBytes(0x09080706, 32);
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });

    // Test append_packed_bytes with 16-bit values
    buf = InstBuf.fromArray(&[_]u8{0x01});
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{0x01});
    buf.appendPackedBytes(0x0302, 16);
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{ 0x01, 0x02, 0x03 });
    buf.appendPackedBytes(0x0504, 16);
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 });
    buf.appendPackedBytes(0x0706, 16);
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
    buf.appendPackedBytes(0x0908, 16);
    try testAfterAppendPackedBytes(allocator, buf, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });
}
