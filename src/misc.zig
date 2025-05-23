const std = @import("std");
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

pub fn Instruction(comptime T: type) type {
    return struct {
        const Self = @This();

        instruction: T,
        bytes: InstBuf,
        fixup: ?.{ Label, FixupKind },

        pub fn fmt(self: *Self) !void {
            self.instruction.fmt();
        }

        pub inline fn len(self: *Self) u32 {
            return self.bytes.len();
        }
    };
}

pub const FixupKind = struct {
    const Self = @This();

    kind: u32,

    pub inline fn offset(self: *Self) u32 {
        return (self.kind >> 24) & 0b11;
    }

    pub inline fn length(self: *Self) u32 {
        return self.kind >> 28;
    }

    pub inline fn new1(opcode: u32, length: u32) Self {
        return Self{ .kind = (1 << 24) | (length << 28) | opcode };
    }

    pub inline fn new2(opcode: [u32; 2], length: u32) Self {
        let opcode = opcode[0] | (opcode[1] << 8);
        return Self{ .kind = (2 << 24) | (length << 28) | opcode };
    }

    pub inline fn new3(opcode: [u32; 3], length: u32) Self {
        let opcode = opcode[0] | (opcode[1] << 8) | (opcode[2] << 16);
        return Self{ .kind = (3 << 24) | (length << 28) | opcode };
    }
};

const MAXIMUM_INSTRUCTION_SIZE: usize = 16;

pub const InstBuf = struct {
    const Self = @This();

    out: u128,
    len: usize,

    pub inline fn new() Self {
        return Self{ .out = 0, .len = 0 };
    }

    pub inline fn len(self: *Self) usize {
        return @as(usize, self.len >> 3);
    }

    pub inline fn append(self: *Self, byte: u8) {
        self.out |= @as(u128, byte) <<| @as(u128, self.len);
        self.len += 8;
    }

    pub inline fn appendPackedBytes(self: *Self, value: u32, length: u32) {
        self.out |= @as(u128, value) <<| @as(u128, self.len);
        self.len += length;
    }

    inline fn encodeIntoRaw(self: *Self, output: u8) void {
        // Not required
    }

    pub inline fn encodeIntoVecUnsafe(self: Self, output: *ArrayList(u8)) void {
        // Ensure we have enough capacity
        const available_space = output.capacity - output.items.len;
        std.debug.assert(available_space >= MAXIMUM_INSTRUCTION_SIZE);

        // TODO:
        output.appendAssumeCapacity(std.mem.nativeToLittle(u64, @as(u64, self.out)));
        output.appendAssumeCapacity(std.mem.nativeToLittle(u64, @as(u64, self.out >> 64)));
    }

    inline fn reserveImpl(output: *ArrayList(u8), length: usize) void {
        output.ensureTotalCapacity(output.items.len + length);
    }
};
