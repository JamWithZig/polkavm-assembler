const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const MultiArrayList = std.MultiArrayList;
const misc = @import("misc.zig");
const non_zero = @import("non_zero.zig");

const FixupKind = misc.FixupKind;
const InstBuf = misc.InstBuf;
const Instruction = misc.Instruction;
const Label = misc.Label;

const Fixup = struct {
    target_label: Label,
    instruction_offset: usize,
    instruction_length: u8,
    kind: FixupKind,
};

pub const AssemblerError = error{
    LabelNotDefined,
};

pub const Assembler = struct {
    origin: u64,
    code: ArrayList(u8),
    labels: ArrayList(isize),
    fixups: MultiArrayList(Fixup),
    guaranteed_capacity: usize,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .origin = 0,
            .code = ArrayList(u8).init(allocator),
            .labels = ArrayList(isize).init(allocator),
            .fixups = MultiArrayList(Fixup).init(allocator),
            .guaranteed_capacity = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.code.deinit();
        self.labels.deinit();
        self.fixups.deinit();
    }

    pub fn default() Self {
        return Self.init(std.heap.page_allocator);
    }

    pub fn currentAddress(self: Self) u64 {
        const items_len: u64 = @truncate(self.code.items.len);
        return self.origin + items_len;
    }

    pub fn forwardDeclareLabel(self: *Self) Label {
        const label: u32 = @truncate(self.labels.items.len);
        try self.labels.append(std.math.maxInt(isize));
        return Label.fromRaw(label);
    }

    pub fn createLabel(self: *Self) Label {
        const label: u32 = @truncate(self.labels.items.len);
        const label_from_raw = Label.fromRaw(label);

        const origin_plus_len: u64 = @truncate(self.origin + self.code.items.len);
        std.log.debug("{:08x}: {}:", origin_plus_len, label_from_raw);

        const items_len: isize = @intCast(self.code.items.len);
        try self.labels.append(items_len);
        return label_from_raw;
    }

    pub fn defineLabel(self: *Self, label: Label) *Self {
        const origin_plus_len: u64 = @truncate(self.origin + self.code.items.len);
        std.log.debug("{:08x}: {}:", origin_plus_len, label);
        std.debug.assert(self.labels.items[label.raw()] == std.math.maxInt(isize), "tried to redefine an already defined label");

        const items_len: isize = @intCast(self.code.items.len);
        const label_raw: usize = @truncate(label.raw());
        self.labels.items[label_raw] = items_len;
        return self;
    }

    pub fn pushWithLabel(self: *Self, label: Label, comptime T: type, instruction: Instruction(T)) *Self {
        _ = self.defineLabel(label);
        return self.push(instruction);
    }

    pub inline fn getLabelOriginOffset(self: *Self, label: Label) ?isize {
        const label_raw: usize = @truncate(label.raw());
        const offset = self.labels.items[label_raw];
        if (offset == std.math.maxInt(isize)) return null;
        return offset;
    }

    pub fn getLabelOriginOffsetOrPanic(self: *Self, label: Label) AssemblerError!isize {
        return self.getLabelOriginOffset(label) orelse AssemblerError.LabelNotDefined;
    }

    pub fn setLabelOriginOffset(self: *Self, label: Label, offset: isize) void {
        self.labels.items[label.raw()] = offset;
    }

    pub inline fn addFixup(self: *Self, instruction_offset: usize, instruction_length: usize, target_label: Label, kind: FixupKind) !void {
        std.debug.assert(target_label.raw() < self.labels.items.len, "target label {} is greater than labels len {}", .{ target_label.raw(), self.labels.items.len });
        std.debug.assert(kind.offset() < instruction_length, "instruction is {} bytes long and yet its target fixup starts at {}", .{ instruction_length, kind.offset() });
        std.debug.assert(kind.length() < instruction_length, "kind len {} is greater than instruction len {}", .{ kind.length(), instruction_length });
        std.debug.assert(kind.offset() + kind.length() <= instruction_length, "kind offset {} + kind len {} is greater than instruction len {}", .{ kind.offset(), kind.length(), instruction_length });

        const instruction_length_u8: u8 = @truncate(instruction_length);
        try self.fixups.append(Fixup{
            .target_label = target_label,
            .instruction_offset = instruction_offset,
            .instruction_length = instruction_length_u8,
            .kind = kind,
        });
    }

    pub inline fn reserve(self: *Self, comptime T: non_zero.NonZeroUsize) ReservedAssembler {
        // Reserve space in code buffer
        const t_val = T.get();
        InstBuf.reserve(&self.code, t_val);
        self.guaranteed_capacity = t_val;

        return ReservedAssembler{
            .assembler = self,
            .phantom_data = T,
        };
    }

    pub inline fn push(self: *Assembler, comptime T: type, instruction: Instruction(T)) *Assembler {
        if (self.guaranteed_capacity == 0) {
            InstBuf.reserveConst(1, &self.code);
            self.guaranteed_capacity = 1;
        }

        // SAFETY: We've reserved space for at least one instruction.
        return self.pushUnchecked(instruction);
    }

    // SAFETY: The buffer *must* have space for at least one instruction.
    pub fn pushUnchecked(self: *Assembler, instruction: anytype) *Assembler {
        const origin_plus_len: u64 = @truncate(self.origin + self.code.items.len);
        std.log.debug("{:08x}: {}", origin_plus_len, instruction);
        std.debug.assert(self.guaranteed_capacity > 0, "guaranteed capacity should not be 0");

        const instruction_offset = self.code.items.len;

        // SAFETY: The caller reserved space for at least one instruction.
        instruction.bytes.encodeIntoVecUnsafe(&self.code);
        self.guaranteed_capacity -= 1;

        if (instruction.fixup) |fixup_tuple| {
            self.addFixup(
                instruction_offset,
                instruction.bytes.len(),
                fixup_tuple.label,
                fixup_tuple.kind,
            );
        }

        return self;
    }

    pub fn pushRaw(self: *Assembler, bytes: []const u8) !*Assembler {
        const origin_plus_len: u64 = @truncate(self.origin + self.code.items.len);
        std.log.debug("{:08x}: {}", origin_plus_len, bytes);
        try self.code.appendSlice(bytes);
        return self;
    }

    pub fn finalize(self: *Assembler) AssembledCode {
        for (self.fixups.items) |fixup| {
            const origin = fixup.instruction_offset + @as(usize, fixup.instruction_length);
            const target_absolute = self.labels.items[@as(usize, fixup.target_label.raw())];

            if (target_absolute == std.math.maxInt(isize)) {
                std.log.trace("Undefined label found: {}", fixup.target_label);
                continue;
            }

            const opcode = @as(u32, (fixup.kind.inner << 8) >> 8);
            const fixup_offset = fixup.kind.offset();
            const fixup_length = fixup.kind.length();

            if (fixup_offset >= 1) {
                const opcode_u8: u8 = @truncate(opcode);
                self.code.items[fixup.instruction_offset] = opcode_u8;
                if (fixup_offset >= 2) {
                    const opcode8_u8: u8 = @truncate(opcode >> 8);
                    self.code.items[fixup.instruction_offset + 1] = opcode8_u8;
                    if (fixup_offset >= 3) {
                        const opcode16_u8: u8 = @truncate(opcode >> 16);
                        self.code.items[fixup.instruction_offset + 2] = opcode16_u8;
                    }
                }
            }

            const origin_isize: isize = @intCast(origin);
            const offset = target_absolute - origin_isize;
            const fixup_offset_usize: usize = @truncate(fixup_offset);
            const p = fixup.instruction_offset + fixup_offset_usize;

            if (fixup_length == 1) {
                if (offset > std.math.maxInt(i8) or offset < std.math.minInt(i8)) {
                    @panic("out of range jump");
                }
                const offset_u8: u8 = @truncate(offset);
                self.code.items[p] = offset_u8;
            } else if (fixup_length == 4) {
                if (offset > std.math.maxInt(i32) or offset < std.math.minInt(i32)) {
                    @panic("out of range jump");
                }

                const offset_i32: i32 = @intCast(offset);
                const bytes = std.mem.toBytes(offset_i32);
                @memcpy(self.code.items[p .. p + 4], bytes);
            } else {
                unreachable;
            }
        }

        self.fixups.clearRetainingCapacity();

        return AssembledCode{ .assembler = self };
    }

    pub fn isEmpty(self: *Assembler) bool {
        return self.code.items.len == 0;
    }

    pub fn length(self: *Assembler) usize {
        return self.code.items.len;
    }

    // TODO: may not be required
    // pub fn codeMut(self: *Assembler) []u8 {
    //     return self.code.items;
    // }

    pub fn spareCapacity(self: *Assembler) usize {
        return self.code.capacity - self.code.items.len;
    }

    pub fn resize(self: *Assembler, size: usize, fill_with: u8) !void {
        try self.code.resize(size);
        if (size > self.code.items.len) {
            const start = self.code.items.len;
            const end = size;
            for (self.code.items[start..end]) |*byte| {
                byte.* = fill_with;
            }
        }
    }

    pub fn reserveCode(self: *Assembler, len: usize) !void {
        try self.code.ensureTotalCapacity(self.code.items.len + len);
    }

    pub fn reserveLabels(self: *Assembler, len: usize) !void {
        try self.labels.ensureTotalCapacity(self.labels.items.len + len);
    }

    pub fn reserveFixups(self: *Assembler, len: usize) !void {
        try self.fixups.ensureTotalCapacity(self.fixups.items.len + len);
    }

    pub fn clear(self: *Assembler) void {
        self.origin = 0;
        self.code.clearRetainingCapacity();
        self.labels.clearRetainingCapacity();
        self.fixups.clearRetainingCapacity();
        self.guaranteed_capacity = 0;
    }
};

pub const AssembledCode = struct {
    assembler: *Assembler,

    pub inline fn deref(self: *AssembledCode) []u8 {
        return self.assembler.code.items;
    }

    pub inline fn deinit(self: *AssembledCode) void {
        self.assembler.clear();
    }
};

pub const U0 = struct {};
pub const U1 = non_zero.NonZeroUsize.new(1, U0);
pub const U2 = non_zero.NonZeroUsize.new(2, U1);
pub const U3 = non_zero.NonZeroUsize.new(3, U2);
pub const U4 = non_zero.NonZeroUsize.new(4, U3);
pub const U5 = non_zero.NonZeroUsize.new(5, U4);
pub const U6 = non_zero.NonZeroUsize.new(6, U5);

pub fn ReservedAssembler(comptime R: type) type {
    return struct {
        const Self = @This();

        assembler: *Assembler,
        phantom_data: R,

        // if phantom_data is U0, this function does nothing
        pub inline fn assert_reserved_exactly_as_needed(self: Self) void {
            if (@TypeOf(self.phantom_data) == U0) {
                return;
            }
            // NOTE: this is only implemented for U0
            unreachable;
        }

        pub inline fn push(self: Self, comptime T: type, instruction: Instruction(T)) Self {
            // Safety: `phantom_data: NonZeroUsize`, so we still have space in the buffer.
            if (@TypeOf(self.phantom_data) == non_zero.NonZeroUsize) {
                self.assembler.push_unchecked(instruction);

                return Self{
                    .assembler = self.assembler,
                    .phantom_data = R,
                };
            }
            unreachable;
        }

        pub inline fn push_if(self: Self, condition: bool, comptime T: type, instruction: Instruction(T)) Self {
            // SAFETY: `phantom_data: NonZeroUsize`, so we still have space in the buffer.
            if (@TypeOf(self.phantom_data) == non_zero.NonZeroUsize) {
                if (condition) {
                    self.assembler.push_unchecked(instruction);
                }

                return Self{
                    .assembler = self.assembler,
                    .phantom_data = R,
                };
            }
            unreachable;
        }

        pub inline fn push_none(self: Self) Self {
            // SAFETY: `phantom_data: NonZeroUsize`
            if (@TypeOf(self.phantom_data) == non_zero.NonZeroUsize) {
                return Self{
                    .assembler = self.assembler,
                    .phantom_data = R,
                };
            }
            unreachable;
        }

        pub inline fn get_label_origin_offset(self: Self, label: Label) ?isize {
            return self.assembler.get_label_origin_offset(label);
        }

        pub inline fn length(self: Self) usize {
            return self.assembler.length();
        }

        pub inline fn is_empty(self: Self) bool {
            return self.assembler.is_empty();
        }
    };
}
