const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const misc = @import("misc.zig");

const FixupKind = misc.FixupKind;
const InstBuf = misc.InstBuf;
const Instruction = misc.Instruction;
const Label = misc.Label;

const Fixup = struct {
    target_label: Label(),
    instruction_offset: usize,
    instruction_length: u8,
    kind: FixupKind(),
};

pub const AssemblerError = error{
    LabelNotDefined,
};

pub const Assembler = struct {
    origin: u64,
    code: ArrayList(u8),
    labels: ArrayList(isize),
    fixups: ArrayList(Fixup),
    guaranteed_capacity: usize,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .origin = 0,
            .code = ArrayList(u8).init(allocator),
            .labels = ArrayList(isize).init(allocator),
            .fixups = ArrayList(Fixup).init(allocator),
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

    pub fn current_address(self: Self) u64 {
        const items_len: u64 = @intCast(self.code.items.len);
        return self.origin + items_len;
    }

    pub fn forward_declare_label(self: *Self) Label() {
        const label: u32 = @intCast(self.labels.items.len);
        self.labels.append(std.math.maxInt(isize)) catch unreachable;
        return Label().from_raw(label);
    }

    pub fn create_label(self: *Self) Label() {
        const label: u32 = @intCast(self.labels.items.len);

        std.log.debug("{:08x}: {}:", self.origin + self.code.items.len, Label().from_raw(label));

        const items_len: isize = @intCast(self.code.items.len);
        self.labels.append(items_len) catch unreachable;
        return Label().from_raw(label);
    }

    pub fn define_label(self: *Self, label: Label()) *Self {
        std.log.debug("{:08x}: {}:", self.origin + self.code.items.len, label);
        std.debug.assert(self.labels.items[label.raw()] == std.math.maxInt(isize), "tried to redefine an already defined label");

        const items_len: isize = @intCast(self.code.items.len);
        self.labels.items[label.raw()] = items_len;
        return self;
    }

    pub fn push_with_label(self: *Self, label: Label(), instruction: anytype) *Self {
        _ = self.define_label(label);
        return self.push(instruction);
    }

    pub inline fn get_label_origin_offset(self: *Self, label: Label()) ?isize {
        const offset = self.labels.items[label.raw()];
        if (offset == std.math.maxInt(isize)) return null;
        return offset;
    }

    pub fn get_label_origin_offset_or_panic(self: *Self, label: Label()) AssemblerError!isize {
        return self.get_label_origin_offset(label) orelse
            AssemblerError.LabelNotDefined;
    }

    pub fn set_label_origin_offset(self: *Self, label: Label(), offset: isize) void {
        self.labels.items[label.raw()] = offset;
    }

    pub inline fn add_fixup(self: *Self, instruction_offset: usize, instruction_length: usize, target_label: Label(), kind: FixupKind()) void {
        std.debug.assert(target_label.raw() < self.labels.items.len);
        std.debug.assert(kind.offset() < instruction_length, "instruction is {} bytes long and yet its target fixup starts at {}", .{ instruction_length, kind.offset() });
        std.debug.assert(kind.length() < instruction_length);
        std.debug.assert(kind.offset() + kind.length() <= instruction_length);

        const instruction_length_u8: u8 = @intCast(instruction_length);
        // TODO: change unreachable to error
        self.fixups.append(Fixup{
            .target_label = target_label,
            .instruction_offset = instruction_offset,
            .instruction_length = instruction_length_u8,
            .kind = kind,
        }) catch unreachable;
    }

    pub inline fn reserve(self: *Self, comptime T: NonZero) ReservedAssembler {
        // Reserve space in code buffer
        InstBuf.reserve(&self.code, @field(T, "value"));
        self.guaranteed_capacity = @field(T, "value");

        return ReservedAssembler{
            .assembler = self,
            .phantom_data = T,
        };
    }

    pub fn push(self: *Assembler, instruction: anytype) *Assembler {
        if (self.guaranteed_capacity == 0) {
            // InstBuf.reserve_const(&self.code, 1);
            self.guaranteed_capacity = 1;
        }

        return self.push_unchecked(instruction);
    }

    pub fn push_unchecked(self: *Assembler, instruction: anytype) *Assembler {
        // Trace logging omitted
        std.debug.assert(self.guaranteed_capacity > 0);

        const instruction_offset = self.code.items.len;

        // Encode instruction into code buffer
        // instruction.bytes.encode_into_vec_unsafe(&self.code);
        self.guaranteed_capacity -= 1;

        if (instruction.fixup) |fixup_tuple| {
            self.add_fixup(
                instruction_offset,
                instruction.bytes.len(),
                fixup_tuple[0], // label
                fixup_tuple[1], // fixup
            );
        }

        return self;
    }

    pub fn push_raw(self: *Assembler, bytes: []const u8) *Assembler {
        // Trace logging omitted
        self.code.appendSlice(bytes) catch unreachable;
        return self;
    }

    pub fn finalize(self: *Assembler) AssembledCode {
        var i: usize = 0;
        while (i < self.fixups.items.len) : (i += 1) {
            const fixup = self.fixups.items[i];

            const origin = fixup.instruction_offset + @as(usize, fixup.instruction_length);
            const target_absolute = self.labels.items[fixup.target_label.raw()];

            if (target_absolute == std.math.maxInt(isize)) {
                // Trace logging: Undefined label found
                continue;
            }

            const opcode = (fixup.kind.inner << 8) >> 8;
            const fixup_offset = fixup.kind.offset();
            const fixup_length = fixup.kind.length();

            if (fixup_offset >= 1) {
                self.code.items[fixup.instruction_offset] = @intCast(u8, opcode);
                if (fixup_offset >= 2) {
                    self.code.items[fixup.instruction_offset + 1] = @intCast(u8, opcode >> 8);
                    if (fixup_offset >= 3) {
                        self.code.items[fixup.instruction_offset + 2] = @intCast(u8, opcode >> 16);
                    }
                }
            }

            const offset = target_absolute - @intCast(isize, origin);
            const p = fixup.instruction_offset + @as(usize, fixup_offset);

            if (fixup_length == 1) {
                if (offset > std.math.maxInt(i8) or offset < std.math.minInt(i8)) {
                    @panic("out of range jump");
                }
                self.code.items[p] = @bitCast(u8, @intCast(i8, offset));
            } else if (fixup_length == 4) {
                if (offset > std.math.maxInt(i32) or offset < std.math.minInt(i32)) {
                    @panic("out of range jump");
                }

                const bytes = std.mem.toBytes(@intCast(i32, offset));
                std.mem.copy(u8, self.code.items[p .. p + 4], &bytes);
            } else {
                unreachable;
            }
        }

        // Clear fixups
        self.fixups.clearRetainingCapacity();

        return AssembledCode{ .assembler = self };
    }

    pub fn is_empty(self: *Assembler) bool {
        return self.code.items.len == 0;
    }

    pub fn len(self: *Assembler) usize {
        return self.code.items.len;
    }

    pub fn code_mut(self: *Assembler) []u8 {
        return self.code.items;
    }

    pub fn spare_capacity(self: *Assembler) usize {
        return self.code.capacity - self.code.items.len;
    }

    pub fn resize(self: *Assembler, size: usize, fill_with: u8) void {
        self.code.resize(size) catch unreachable;
        if (size > self.code.items.len) {
            const start = self.code.items.len;
            const end = size;
            for (self.code.items[start..end]) |*byte| {
                byte.* = fill_with;
            }
        }
    }

    pub fn reserve_code(self: *Assembler, length: usize) void {
        self.code.ensureTotalCapacity(self.code.items.len + length) catch unreachable;
    }

    pub fn reserve_labels(self: *Assembler, length: usize) void {
        self.labels.ensureTotalCapacity(self.labels.items.len + length) catch unreachable;
    }

    pub fn reserve_fixups(self: *Assembler, length: usize) void {
        self.fixups.ensureTotalCapacity(self.fixups.items.len + length) catch unreachable;
    }

    pub fn clear(self: *Assembler) void {
        self.origin = 0;
        self.code.clearRetainingCapacity();
        self.labels.clearRetainingCapacity();
        self.fixups.clearRetainingCapacity();
    }
};

pub const AssembledCode = struct {
    assembler: *Assembler,

    pub inline fn deref(self: *AssembledCode) []u8 {
        return self.assembler.code.items;
    }

    pub fn toOwned(self: *AssembledCode, allocator: Allocator) ![]u8 {
        const result = try allocator.alloc(u8, self.assembler.code.items.len);
        std.mem.copy(u8, result, self.assembler.code.items);
        return result;
    }

    pub inline fn deinit(self: *AssembledCode) void {
        self.assembler.clear();
    }
};

// Type-level counter for compile-time counting
pub const NonZero = struct {
    value: usize,
    next: ?type,
};

pub const U0 = struct {};
pub const U1 = NonZero{ .value = 1, .next = U0 };
pub const U2 = NonZero{ .value = 2, .next = U1 };
pub const U3 = NonZero{ .value = 3, .next = U2 };
pub const U4 = NonZero{ .value = 4, .next = U3 };
pub const U5 = NonZero{ .value = 5, .next = U4 };
pub const U6 = NonZero{ .value = 6, .next = U5 };

pub fn ReservedAssembler(comptime phantom_data: type) type {
    return struct {
        assembler: *Assembler,
        phantom_data: phantom_data,

        // if phantom_data is U0, this function does nothing
        pub inline fn assert_reserved_exactly_as_needed(self: ReservedAssembler) void {
            if (self.phantom_data == U0) {
                return;
            }
        }

        pub inline fn push(self: ReservedAssembler, instruction: anytype) ReservedAssembler {
            // Safety: `phantom_data: NonZero`, so we still have space in the buffer.
            if (@TypeOf(self.phantom_data) == NonZero) {
                self.assembler.push_unchecked(instruction);

                return ReservedAssembler{
                    .assembler = self.assembler,
                    .phantom_data = @field(self.phantom_data, "next"),
                };
            }
            unreachable;
        }

        pub inline fn push_if(self: ReservedAssembler, condition: bool, instruction: anytype) ReservedAssembler {
            // SAFETY: `phantom_data: NonZero`, so we still have space in the buffer.
            if (@TypeOf(self.phantom_data) == NonZero) {
                if (condition) {
                    self.assembler.push_unchecked(instruction);
                }

                return ReservedAssembler{
                    .assembler = self.assembler,
                    .phantom_data = @field(self.phantom_data, "next"),
                };
            }
            unreachable;
        }

        pub inline fn push_none(self: ReservedAssembler) ReservedAssembler {
            // SAFETY: `phantom_data: NonZero`
            if (@TypeOf(self.phantom_data) == NonZero) {
                return ReservedAssembler{
                    .assembler = self.assembler,
                    .phantom_data = @field(self.phantom_data, "next"),
                };
            }
            unreachable;
        }

        pub inline fn get_label_origin_offset(self: ReservedAssembler, label: Label()) ?isize {
            return self.assembler.get_label_origin_offset(label);
        }

        pub inline fn len(self: ReservedAssembler) usize {
            return self.assembler.len();
        }

        pub inline fn is_empty(self: ReservedAssembler) bool {
            return self.assembler.is_empty();
        }
    };
}
