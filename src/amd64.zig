const std = @import("std");
const misc = @import("misc.zig");
const Fixup = misc.Fixup;
const FixupKind = misc.FixupKind;
const InstBuf = misc.InstBuf;
const Instruction = misc.Instruction;
const Label = misc.Label;

/// The REX prefix.
const REX: u8 = 0x40;
const REX_64B_OP: u8 = REX | (1 << 3);
const REX_EXT_MODRM_REG: u8 = REX | (1 << 2);
const REX_EXT_MODRM_SIB_INDEX: u8 = REX | (1 << 1);
const REX_EXT_MODRM_RM: u8 = REX | (1 << 0);

const PREFIX_REP: u8 = 0xf3;
const PREFIX_OVERRIDE_SEGMENT_FS: u8 = 0x64;
const PREFIX_OVERRIDE_SEGMENT_GS: u8 = 0x65;
const PREFIX_OVERRIDE_OP_SIZE: u8 = 0x66;
const PREFIX_OVERRIDE_ADDR_SIZE: u8 = 0x67;

pub const Reg = enum(u8) {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    rsp = 4,
    rbp = 5,
    rsi = 6,
    rdi = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,

    const Self = @This();

    pub fn isRegPreserved(self: Self) bool {
        // See page 23 from: https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf
        return switch (self) {
            inline .rbx, .rsp, .rbp, .r12, .r13, .r14, .r15 => true,
            inline .rax, .rcx, .rdx, .rsi, .rdi, .r8, .r9, .r10, .r11 => false,
        };
    }

    pub inline fn needsRex(self: Self) bool {
        return @as(usize, self) >= @as(usize, Self.r8);
    }

    pub inline fn modrmRmBits(self: Self) u8 {
        return @truncate(@as(usize, self) & 0b111);
    }

    pub inline fn modrmRegBits(self: Self) u8 {
        return @truncate((@as(usize, self) << 3) & 0b111000);
    }

    pub inline fn rexBit(self: Self) u8 {
        if (@as(usize, self) >= @as(usize, Self.r8)) {
            return REX_EXT_MODRM_RM;
        } else {
            return 0;
        }
    }

    pub inline fn rexModrmReg(self: Self) u8 {
        if (@as(usize, self) >= @as(usize, Self.r8)) {
            return REX_EXT_MODRM_REG;
        } else {
            return 0;
        }
    }

    pub fn nameFrom(self: Self, size: RegSize) []const u8 {
        return switch (size) {
            inline RegSize.R64 => self.name(),
            inline RegSize.R32 => self.name32(),
        };
    }

    pub fn nameFromSize(self: Self, kind: Size) []const u8 {
        return switch (kind) {
            inline Size.U64 => self.name(),
            inline Size.U32 => self.name32(),
            inline Size.U16 => self.name16(),
            inline Size.U8 => self.name8(),
        };
    }

    pub inline fn name(self: Self) []const u8 {
        return reg_names64[@intFromEnum(self)];
    }

    pub inline fn name32(self: Self) []const u8 {
        return reg_names32[@intFromEnum(self)];
    }

    pub inline fn name16(self: Self) []const u8 {
        return reg_names16[@intFromEnum(self)];
    }

    pub inline fn name8(self: Self) []const u8 {
        return reg_names8[@intFromEnum(self)];
    }

    pub fn fmt(self: Self) []const u8 {
        return self.name();
    }

    pub inline fn from(regIdx: RegIndex) Self {
        return regIdx.intoReg();
    }
};

const regs = [_][4][]const u8{
    .{ "rax", "eax", "ax", "al" },
    .{ "rcx", "ecx", "cx", "cl" },
    .{ "rdx", "edx", "dx", "dl" },
    .{ "rbx", "ebx", "bx", "bl" },
    .{ "rsp", "esp", "sp", "spl" },
    .{ "rbp", "ebp", "bp", "bpl" },
    .{ "rsi", "esi", "si", "sil" },
    .{ "rdi", "edi", "di", "dil" },
    .{ "r8", "r8d", "r8w", "r8b" },
    .{ "r9", "r9d", "r9w", "r9b" },
    .{ "r10", "r10d", "r10w", "r10b" },
    .{ "r11", "r11d", "r11w", "r11b" },
    .{ "r12", "r12d", "r12w", "r12b" },
    .{ "r13", "r13d", "r13w", "r13b" },
    .{ "r14", "r14d", "r14w", "r14b" },
    .{ "r15", "r15d", "r15w", "r15b" },
};

fn regNames(comptime index: usize) [][]const u8 {
    var names = [regs.len][]const u8{undefined};
    for (regs, 0..) |reg, i| {
        names[i] = reg[index];
    }
    return names;
}

const reg_names64 = regNames(0);
const reg_names32 = regNames(1);
const reg_names16 = regNames(2);
const reg_names8 = regNames(3);

pub const RegIndex = enum(u8) {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    // No `rsp`.
    rbp = 5,
    rsi = 6,
    rdi = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,

    const Self = @This();

    pub inline fn intoReg(self: Self) Reg {
        return switch (self) {
            inline .rax => Reg.rax,
            inline .rcx => Reg.rcx,
            inline .rdx => Reg.rdx,
            inline .rbx => Reg.rbx,
            inline .rbp => Reg.rbp,
            inline .rsi => Reg.rsi,
            inline .rdi => Reg.rdi,
            inline .r8 => Reg.r8,
            inline .r9 => Reg.r9,
            inline .r10 => Reg.r10,
            inline .r11 => Reg.r11,
            inline .r12 => Reg.r12,
            inline .r13 => Reg.r13,
            inline .r14 => Reg.r14,
            inline .r15 => Reg.r15,
        };
    }

    pub inline fn name(self: Self) []const u8 {
        return self.intoReg().name();
    }

    pub inline fn name32(self: Self) []const u8 {
        return self.intoReg().name32();
    }

    pub inline fn name16(self: Self) []const u8 {
        return self.intoReg().name16();
    }

    pub inline fn name8(self: Self) []const u8 {
        return self.intoReg().name8();
    }

    pub inline fn nameFrom(self: Self, size: RegSize) []const u8 {
        return switch (size) {
            inline RegSize.R64 => self.name(),
            inline RegSize.R32 => self.name32(),
        };
    }

    pub fn fmt(self: Self) []const u8 {
        return self.intoReg().fmt();
    }
};

pub const SegReg = enum {
    fs,
    gs,

    pub fn fmt(self: Self) []const u8 {
        return @tagName(self);
    }
};

pub const Scale = enum(u2) {
    x1 = 0,
    x2 = 1,
    x4 = 2,
    x8 = 3,
};

pub const MemOp = union(enum) {
    /// segment:base + offset
    base_offset: struct {
        segment: ?SegReg,
        size: RegSize,
        base: Reg,
        offset: i32,
    },
    /// segment:base + index * scale + offset
    base_index_scale_offset: struct {
        segment: ?SegReg,
        size: RegSize,
        base: Reg,
        index: RegIndex,
        scale: Scale,
        offset: i32,
    },
    /// segment:base * scale + offset
    index_scale_offset: struct {
        segment: ?SegReg,
        size: RegSize,
        index: RegIndex,
        scale: Scale,
        offset: i32,
    },
    /// segment:offset
    offset: struct {
        segment: ?SegReg,
        size: RegSize,
        offset: i32,
    },
    /// segment:rip + offset
    rip_relative: struct {
        segment: ?SegReg,
        offset: i32,
    },

    const Self = @This();

    inline fn needsRex(self: Self) bool {
        return switch (self) {
            .base_offset => |op| op.base.needsRex(),
            .base_index_scale_offset => |op| op.base.needsRex() || op.index.intoReg().needsRex(),
            .index_scale_offset => |op| op.index.intoReg().needsRex(),
            .offset => false,
            .rip_relative => false,
        };
    }

    inline fn simplify(self: Self) Self {
        return switch (self) {
            // Use a more compact encoding if possible.
            .index_scale_offset => |op| {
                if (op.scale == .x1) {
                    return .{ .base_offset = .{
                        .segment = op.segment,
                        .size = op.size,
                        .base = op.index.intoReg(),
                        .offset = op.offset,
                    } };
                } else {
                    return self;
                }
            },
            else => self,
        };
    }

    // TODO: fix it
    fn fmt(self: Self) []const u8 {
        const (segment, base, index, offset_reg_size, offset) = switch (self.simplify()) {
            .base_offset => |op| .{
                op.segment,
                .{ op.size, op.base },
                null,
                op.size,
                op.offset,
            },
            .base_index_scale_offset => |op| .{
                op.segment,
                .{ op.reg_size, op.base },
                .{ op.reg_size, op.index, op.scale },
                op.size,
                op.offset,
            },
            .index_scale_offset => |op| .{
                op.segment,
                null,
                .{ op.reg_size, op.index, op.scale },
                op.size,
                op.offset,
            },
            .offset => |op| .{
                op.segment,
                null,
                null,
                op.size,
                op.offset,
            },
            .rip_relative => |op| {
                var str = std.ArrayList(u8).init(std.heap.page_allocator);
                defer str.deinit();

                if(op.segment) |segment| {
                    str.appendSlice(segment.fmt()) catch unreachable;
                    str.append(':') catch unreachable;
                }

                str.append("rip") catch unreachable;
                if(op.offset > 0) {
                    str.appendPrint("+0x{x}", .{op.offset}) catch unreachable;
                } else if(op.offset < 0) {
                    str.appendPrint("-0x{x}", .{-@as(i64, op.offset)}) catch unreachable;
                }
                str.append("]") catch unreachable;
                return str.toOwnedSlice();
            },
        };
    }
};

pub const RegMem = union(enum) {
    reg: Reg,
    mem: MemOp,

    const Self = @This();

    // TODO: fn fmt.Display
    // TODO: fn displayWithoutPrefix
    // TODO: fn display

    /// from for Reg
    fn fromReg(reg: Reg) Self {
        return .{ .reg = reg };
    }

    /// from for RegIndex
    fn fromRegIndex(reg: RegIndex) Self {
        return .{ .reg = reg.intoReg() };
    }

    /// from for MemOp
    fn fromMem(mem: MemOp) Self {
        return .{ .mem = mem };
    }
};

pub const Operands = union(enum) {
    reg_mem_reg: struct {
        size: Size,
        reg_mem: RegMem,
        reg: Reg,
    },
    reg_reg_mem: struct {
        size: Size,
        reg: Reg,
        reg_mem: RegMem,
    },
    reg_mem_imm: struct {
        reg_mem: RegMem,
        imm: ImmKind,
    },
};

pub const Inst = struct {
    op_rep_prefix: bool,
    override_op_size: bool,
    override_addr_size: bool,
    op_alt: bool,
    force_enable_modrm: bool,
    rex: u8,
    opcode: u8,
    modrm: u8,
    sib: u8,
    displacement: u32,
    displacement_length: u32,
    immediate: u32,
    immediate_length: u32,
    override_segment: ?SegReg,

    const Self = @This();

    // See: https://www-user.tu-chemnitz.de/~heha/hsn/chm/x86.chm/x64.htm
    inline fn new(opcode: u8) Self {
        return Self{
            .op_rep_prefix = false,
            .override_op_size = false,
            .override_addr_size = false,
            .op_alt = false,
            .force_enable_modrm = false,
            .rex = 0,
            .opcode = opcode,
            .modrm = 0,
            .sib = 0,
            .displacement = 0,
            .displacement_length = 0,
            .immediate = 0,
            .immediate_length = 0,
            .override_segment = null,
        };
    }

    inline fn withRegInOp(opcode: u8, reg: Reg) Self {
        return Self.new(opcode | reg.modrmRmBits()).rexFromReg(reg);
    }

    inline fn opRepPrefix(self: *Self) *Self {
        self.op_rep_prefix = true;
        return self;
    }

    inline fn overrideOpSize(self: *Self) *Self {
        self.override_op_size = true;
        return self;
    }

    inline fn overrideOpSizeIf(self: *Self, cond: bool) *Self {
        if (cond) {
            self.override_op_size = true;
        }
        return self;
    }

    inline fn overrideAddrSizeIf(self: *Self, cond: bool) *Self {
        if (cond) {
            self.override_addr_size = true;
        }
        return self;
    }

    inline fn opAlt(self: *Self) *Self {
        self.op_alt = true;
        return self;
    }

    inline fn setRex(self: *Self) *Self {
        self.rex |= REX;
        return self;
    }

    inline fn rexIf(self: *Self, cond: bool) *Self {
        if (cond) {
            self.rex |= REX;
        }
        return self;
    }

    inline fn rexFromReg(self: *Self, reg: Reg) *Self {
        if (reg.needsRex()) {
            self.rex |= REX_EXT_MODRM_RM;
        }
        return self;
    }

    inline fn rex64b(self: *Self) *Self {
        self.rex |= REX_64B_OP;
        return self;
    }

    inline fn rex64bIf(self: *Self, cond: bool) *Self {
        if (cond) {
            self.rex |= REX_64B_OP;
        }
        return self;
    }

    inline fn modrmRmDirect(self: *Self, value: Reg) *Self {
        if (value.needsRex()) {
            self.rex |= REX_EXT_MODRM_RM;
        }
        self.modrm |= value.modrmRmBits() | 0b11000000;
        return self;
    }

    inline fn regmem(self: *Self, operand: RegMem) *Self {
        return switch (operand) {
            .reg => |reg| self.modrmRmDirect(reg),
            .mem => |mem_op| self.mem(mem_op),
        };
    }

    // TODO: review cast
    inline fn mem(self: *Self, operand: MemOp) *Self {
        const simplified = operand.simplify();
        switch (simplified) {
            .base_offset => |op| {
                self.force_enable_modrm = true;

                if (op.base.needsRex()) {
                    self.rex |= REX_EXT_MODRM_RM;
                }

                if (op.base == Reg.rsp or op.base == Reg.r12) {
                    self.sib = 0b00100100;
                }

                self.modrm |= op.base.modrmRmBits();

                const set_displacement = (op.offset != 0) or (op.base == Reg.rbp or op.base == Reg.r13);
                const set_displacement_i32: i32 = @intCast(set_displacement);
                const set_displacement_mask: u32 = @truncate(set_displacement_i32 * -1);

                const set_displacement_mask_u8: u8 = @truncate(set_displacement_mask);
                if (op.offset <= @as(i32, std.math.maxInt(i8)) and op.offset >= @as(i32, std.math.minInt(i8))) {
                    self.modrm |= 0b01000000 & set_displacement_mask_u8;
                    const offset_u8: u8 = @truncate(op.offset);
                    const offset_u32: u32 = @bitCast(offset_u8);
                    self.displacement = offset_u32 & set_displacement_mask;
                    self.displacement_length = 8 & set_displacement_mask;
                } else {
                    self.modrm |= 0b10000000 & set_displacement_mask_u8;
                    const offset_u32: u32 = @bitCast(op.offset);
                    self.displacement = offset_u32 & set_displacement_mask;
                    self.displacement_length = 32 & set_displacement_mask;
                }

                self.override_segment = op.segment;
                self.overrideAddrSizeIf(op.size == RegSize.R32);
            },
            .base_index_scale_offset => |op| {
                if (op.base.needsRex()) {
                    self.rex |= REX_EXT_MODRM_RM;
                }

                if (op.index.intoReg().needsRex()) {
                    self.rex |= REX_EXT_MODRM_SIB_INDEX;
                }

                self.modrm |= 0b00000100;
                self.sib |= op.index.intoReg().modrmRegBits();
                self.sib |= op.base.modrmRmBits();
                self.sib |= @truncate(@as(usize, op.scale) << 6);

                const set_displacement = (op.offset != 0) or (op.base == Reg.rbp or op.base == Reg.r13);
                const set_displacement_i32: i32 = @intCast(set_displacement);
                const set_displacement_mask: u32 = @truncate(set_displacement_i32 * -1);

                const set_displacement_mask_u8: u8 = @truncate(set_displacement_mask);
                if (op.offset <= @as(i32, std.math.maxInt(i8)) and op.offset >= @as(i32, std.math.minInt(i8))) {
                    self.modrm |= 0b01000000 & set_displacement_mask_u8;
                    const offset_u8: u8 = @truncate(op.offset);
                    const offset_u32: u32 = @bitCast(offset_u8);
                    self.displacement = offset_u32 & set_displacement_mask;
                    self.displacement_length = 8 & set_displacement_mask;
                } else {
                    self.modrm |= 0b10000000 & set_displacement_mask_u8;
                    const offset_u32: u32 = @bitCast(op.offset);
                    self.displacement = offset_u32 & set_displacement_mask;
                    self.displacement_length = 32 & set_displacement_mask;
                }

                self.override_segment = op.segment;
                return self.override_addr_size_if(op.size == RegSize.R32);
            },
            .index_scale_offset => |op| {
                if (op.index.intoReg().needsRex()) {
                    self.rex |= REX_EXT_MODRM_SIB_INDEX;
                }

                self.modrm |= 0b00000100;
                self.sib |= op.index.intoReg().modrmRegBits();
                self.sib |= 0b00000101;
                const scale_u8: u8 = @truncate(op.scale);
                self.sib |= @bitCast(scale_u8 << 6);
                self.displacement = @bitCast(op.offset);
                self.displacement_length = 32;
                self.override_segment = op.segment;
                return self.override_addr_size_if(op.size == RegSize.R32);
            },
            .offset => |op| {
                self.modrm |= 0b00000100;
                self.sib |= 0b00100101;
                self.displacement = @bitCast(op.offset);
                self.displacement_length = 32;
                self.override_segment = op.segment;
                return self.override_addr_size_if(op.size == RegSize.R32 and op.offset < 0);
            },
            .rip_relative => |op| {
                self.modrm |= 0b00000101;
                self.displacement = @bitCast(op.offset);
                self.override_segment = op.segment;
                return self;
            },
        }
    }

    inline fn modrmReg(self: *Self, value: Reg) *Self {
        if (value.needsRex()) {
            self.rex |= REX_EXT_MODRM_REG;
        }
        self.modrm |= value.modrmRegBits();
        self.force_enable_modrm = true;
        return self;
    }

    inline fn modrmOpExt(self: *Self, ext: u8) *Self {
        self.modrm |= ext << 3;
        self.force_enable_modrm = true;
        return self;
    }

    inline fn imm8(self: *Self, value: u8) *Self {
        self.immediate = value;
        self.immediate_length = 8;
        return self;
    }

    inline fn imm16(self: *Self, value: u16) *Self {
        self.immediate = value;
        self.immediate_length = 16;
        return self;
    }

    inline fn imm32(self: *Self, value: u32) *Self {
        self.immediate = value;
        self.immediate_length = 32;
        return self;
    }

    fn encode(self: *Self) InstBuf {
        var enc = InstBuf.init();
        self.encodeInto(&enc);
        return enc;
    }

    fn encodeInto(self: *Self, buf: *InstBuf) void {
        if (self.op_rep_prefix) {
            buf.append(PREFIX_REP);
        }

        switch (self.override_segment) {
            .fs => buf.append(PREFIX_OVERRIDE_SEGMENT_FS),
            .gs => buf.append(PREFIX_OVERRIDE_SEGMENT_GS),
            else => {},
        }

        if (self.override_op_size) {
            buf.append(PREFIX_OVERRIDE_OP_SIZE);
        }

        if (self.override_addr_size) {
            buf.append(PREFIX_OVERRIDE_ADDR_SIZE);
        }

        if (self.rex != 0) {
            buf.append(self.rex);
        }

        if (self.op_alt) {
            buf.append(0x0f);
        }

        buf.append(self.opcode);

        if (self.modrm != 0 or self.force_enable_modrm) {
            buf.append(self.modrm);
            if (self.modrm & 0b11000000 != 0b11000000 and self.modrm & 0b111 == 0b100) {
                buf.append(self.sib);
            }
        }

        buf.append_packed_bytes(self.displacement, self.displacement_length);
        buf.append_packed_bytes(self.immediate, self.immediate_length);
    }
};

// macro impl_inst
/// Define an instruction type with encoding, fixup, and formatting capabilities
pub fn InstructionType(comptime name: []const u8, comptime Args: type, comptime encodeFn: fn (args: Args) InstBuf, comptime fixupFn: fn (args: Args) ?Fixup, comptime formatFn: fn (args: Args, writer: anytype) anyerror!void) type {
    return struct {
        args: Args,

        const Self = @This();

        pub fn init(args: Args) Self {
            return .{ .args = args };
        }

        pub inline fn encode(self: Self) InstBuf {
            return encodeFn(self.args);
        }

        pub inline fn fixup(self: Self) ?Fixup {
            return fixupFn(self.args);
        }

        pub fn format(
            self: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            return formatFn(self.args, writer);
        }
    };
}

/// Helper to create a collection of instruction types
pub fn defineInstructions(comptime defs: anytype) type {
    comptime {
        // Create a struct to hold all instruction types
        var fields: [defs.len]std.builtin.Type.StructField = undefined;

        inline for (defs, 0..) |def, i| {
            const Args = def.args;
            const encode_fn = def.encode;
            const fixup_fn = def.fixup;
            const format_fn = def.format;

            fields[i] = .{
                .name = def.name,
                .type = InstructionType(def.name, Args, encode_fn, fixup_fn, format_fn),
                .default_value = null,
                .is_comptime = false,
                .alignment = @alignOf(u8),
            };
        }

        return @Type(.{
            .Struct = .{
                .layout = .Auto,
                .fields = &fields,
                .decls = &[_]std.builtin.Type.Declaration{},
                .is_tuple = false,
            },
        });
    }
}

fn generate_test_values0() void {}

fn generate_test_values1() void {}

fn generate_test_values2() void {}

fn generate_test_values3() void {}

fn generate_test_values4() void {}

fn generate_test_values5() void {}

fn generate_test_values6() void {}

test "Test amd64" {}

pub const Condition = enum(u8) {
    Overflow = 0,
    NotOverflow = 1,
    Below = 2, // For unsigned values.
    AboveOrEqual = 3, // For unsigned values.
    Equal = 4,
    NotEqual = 5,
    BelowOrEqual = 6, // For unsigned values.
    Above = 7, // For unsigned values.
    Sign = 8,
    NotSign = 9,
    Parity = 10,
    NotParity = 11,
    Less = 12, // For signed values.
    GreaterOrEqual = 13, // For signed values.
    LessOrEqual = 14, // For signed values.
    Greater = 15, // For signed values.

    const Self = @This();

    fn suffix(self: Self) []const u8 {
        return switch (self) {
            .Overflow => "o",
            .NotOverflow => "no",
            .Below => "b",
            .AboveOrEqual => "ae",
            .Equal => "e",
            .NotEqual => "ne",
            .BelowOrEqual => "be",
            .Above => "a",
            .Sign => "s",
            .NotSign => "ns",
            .Parity => "p",
            .NotParity => "np",
            .Less => "l",
            .GreaterOrEqual => "ge",
            .LessOrEqual => "le",
            .Greater => "g",
        };
    }
};

pub const RegSize = enum {
    R32,
    R64,
};

/// U64 is the default
pub const LoadKind = enum {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
};

/// U64 is the default
pub const Size = enum {
    U8,
    U16,
    U32,
    U64,

    const Self = @This();

    fn name(self: Self) []const u8 {
        return switch (self) {
            .U8 => "byte",
            .U16 => "word",
            .U32 => "dword",
            .U64 => "qword",
        };
    }

    fn from(reg_size: RegSize) Self {
        return switch (reg_size) {
            RegSize.R32 => .U32,
            RegSize.R64 => .U64,
        };
    }
};

pub const ImmKind = union(enum) {
    I8: u8,
    I16: u16,
    I32: u32,
    I64: i32,

    // TODO: fmt
    const Self = @This();

    inline fn size(self: Self) Size {
        return switch (self) {
            .I8 => Size.U8,
            .I16 => Size.U16,
            .I32 => Size.U32,
            .I64 => Size.U64,
        };
    }
};

// tests
