const misc = @import("misc.zig");
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

    pub fn is_reg_preserved(self: Reg) bool {
        // See page 23 from: https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf
        return switch (self) {
            Reg.rbx, Reg.rsp, Reg.rbp, Reg.r12, Reg.r13, Reg.r14, Reg.r15 => true,
            Reg.rax, Reg.rcx, Reg.rdx, Reg.rsi, Reg.rdi, Reg.r8, Reg.r9, Reg.r10, Reg.r11 => false,
        };
    }

    pub inline fn needs_rex(self: Reg) bool {
        return @as(usize, self) >= @as(usize, Reg.r8);
    }

    pub inline fn modrm_rm_bits(self: Reg) u8 {
        return @as(u8, @as(usize, self) & 0b111);
    }

    pub inline fn modrm_reg_bits(self: Reg) u8 {
        return @as(u8, (@as(usize, self) << 3) & 0b111000);
    }

    pub inline fn rex_bit(self: Reg) u8 {
        if (@as(usize, self) >= @as(usize, Reg.r8)) {
            return REX_EXT_MODRM_RM;
        } else {
            return 0;
        }
    }

    pub inline fn rex_modrm_reg(self: Reg) u8 {
        if (@as(usize, self) >= @as(usize, Reg.r8)) {
            return REX_EXT_MODRM_REG;
        } else {
            return 0;
        }
    }

    pub fn name_from(self: Reg, size: RegSize) []const u8 {
        return switch (size) {
            RegSize.R64 => self.name(),
            RegSize.R32 => self.name32(),
        };
    }

    pub fn name_from_size(self: Reg, kind: Size) []const u8 {
        return switch (kind) {
            Size.U64 => self.name(),
            Size.U32 => self.name32(),
            Size.U16 => self.name16(),
            Size.U8 => self.name8(),
        };
    }

    pub fn name(self: Reg) []const u8 {
        return reg_names_64[@enumToInt(self)];
    }

    pub fn name32(self: Reg) []const u8 {
        return reg_names_32[@enumToInt(self)];
    }

    pub fn name16(self: Reg) []const u8 {
        return reg_names_16[@enumToInt(self)];
    }

    pub fn name8(self: Reg) []const u8 {
        return reg_names_8[@enumToInt(self)];
    }
}

comptime {
    const regs = [_][4][]const u8{
        .{ "rax",  "eax",  "ax",  "al" },
        .{ "rcx",  "ecx",  "cx",  "cl" },
        .{ "rdx",  "edx",  "dx",  "dl" },
        .{ "rbx",  "ebx",  "bx",  "bl" },
        .{ "rsp",  "esp",  "sp",  "spl" },
        .{ "rbp",  "ebp",  "bp",  "bpl" },
        .{ "rsi",  "esi",  "si",  "sil" },
        .{ "rdi",  "edi",  "di",  "dil" },
        .{ "r8",   "r8d",  "r8w", "r8b" },
        .{ "r9",   "r9d",  "r9w", "r9b" },
        .{ "r10",  "r10d", "r10w","r10b" },
        .{ "r11",  "r11d", "r11w","r11b" },
        .{ "r12",  "r12d", "r12w","r12b" },
        .{ "r13",  "r13d", "r13w","r13b" },
        .{ "r14",  "r14d", "r14w","r14b" },
        .{ "r15",  "r15d", "r15w","r15b" },
    };

    const reg_names_64 = [_][]const u8{
        for (regs) |reg| reg[0],
    };
    const reg_names_32 = [_][]const u8{
        for (regs) |reg| reg[1],
    };
    const reg_names_16 = [_][]const u8{
        for (regs) |reg| reg[2],
    };
    const reg_names_8 = [_][]const u8{
        for (regs) |reg| reg[3],
    };
}

pub enum RegIndex {
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


    inline fn from(reg: RegIndex) Reg {
        reg.into_reg()
    }

    pub inline fn into_reg(self: RegIndex) Reg {
        return switch (self) {
            RegIndex.rax => Reg.rax,
            RegIndex.rcx => Reg.rcx,
            RegIndex.rdx => Reg.rdx,
            RegIndex.rbx => Reg.rbx,
            RegIndex.rbp => Reg.rbp,
            RegIndex.rsi => Reg.rsi,
            RegIndex.rdi => Reg.rdi,
            RegIndex.r8 => Reg.r8,
            RegIndex.r9 => Reg.r9,
            RegIndex.r10 => Reg.r10,
            RegIndex.r11 => Reg.r11,
            RegIndex.r12 => Reg.r12,
            RegIndex.r13 => Reg.r13,
            RegIndex.r14 => Reg.r14,
            RegIndex.r15 => Reg.r15,
        };
    }

    pub inline fn name(self: RegIndex) []const u8 {
        return self.into_reg().name();
    }

    pub inline fn name32(self: RegIndex) []const u8 {
        return self.into_reg().name32();
    }

    pub inline fn name16(self: RegIndex) []const u8 {
        return self.into_reg().name16();
    }

    pub inline fn name8(self: RegIndex) []const u8 {
        return self.into_reg().name8();
    }

    pub inline fn name_from(self: RegIndex, size: RegSize) []const u8 {
        return switch (size) {
            RegSize.R64 => self.name(),
            RegSize.R32 => self.name32(),
        };
    }

    // TODO: implement Display
}

pub const SegReg = enum {
    fs,
    gs,
};

pub const Scale = enum(u2) {
    x1 = 0,
    x2 = 1,
    x4 = 2,
    x8 = 3,
};

pub const MemOp = struct {
    /// segment:base + offset
    base_offset: struct {
        segment: ?SegReg,
        base: Reg,
        offset: i32,
    },
    /// segment:base + index * scale + offset
    base_index_scale_offset: struct {
        segment: ?SegReg,
        base: Reg,
        index: Reg,
        scale: Scale,
        offset: i32,
    },

    const Self = @This();

    inline fn needs_rex(self: Self) bool {
        return switch (self) {
            MemOp::BaseOffset(_, _, base, _) => base.needs_rex(),
            MemOp::BaseIndexScaleOffset(_, _, base, index, _, _) => base.needs_rex() || index.into_reg().needs_rex(),
            MemOp::IndexScaleOffset(_, _, index, _, _) => index.into_reg().needs_rex(),
            MemOp::Offset(..) => false,
            MemOp::RipRelative(..) => false,
        };
    }

    inline fn simplify(self: Self) Self {
        return switch (self) {
            // Use a more compact encoding if possible.
            MemOp::IndexScaleOffset(segment, reg_size, index, Scale.x1, offset) => {
                MemOp::BaseOffset(segment, reg_size, index.into_reg(), offset)
            }
            operand => operand,
        }
    }
};

pub enum RegMem {
    Reg(Reg),
    Mem(MemOp),
}

pub enum Operands {
    RegMem_Reg(Size, RegMem, Reg),
    Reg_RegMem(Size, Reg, RegMem),
    RegMem_Imm(RegMem, ImmKind),
}
