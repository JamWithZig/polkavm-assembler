const NonZeroU32 = @import("non_zero.zig").NonZeroU32;

pub const Label = struct {
    const Self = @This();

    non_zero: NonZeroU32,

    pub inline fn raw(self: *Self) u32 {
        return self.non_zero.get() - 1;
    }

    pub inline fn from_raw(value: u32) ?Self {
        if (value == 0) return null;
        return Self{ .non_zero = NonZeroU32.new(value + 1) };
    }
};
