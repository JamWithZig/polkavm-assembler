const std = @import("std");

fn NonZero(comptime T: type) type {
    return struct {
        value: T,
    };
}

pub const NonZeroError = error{
    ZeroNotAllowed,
};

pub const NonZeroU32 = struct {
    const Self = @This();

    value: NonZero(u32),

    /// Constructor: returns error if value is zero
    pub fn new(v: u32) NonZeroError!Self {
        if (v == 0) return error.ZeroNotAllowed;
        return Self{ .value = NonZero(u32){ .value = v } };
    }

    /// Accessor for the underlying value
    pub fn get(self: Self) u32 {
        return self.value.value;
    }
};
