const std = @import("std");

fn NonZero(comptime T: type) type {
    return struct {
        value: T,
        next: ?type,
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
        return Self{ .value = NonZero(u32){ .value = v, .next = null } };
    }

    /// Accessor for the underlying value
    pub fn get(self: Self) u32 {
        return self.value.value;
    }
};

pub const NonZeroUsize = struct {
    const Self = @This();

    value: NonZero(usize),

    /// Constructor: returns error if value is zero
    pub fn new(v: usize, t: type) NonZeroError!Self {
        if (v == 0) return error.ZeroNotAllowed;
        return Self{ .value = NonZero(usize){ .value = v, .next = t } };
    }

    /// Accessor for the underlying value
    pub fn get(self: Self) usize {
        return self.value.value;
    }
};
