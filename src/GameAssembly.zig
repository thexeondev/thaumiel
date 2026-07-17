const GameAssembly = @This();
const std = @import("std");

const nt = @import("nt.zig");

handle: std.os.windows.PVOID,

pub const LoadError = error{LoadDllFailed};

pub fn load(syscall: *nt.Syscall) LoadError!GameAssembly {
    const w = std.os.windows;

    var assembly: GameAssembly = undefined;
    return switch (w.ntdll.LdrLoadDll(
        null, // DllPath
        null, // DllCharacteristics
        &.initZ(&.{ 'G', 'a', 'm', 'e', 'A', 's', 's', 'e', 'm', 'b', 'l', 'y', '.', 'd', 'l', 'l' }),
        &assembly.handle,
    )) {
        .SUCCESS => assembly,
        else => |status| syscall.fail(error.LoadDllFailed, status),
    };
}

const Offsets = struct {
    IsLoadMHYBase: usize,
    @"System.Runtime.InteropServices.Marshal::PtrToStringAnsi": usize,
    @"Foundation.Assets::SetLoginSettingByJson": usize,
    @"MiHoYo.SDK.SDKDelegate.LoadFileDelegate::Invoke": usize,
    sdk_rsa_keys: []const usize,
    crypto_str: usize,
    @"MiHoYo.SDK.DeviceFPManager::GetDeviceFP": usize,
    static_table: usize,
    @"System.Security.Cryptography.RSA::Create": usize,
    @"System.Security.Cryptography.RSA::FromXmlString": usize,
    @"Foundation.RSAUtil::PublicRsaKey": usize,
    dither_alpha_strings: []const usize,
    @"MoleMole.UIMainCityMiniMenuWidgetController::RefreshGachaTimeIcon": usize,

    pub const Tag = std.meta.FieldEnum(Offsets);
};

const offsets: Offsets = @import("offsets.zon");

pub inline fn add(g: GameAssembly, offset: Offsets.Tag) usize {
    return @intFromPtr(g.handle) + @field(offsets, @tagName(offset));
}

pub inline fn addMany(
    g: GameAssembly,
    tag: Offsets.Tag,
) [@field(offsets, @tagName(tag)).len]usize {
    const group = @field(offsets, @tagName(tag));
    var addresses: [group.len]usize = undefined;

    for (group, &addresses) |offset_value, *address|
        address.* = @intFromPtr(g.handle) + offset_value;

    return addresses;
}

pub const String = opaque {
    pub fn allocZ(g: GameAssembly, content: [*:0]const u8) *String {
        const ptrToStringAnsi: *const fn ([*:0]const u8) callconv(.c) *String =
            @ptrFromInt(g.add(.@"System.Runtime.InteropServices.Marshal::PtrToStringAnsi"));

        return ptrToStringAnsi(content);
    }

    pub fn slice(string: *String) []const u16 {
        const len = @as(*u32, @ptrFromInt(@intFromPtr(string) + 16)).*;
        return @as([*]u16, @ptrFromInt(@intFromPtr(string) + 20))[0..len];
    }
};

pub fn setLoginSettingByJson(g: GameAssembly, json: [:0]const u8) void {
    const setLoginSettingByJsonImpl: *const fn (*const String) callconv(.c) void =
        @ptrFromInt(g.add(.@"Foundation.Assets::SetLoginSettingByJson"));
    setLoginSettingByJsonImpl(.allocZ(g, json.ptr));
}

pub fn setServerPublicKey(g: GameAssembly, rsa: *anyopaque) void {
    const statics: **anyopaque = @ptrFromInt(g.add(.static_table));
    @as(**anyopaque, @ptrFromInt(@intFromPtr(statics.*) +
        offsets.@"Foundation.RSAUtil::PublicRsaKey")).* = rsa;
}
