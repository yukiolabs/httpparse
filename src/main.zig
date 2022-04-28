const std = @import("std");
const root = @import("root");

var default_gpa = std.heap.GeneralPurposeAllocator(.{}){};

var gpa: std.mem.Allocator = if (@hasDecl(root, "gpa")) root.gpa else default_gpa.allocator();

/// Determines if byte is a token char.
///
/// > ```notrust
/// > token          = 1*tchar
/// >
/// > tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
/// >                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
/// >                / DIGIT / ALPHA
/// >                ; any VCHAR, except delimiters
/// > ```
inline fn is_token(b: u8) bool {
    return b > 0x1F and b < 0x7F;
}

const URI_MAP: [256]u1 = [_]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //  \0                            \n
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //  commands
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //  \w !  "  #  $  %  &  '  (  )  *  +  ,  -  .  /
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
    //  0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ?
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //  @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //  P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //  `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    //  p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~  del
    //   ====== Extended ASCII (aka. obs-text) ======
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

inline fn is_uri_token(b: u8) bool {
    return URI_MAP[@intCast(usize, b)] == 1;
}

const HEADER_NAME_MAP: [256]u1 = [_]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

inline fn is_header_name_token(b: u8) bool {
    return HEADER_NAME_MAP[@intCast(usize, b)] == 1;
}

const HEADER_VALUE_MAP: [256]u1 = [_]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

inline fn is_header_value_token(b: u8) bool {
    return HEADER_VALUE_MAP[@intCast(usize, b)] == 1;
}

pub const Error = error{
    /// Invalid byte in header name.
    HeaderName,
    /// Invalid byte in header value.
    HeaderValue,
    /// Invalid byte in new line.
    NewLine,
    /// Invalid byte in Response status.
    Status,
    /// Invalid byte where token is required.
    Token,
    /// Parsed more headers than provided buffer can contain.
    TooManyHeaders,
    /// Invalid byte in HTTP version.
    Version,
    /// We do allocate headers using gpa.
    OutOfMemory,
    InvalidChunkSize,
};

pub fn Status(comptime T: type) type {
    return union(enum) {
        /// The completed result.
        Complete: T,
        /// A partial result.
        Partial,

        const Self = @This();

        pub fn is_complete(self: Self) bool {
            return switch (self) {
                .Complete => true,
                .Partial => false,
            };
        }

        pub fn is_partial(self: Self) bool {
            return switch (self) {
                .Complete => false,
                .Partial => true,
            };
        }

        pub fn unwrap(self: Self) T {
            return switch (self) {
                .Complete => |t| t,
                .Partial => unreachable,
            };
        }
    };
}

pub const ParserConfig = struct {
    /// Sets whether spaces should be allowed after header name.
    allow_spaces_after_header_name_in_responses: bool = false,

    /// Sets whether multiple spaces are allowed as delimiters in request lines.
    ///
    /// # Background
    ///
    /// The [latest version of the HTTP/1.1 spec][spec] allows implementations to parse multiple
    /// whitespace characters in place of the `SP` delimiters in the request line, including:
    ///
    /// > SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
    ///
    /// This option relaxes the parser to allow for multiple spaces, but does *not* allow the
    /// request line to contain the other mentioned whitespace characters.
    ///
    /// [spec]: https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#rfc.section.3.p.3
    allow_obsolete_multiline_headers_in_responses: bool = false,

    /// Whether multiple spaces are allowed as delimiters in request lines.
    allow_multiple_spaces_in_request_line_delimiters: bool = false,

    /// Sets whether multiple spaces are allowed as delimiters in response status lines.
    ///
    /// # Background
    ///
    /// The [latest version of the HTTP/1.1 spec][spec] allows implementations to parse multiple
    /// whitespace characters in place of the `SP` delimiters in the response status line,
    /// including:
    ///
    /// > SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
    ///
    /// This option relaxes the parser to allow for multiple spaces, but does *not* allow the status
    /// line to contain the other mentioned whitespace characters.
    ///
    /// [spec]: https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#rfc.section.4.p.3
    allow_multiple_spaces_in_response_status_delimiters: bool = false,
};

pub const Request = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    version: ?u8 = null,
    headers: std.ArrayList(Header),

    pub fn new() Request {
        return Request{
            .headers = std.ArrayList(Header).init(gpa),
        };
    }

    pub fn deinit(self: *Request) void {
        self.headers.deinit();
    }

    pub fn parse(
        self: *Request,
        buf: []const u8,
    ) Error!Status(usize) {
        return self.parse_with_config(buf, .{});
    }
    pub fn parse_with_config(
        self: *Request,
        buf: []const u8,
        config: ParserConfig,
    ) Error!Status(usize) {
        const orig_len = buf.len;
        var bytes = &Bytes{ .slice = buf };
        switch (try skip_empty_lines(bytes)) {
            .Complete => {},
            .Partial => return .Partial,
        }
        self.method = switch (try parse_token(bytes)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        if (config.allow_multiple_spaces_in_request_line_delimiters) {
            switch (try skip_spaces(bytes)) {
                .Complete => {},
                .Partial => return .Partial,
            }
        }
        self.path = switch (try parse_uri(bytes)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        if (config.allow_multiple_spaces_in_request_line_delimiters) {
            switch (try skip_spaces(bytes)) {
                .Complete => {},
                .Partial => return .Partial,
            }
        }
        self.version = switch (try parse_version(bytes)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        const b = bytes.next() orelse return .Partial;
        switch (b) {
            '\r' => {
                const next = bytes.next() orelse return .Partial;
                try expect(next, '\n', error.NewLine);
                _ = bytes.slice_skip(0);
            },
            '\n' => {
                _ = bytes.slice_skip(0);
            },
            else => return error.NewLine,
        }
        const len = orig_len - bytes.slice.len;
        const headers_len = switch (try parse_headers(&self.headers, bytes, config)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        return Status(usize){ .Complete = len + headers_len };
    }
};

inline fn skip_empty_lines(bytes: *Bytes) Error!Status(void) {
    while (true) {
        const b = bytes.peek() orelse return .Partial;
        switch (b) {
            '\r' => {
                bytes.bump();
                const next = bytes.next() orelse return .Partial;
                try expect(next, '\n', error.NewLine);
            },
            '\n' => bytes.bump(),
            else => {
                _ = bytes.slice_skip(0);
                return Status(void){ .Complete = {} };
            },
        }
    }
}

inline fn skip_spaces(bytes: *Bytes) Error!Status(void) {
    while (true) {
        const b = bytes.peek() orelse return .Partial;
        switch (b) {
            ' ' => {
                bytes.bump();
            },
            else => {
                _ = bytes.slice_skip(0);
                return Status(void){ .Complete = {} };
            },
        }
    }
}

pub const Response = struct {
    version: ?u8 = null,
    code: ?u16 = null,
    reason: ?[]const u8 = null,
    headers: std.ArrayList(Header),

    pub fn new() Response {
        return .{
            .headers = std.ArrayList(Header).init(gpa),
        };
    }

    pub fn deinit(self: *Response) void {
        self.headers.deinit();
    }

    pub fn parse(
        self: *Response,
        buf: []const u8,
    ) Error!Status(usize) {
        return self.parse_with_config(buf, .{});
    }

    pub fn parse_with_config(
        self: *Response,
        buf: []const u8,
        config: ParserConfig,
    ) Error!Status(usize) {
        const orig_len = buf.len;
        var bytes = &Bytes{ .slice = buf };
        switch (try skip_empty_lines(bytes)) {
            .Complete => {},
            .Partial => return .Partial,
        }
        self.version = switch (try parse_version(bytes)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        var next = bytes.next() orelse return .Partial;
        try expect(next, ' ', error.Version);
        _ = bytes.slice_skip(0);
        if (config.allow_multiple_spaces_in_response_status_delimiters) {
            switch (try skip_spaces(bytes)) {
                .Complete => {},
                .Partial => return .Partial,
            }
        }
        self.code = switch (try parse_code(bytes)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        // RFC7230 says there must be 'SP' and then reason-phrase, but admits
        // its only for legacy reasons. With the reason-phrase completely
        // optional (and preferred to be omitted) in HTTP2, we'll just
        // handle any response that doesn't include a reason-phrase, because
        // it's more lenient, and we don't care anyways.
        //
        // So, a SP means parse a reason-phrase.
        // A newline means go to headers.
        // Anything else we'll say is a malformed status.

        const b = bytes.next() orelse return .Partial;
        switch (b) {
            ' ' => {
                if (config.allow_multiple_spaces_in_response_status_delimiters) {
                    switch (try skip_spaces(bytes)) {
                        .Complete => {},
                        .Partial => return .Partial,
                    }
                }
                _ = bytes.slice_skip(0);
                self.reason = switch (try parse_reason(bytes)) {
                    .Complete => |v| v,
                    .Partial => return .Partial,
                };
            },
            '\r' => {
                next = bytes.next() orelse return .Partial;
                try expect(next, '\n', error.Status);
                _ = bytes.slice_skip(0);
                self.reason = "";
            },
            '\n' => {
                _ = bytes.slice_skip(0);
                self.reason = "";
            },
            else => return error.Status,
        }
        const len = orig_len - bytes.slice.len;
        const headers_len = switch (try parse_headers(&self.headers, bytes, config)) {
            .Complete => |v| v,
            .Partial => return .Partial,
        };
        return Status(usize){ .Complete = len + headers_len };
    }
};

pub const Header = struct {
    name: []const u8 = "",
    value: []const u8 = "",
};

const Bytes = struct {
    slice: []const u8,
    pos: usize = 0,

    pub fn next_8(self: *Bytes) ?Bytes8 {
        if (self.slice.len > self.pos + 8) {
            return Bytes8{ .b = self };
        }
        return null;
    }

    pub inline fn peek(self: *Bytes) ?u8 {
        if (self.slice.len > self.pos) {
            return self.slice[self.pos];
        }
        return null;
    }

    pub inline fn bump(self: *Bytes) void {
        std.debug.assert(self.pos + 1 <= self.slice.len);
        self.pos += 1;
    }

    pub fn next(self: *Bytes) ?u8 {
        if (self.slice.len > self.pos) {
            const b = self.slice[self.pos];
            self.pos += 1;
            return b;
        }
        return null;
    }

    pub fn slice_skip(self: *Bytes, skip: usize) []const u8 {
        std.debug.assert(self.pos >= skip);
        const head_pos = self.pos - skip;
        var head = self.slice[0..head_pos];
        var tail = self.slice[self.pos..][0 .. self.slice.len - self.pos];
        self.pos = 0;
        self.slice = tail;
        return head;
    }
};

const Bytes8 = struct {
    b: *Bytes,

    fn _0(self: *Bytes8) u8 {
        return self.b.next().?;
    }
    fn _1(self: *Bytes8) u8 {
        return self.b.next().?;
    }
    fn _2(self: *Bytes8) u8 {
        return self.b.next().?;
    }
    fn _3(self: *Bytes8) u8 {
        return self.b.next().?;
    }
    fn _4(self: *Bytes8) u8 {
        return self.b.next().?;
    }
    fn _5(self: *Bytes8) u8 {
        return self.b.next().?;
    }
    fn _6(self: *Bytes8) u8 {
        return self.b.next().?;
    }

    fn _7(self: *Bytes8) u8 {
        return self.b.next().?;
    }
};

inline fn expect(d: u8, ch: u8, err: Error) Error!void {
    if (d != ch) return err;
}

inline fn parse_version(bytes: *Bytes) Error!Status(u8) {
    if (bytes.next_8()) |*eight| {
        try expect(eight._0(), 'H', error.Version);
        try expect(eight._1(), 'T', error.Version);
        try expect(eight._2(), 'T', error.Version);
        try expect(eight._3(), 'P', error.Version);
        try expect(eight._4(), '/', error.Version);
        try expect(eight._5(), '1', error.Version);
        try expect(eight._6(), '.', error.Version);
        const v: u8 = switch (eight._7()) {
            '0' => 0,
            '1' => 1,
            else => return error.Version,
        };
        return Status(u8){ .Complete = v };
    }
    var next = bytes.next() orelse return .Partial;
    try expect(next, 'H', error.Version);
    next = bytes.next() orelse return .Partial;
    try expect(next, 'T', error.Version);
    next = bytes.next() orelse return .Partial;
    try expect(next, 'T', error.Version);
    next = bytes.next() orelse return .Partial;
    try expect(next, 'P', error.Version);
    next = bytes.next() orelse return .Partial;
    try expect(next, '/', error.Version);
    next = bytes.next() orelse return .Partial;
    try expect(next, '1', error.Version);
    next = bytes.next() orelse return .Partial;
    try expect(next, '.', error.Version);
    return .Partial;
}

/// From [RFC 7230](https://tools.ietf.org/html/rfc7230):
///
/// > ```notrust
/// > reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
/// > HTAB           = %x09        ; horizontal tab
/// > VCHAR          = %x21-7E     ; visible (printing) characters
/// > obs-text       = %x80-FF
/// > ```
///
/// > A.2.  Changes from RFC 2616
/// >
/// > Non-US-ASCII content in header fields and the reason phrase
/// > has been obsoleted and made opaque (the TEXT rule was removed).
inline fn parse_reason(bytes: *Bytes) Error!Status([]const u8) {
    var seen_obs_text: bool = false;
    while (true) {
        const b = bytes.next() orelse return .Partial;
        if (b == '\r') {
            const next = bytes.next() orelse return .Partial;
            try expect(next, '\n', error.Status);
            const r = bytes.slice_skip(2);
            if (!seen_obs_text) return Status([]const u8){
                .Complete = r,
            };
            return Status([]const u8){
                .Complete = "",
            };
        } else if (b == '\n') {
            const r = bytes.slice_skip(1);
            if (!seen_obs_text) return Status([]const u8){
                .Complete = r,
            };
            return Status([]const u8){
                .Complete = "",
            };
        } else if (!(switch (b) {
            0x09, ' ', 0x21...0x7E => true,
            else => b >= 0x80,
        })) {
            return error.Status;
        } else if (b >= 0x80) {
            seen_obs_text = true;
        }
    }
}

inline fn parse_token(bytes: *Bytes) Error!Status([]const u8) {
    var b = bytes.next() orelse return .Partial;
    if (!is_token(b) or b == ' ') return error.Token;
    while (true) {
        b = bytes.next() orelse return .Partial;
        var s: [1]u8 = undefined;
        s[0] = b;
        if (b == ' ') {
            return Status([]const u8){ .Complete = bytes.slice_skip(1) };
        } else if (!is_token(b)) {
            return error.Token;
        }
    }
}

inline fn parse_uri(bytes: *Bytes) Error!Status([]const u8) {
    var b = bytes.next() orelse return .Partial;
    if (!is_uri_token(b)) return error.Token;
    while (true) {
        b = bytes.next() orelse return .Partial;
        if (b == ' ') {
            return Status([]const u8){ .Complete = bytes.slice_skip(1) };
        } else if (!is_uri_token(b)) {
            return error.Token;
        }
    }
}

inline fn expect_num(d: u8) Error!u8 {
    return switch (d) {
        '0'...'9' => d,
        else => return error.Status,
    };
}

inline fn parse_code(bytes: *Bytes) Error!Status(u16) {
    const hundreds = try expect_num(bytes.next().?);
    const tens = try expect_num(bytes.next().?);
    const ones = try expect_num(bytes.next().?);
    return Status(u16){
        .Complete = @intCast(u16, hundreds - '0') * 100 +
            @intCast(u16, tens - '0') * 10 + @intCast(u16, ones - '0'),
    };
}

inline fn parse_headers(
    h: *std.ArrayList(Header),
    bytes: *Bytes,
    config: ParserConfig,
) Error!Status(usize) {
    var count: usize = 0;
    while (true) {
        var b = bytes.next() orelse return .Partial;
        if (b == '\r') {
            const next = bytes.next() orelse return .Partial;
            try expect(next, '\n', error.NewLine);
            return Status(usize){ .Complete = count + bytes.pos };
        } else if (b == '\n') {
            return Status(usize){ .Complete = count + bytes.pos };
        } else if (!is_header_name_token(b)) {
            return error.HeaderName;
        }
        var head = try h.addOne();
        var header_name: []const u8 = undefined;
        name: while (true) {
            b = bytes.next() orelse return .Partial;
            if (is_header_name_token(b)) continue :name;
            count += bytes.pos;
            const name = bytes.slice_skip(1);
            if (b == ':') {
                header_name = name;
                break :name;
            }
            if (config.allow_spaces_after_header_name_in_responses) {
                while (b == ' ' or b == '\t') {
                    b = bytes.next() orelse return .Partial;
                    if (b == ':') {
                        count += bytes.pos;
                        _ = bytes.slice_skip(0);
                        header_name = name;
                        break :name;
                    }
                }
            }
            return error.HeaderName;
        }
        var value_slice: []const u8 = undefined;
        value: while (true) {
            // eat white space between colon and value
            whitespace_after_colon: while (true) {
                b = bytes.next() orelse return .Partial;
                if (b == ' ' or b == '\t') {
                    count += bytes.pos;
                    _ = bytes.slice_skip(0);
                    continue :whitespace_after_colon;
                } else {
                    if (!is_header_value_token(b)) {
                        if (b == '\r') {
                            const next = bytes.next() orelse return .Partial;
                            try expect(next, '\n', error.HeaderValue);
                        } else if (b != '\n') {
                            return error.HeaderValue;
                        }
                        if (config.allow_obsolete_multiline_headers_in_responses) {
                            const p = bytes.peek() orelse {
                                // Next byte may be a space, in which case that header
                                // is using obsolete line folding, so we may have more
                                // whitespace to skip after colon.
                                return .Partial;
                            };
                            switch (p) {
                                ' ', '\t' => continue :whitespace_after_colon,
                                else => {
                                    // There is another byte after the end of the line,
                                    // but it's not whitespace, so it's probably another
                                    // header or the final line return. This header is thus
                                    // empty.
                                },
                            }
                        }
                        count += bytes.pos;
                        const whitespace_slice = bytes.slice_skip(0);
                        value_slice = whitespace_slice[0..0];
                        break :value;
                    }
                    break :whitespace_after_colon;
                }
            }
            value_lines: while (true) {
                value_line: while (true) {
                    if (bytes.next_8()) |*bytes8| {
                        b = bytes8._0();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._1();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._2();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._3();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._4();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._5();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._6();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        b = bytes8._7();
                        if (!is_header_value_token(b)) {
                            break :value_line;
                        }
                        continue :value_line;
                    }

                    b = bytes.next() orelse return .Partial;
                    if (!is_header_value_token(b)) {
                        break :value_line;
                    }
                }
                var skip: usize = 0;
                if (b == '\r') {
                    const next = bytes.next() orelse return .Partial;
                    try expect(next, '\n', error.HeaderValue);
                    skip = 2;
                } else if (b == '\n') {
                    skip = 1;
                } else {
                    return error.HeaderValue;
                }
                if (config.allow_obsolete_multiline_headers_in_responses) {
                    const p = bytes.peek() orelse {
                        // Next byte may be a space, in which case that header
                        // may be using line folding, so we need more data.
                        return .Partial;
                    };
                    switch (p) {
                        ' ', '\t' => continue :value_lines,
                        else => {
                            // There is another byte after the end of the line,
                            // but it's not a space, so it's probably another
                            // header or the final line return. We are thus done
                            // with this current header.
                        },
                    }
                }
                count += bytes.pos;
                value_slice = bytes.slice_skip(skip);
                break :value;
            }
        }
        var last_visible = value_slice.len;
        while (last_visible > 0 and (switch (value_slice[last_visible - 1]) {
            ' ', '\t', '\r', '\n' => true,
            else => false,
        })) : (last_visible -= 1) {}
        value_slice = value_slice[0..last_visible];

        var header_value = value_slice;
        head.* = Header{
            .name = header_name,
            .value = header_value,
        };
    }
}

const ChunkSize = struct {
    size: u64,
    index: usize,
};

/// Parse a buffer of bytes as a chunk size.
///
/// The return value, if complete and successful, includes the index of the
/// buffer that parsing stopped at, and the size of the following chunk.
///
/// # Example
///
/// ```
/// let buf = b"4\r\nRust\r\n0\r\n\r\n";
/// assert_eq!(httparse::parse_chunk_size(buf),
///            Ok(httparse::Status::Complete((3, 4))));
/// ```
fn parse_chunk_size(buf: []const u8) Error!Status(ChunkSize) {
    const RADIX: u64 = 16;
    var bytes = Bytes{ .slice = buf };
    var size: u64 = 0;
    var in_chunk_size: bool = true;
    var in_ext: bool = false;
    var count: usize = 0;
    while (true) {
        const b = bytes.next() orelse return .Partial;

        if ((switch (b) {
            '0'...'9' => true,
            else => false,
        }) and in_chunk_size) {
            if (count > 15) {
                return error.InvalidChunkSize;
            }
            count += 1;
            size *= RADIX;
            size += @intCast(u64, b - '0');
        } else if ((switch (b) {
            'a'...'f' => true,
            else => false,
        }) and in_chunk_size) {
            if (count > 15) {
                return error.InvalidChunkSize;
            }
            count += 1;
            size *= RADIX;
            size += @intCast(u64, b + 10 - 'a');
        } else if ((switch (b) {
            'A'...'F' => true,
            else => false,
        }) and in_chunk_size) {
            if (count > 15) {
                return error.InvalidChunkSize;
            }
            count += 1;
            size *= RADIX;
            size += @intCast(u64, b + 10 - 'A');
        } else if (b == '\r') {
            const next = bytes.next() orelse return .Partial;
            if (next == '\n') break;
            return error.InvalidChunkSize;
        } else if (b == ';' and !in_ext) {
            // If we weren't in the extension yet, the ";" signals its start
            in_ext = true;
            in_chunk_size = false;
        } else if ((b == '\t' or b == ' ') and (!in_ext and !in_chunk_size)) {
            // "Linear white space" is ignored between the chunk size and the
            // extension separator token (";") due to the "implied *LWS rule"
        } else if ((b == '\t' or b == ' ') and in_chunk_size) {
            // LWS can follow the chunk size, but no more digits can come
            in_chunk_size = false;
        } else if (in_ext) {
            // We allow any arbitrary octet once we are in the extension, since
            // they all get ignored anyway. According to the HTTP spec, valid
            // extensions would have a more strict syntax:
            //     (token ["=" (token | quoted-string)])
            // but we gain nothing by rejecting an otherwise valid chunk size
        } else {
            // Finally, if we aren't in the extension and we're reading any
            // other octet, the chunk size line is invalid!
            return error.InvalidChunkSize;
        }
    }
    return Status(ChunkSize){ .Complete = ChunkSize{
        .size = size,
        .index = bytes.pos,
    } };
}

fn req(buf: []const u8, check: anytype) !void {
    try req_len(buf, buf.len, check);
}

fn req_err(buf: []const u8, err: anyerror) !void {
    gpa = std.testing.allocator;
    var r = Request.new();
    defer r.deinit();
    try std.testing.expectError(err, r.parse(buf));
}

fn req_len(buf: []const u8, len: usize, check: anytype) !void {
    try req_status(buf, Status(usize){ .Complete = len }, check);
}

fn req_status(buf: []const u8, status: Status(usize), check: anytype) !void {
    gpa = std.testing.allocator;
    var r = Request.new();
    defer r.deinit();
    try std.testing.expectEqual(status, try r.parse(buf));
    try check.check(&r);
}

fn res(buf: []const u8, check: anytype) !void {
    try res_len(buf, buf.len, check);
}

fn res_err(buf: []const u8, err: anyerror) !void {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    try std.testing.expectError(err, r.parse(buf));
}

fn res_len(buf: []const u8, len: usize, check: anytype) !void {
    try res_status(buf, Status(usize){ .Complete = len }, check);
}

fn res_status(buf: []const u8, status: Status(usize), check: anytype) !void {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    try std.testing.expectEqual(status, try r.parse(buf));
    try check.check(&r);
}

test "test_request_simple" {
    try req(
        "GET / HTTP/1.1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try std.testing.expectEqualStrings("GET", r.method.?);
                try std.testing.expectEqualStrings("/", r.path.?);
                try std.testing.expectEqual(@as(u8, 1), r.version.?);
                try std.testing.expectEqual(@as(usize, 0), r.headers.items.len);
            }
        },
    );
}

test "test_request_simple_with_query_params" {
    try req("GET /thing?data=a HTTP/1.1\r\n\r\n", struct {
        fn check(r: *Request) !void {
            try expectedStrings(r.method.?, "GET");
            try expectedStrings(r.path.?, "/thing?data=a");
            try expectedVersion(r.version.?, 1);
            try expectedHeaderLen(r.headers.items.len, 0);
        }
    });
}

fn expectedStrings(actual: []const u8, expected: []const u8) !void {
    try std.testing.expectEqualStrings(expected, actual);
}

fn expectedVersion(actual: u8, expected: anytype) !void {
    try std.testing.expectEqual(@as(u8, expected), actual);
}

fn expectedCode(actual: u16, expected: anytype) !void {
    try std.testing.expectEqual(@as(u16, expected), actual);
}

fn expectedHeaderLen(actual: usize, expected: anytype) !void {
    try std.testing.expectEqual(@as(usize, expected), actual);
}

test "test_request_simple_with_whatwg_query_params" {
    try req(
        "GET /thing?data=a^ HTTP/1.1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/thing?data=a^");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 0);
            }
        },
    );
}

test "test_request_headers" {
    try req(
        "GET / HTTP/1.1\r\nHost: foo.com\r\nCookie: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 2);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.com");
                try expectedStrings(r.headers.items[1].name, "Cookie");
                try expectedStrings(r.headers.items[1].value, "");
            }
        },
    );
}

test "test_request_headers_optional_whitespace" {
    try req(
        "GET / HTTP/1.1\r\nHost: \tfoo.com\t \r\nCookie: \t \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 2);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.com");
                try expectedStrings(r.headers.items[1].name, "Cookie");
                try expectedStrings(r.headers.items[1].value, "");
            }
        },
    );
}

test "test_request_header_value_htab_short" {
    // test the scalar parsing
    try req(
        "GET / HTTP/1.1\r\nUser-Agent: some\tagent\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "User-Agent");
                try expectedStrings(r.headers.items[0].value, "some\tagent");
            }
        },
    );
}

test "test_request_header_value_htab_med" {
    // test the sse42 parsing
    try req(
        "GET / HTTP/1.1\r\nUser-Agent: 1234567890some\tagent\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "User-Agent");
                try expectedStrings(r.headers.items[0].value, "1234567890some\tagent");
            }
        },
    );
}

test "test_request_header_value_htab_long" {
    // test the avx2 parsing
    try req(
        "GET / HTTP/1.1\r\nUser-Agent: 1234567890some\t1234567890agent1234567890\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "User-Agent");
                try expectedStrings(r.headers.items[0].value, "1234567890some\t1234567890agent1234567890");
            }
        },
    );
}

test "test_request_headers_max" {
    // There is no max header size limit
}

test "test_request_multibyte" {
    try req(
        "GET / HTTP/1.1\r\nHost: foo.com\r\nUser-Agent: \xe3\x81\xb2\xe3/1.0\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 2);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.com");
                try expectedStrings(r.headers.items[1].name, "User-Agent");
                try expectedStrings(r.headers.items[1].value, "\xe3\x81\xb2\xe3/1.0");
            }
        },
    );
}

test "test_request_partial" {
    try req_status("GET / HTTP/1.1\r\n\r", .Partial, struct {
        fn check(_: *Request) !void {}
    });
}

test "test_request_partial_version" {
    try req_status("GET / HTTP/1.", .Partial, struct {
        fn check(_: *Request) !void {}
    });
}

test "test_request_partial_parses_headers_as_much_as_it_can" {
    try req_status(
        "GET / HTTP/1.1\r\nHost: yolo\r\n",
        .Partial,
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "yolo");
            }
        },
    );
}

test "test_request_newlines" {
    try req(
        "GET / HTTP/1.1\nHost: foo.bar\n\n",
        struct {
            fn check(_: *Request) !void {}
        },
    );
}

test "test_request_empty_lines_prefix" {
    try req(
        "\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 0);
            }
        },
    );
}

test "test_request_empty_lines_prefix_lf_only" {
    try req(
        "\n\nGET / HTTP/1.1\n\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 0);
            }
        },
    );
}

test "test_request_path_backslash" {
    try req(
        "\n\nGET /\\?wayne\\=5 HTTP/1.1\n\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/\\?wayne\\=5");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 0);
            }
        },
    );
}

test "test_request_with_invalid_token_delimiter" {
    try req_err(
        "GET\n/ HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        error.Token,
    );
}

test "test_request_with_invalid_but_short_version" {
    try req_err(
        "GET / HTTP/1!",
        error.Version,
    );
}

test "test_request_with_empty_method" {
    try req_err(
        " / HTTP/1.1\r\n\r\n",
        error.Token,
    );
}

test "test_request_with_empty_path" {
    try req_err(
        "GET  HTTP/1.1\r\n\r\n",
        error.Token,
    );
}

test "test_request_with_empty_method_and_path" {
    try req_err(
        "  HTTP/1.1\r\n\r\n",
        error.Token,
    );
}

test "test_response_simple" {
    try res(
        "HTTP/1.1 200 OK\r\n\r\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 200);
                try expectedStrings(r.reason.?, "OK");
            }
        },
    );
}

test "test_response_newlines" {
    try res(
        "HTTP/1.0 403 Forbidden\nServer: foo.bar\n\n",
        struct {
            fn check(_: *Response) !void {}
        },
    );
}

test "test_response_reason_missing" {
    try res(
        "HTTP/1.1 200 \r\n\r\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 200);
                try expectedStrings(r.reason.?, "");
            }
        },
    );
}

test "test_response_reason_missing_no_space" {
    try res(
        "HTTP/1.1 200\r\n\r\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 200);
                try expectedStrings(r.reason.?, "");
            }
        },
    );
}

test "test_response_reason_missing_no_space_with_headers" {
    try res(
        "HTTP/1.1 200\r\nFoo: bar\r\n\r\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 200);
                try expectedStrings(r.reason.?, "");
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Foo");
                try expectedStrings(r.headers.items[0].value, "bar");
            }
        },
    );
}

test "test_response_reason_with_space_and_ta" {
    try res(
        "HTTP/1.1 101 Switching Protocols\t\r\n\r\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 101);
                try expectedStrings(r.reason.?, "Switching Protocols\t");
            }
        },
    );
}

test "test_response_reason_with_obsolete_text_byte" {
    try res(
        "HTTP/1.1 200 X\xFFZ\r\n\r\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 200);
                // Empty string fallback in case of obs-text
                try expectedStrings(r.reason.?, "");
            }
        },
    );
}

test "test_response_reason_with_nul_byte" {
    try res_err(
        "HTTP/1.1 200 \x00\r\n\r\n",
        error.Status,
    );
}

test "test_response_version_missing_space" {
    try res_status(
        "HTTP/1.1",
        .Partial,
        struct {
            fn check(_: *Response) !void {}
        },
    );
}

test "test_response_code_missing_space" {
    try res_status(
        "HTTP/1.1 200",
        .Partial,
        struct {
            fn check(_: *Response) !void {}
        },
    );
}

test "test_response_partial_parses_headers_as_much_as_it_can" {
    try res_status(
        "HTTP/1.1 200 OK\r\nServer: yolo\r\n",
        .Partial,
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 1);
                try expectedCode(r.code.?, 200);
                try expectedStrings(r.reason.?, "OK");
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Server");
                try expectedStrings(r.headers.items[0].value, "yolo");
            }
        },
    );
}

test "test_response_empty_lines_prefix_lf_only" {
    try res(
        "\n\nHTTP/1.1 200 OK\n\n",
        struct {
            fn check(_: *Response) !void {}
        },
    );
}

test "test_response_no_cr" {
    try res(
        "HTTP/1.0 200\nContent-type: text/html\n\n",
        struct {
            fn check(r: *Response) !void {
                try expectedVersion(r.version.?, 0);
                try expectedCode(r.code.?, 200);
                try expectedStrings(r.reason.?, "");
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Content-type");
                try expectedStrings(r.headers.items[0].value, "text/html");
            }
        },
    );
}

test "test_forbid_response_with_whitespace_between_header_name_and_colon" {
    try res_err(
        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials : true\r\nBread: baguette\r\n\r\n",
        error.HeaderName,
    );
}

test "test_allow_response_with_whitespace_between_header_name_and_colon" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    const result = try r.parse_with_config(
        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials : true\r\nBread: baguette\r\n\r\n",
        ParserConfig{
            .allow_spaces_after_header_name_in_responses = true,
        },
    );
    try std.testing.expectEqual(Status(usize){ .Complete = 77 }, result);
    try expectedVersion(r.version.?, 1);
    try expectedCode(r.code.?, 200);
    try expectedStrings(r.reason.?, "OK");
    try expectedHeaderLen(r.headers.items.len, 2);
    try expectedStrings(r.headers.items[0].name, "Access-Control-Allow-Credentials");
    try expectedStrings(r.headers.items[0].value, "true");
    try expectedStrings(r.headers.items[1].name, "Bread");
    try expectedStrings(r.headers.items[1].value, "baguette");
}

test "test_forbid_request_with_whitespace_between_header_name_and_colon" {
    try req_err(
        "GET / HTTP/1.1\r\nHost : localhost\r\n\r\n",
        error.HeaderName,
    );
}

test "test_forbid_response_with_obsolete_line_folding_at_start" {
    try res_err(
        "HTTP/1.1 200 OK\r\nLine-Folded-Header: \r\n   \r\n hello there\r\n\r\n",
        error.HeaderName,
    );
}

test "test_allow_response_with_obsolete_line_folding_at_end" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    const result = try r.parse_with_config(
        "HTTP/1.1 200 OK\r\nLine-Folded-Header: hello there\r\n   \r\n \r\n\r\n",
        ParserConfig{
            .allow_obsolete_multiline_headers_in_responses = true,
        },
    );
    try std.testing.expectEqual(Status(usize){ .Complete = 60 }, result);
    try expectedVersion(r.version.?, 1);
    try expectedCode(r.code.?, 200);
    try expectedStrings(r.reason.?, "OK");
    try expectedHeaderLen(r.headers.items.len, 1);
    try expectedStrings(r.headers.items[0].name, "Line-Folded-Header");
    try expectedStrings(r.headers.items[0].value, "hello there");
}

test "test_forbid_response_with_obsolete_line_folding_in_middle" {
    try res_err(
        "HTTP/1.1 200 OK\r\nLine-Folded-Header: hello  \r\n \r\n there\r\n\r\n",
        error.HeaderName,
    );
}

test "test_allow_response_with_obsolete_line_folding_at_end" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    const result = try r.parse_with_config(
        "HTTP/1.1 200 OK\r\nLine-Folded-Header: hello  \r\n \r\n there\r\n\r\n",
        ParserConfig{
            .allow_obsolete_multiline_headers_in_responses = true,
        },
    );
    try std.testing.expectEqual(Status(usize){ .Complete = 59 }, result);
    try expectedVersion(r.version.?, 1);
    try expectedCode(r.code.?, 200);
    try expectedStrings(r.reason.?, "OK");
    try expectedHeaderLen(r.headers.items.len, 1);
    try expectedStrings(r.headers.items[0].name, "Line-Folded-Header");
    try expectedStrings(r.headers.items[0].value, "hello  \r\n \r\n there");
}

test "test_forbid_response_with_obsolete_line_folding_in_empty_header" {
    try res_err(
        "HTTP/1.1 200 OK\r\nLine-Folded-Header:   \r\n \r\n \r\n\r\n",
        error.HeaderName,
    );
}

test "test_allow_response_with_obsolete_line_folding_in_empty_header" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    const result = try r.parse_with_config(
        "HTTP/1.1 200 OK\r\nLine-Folded-Header:   \r\n \r\n \r\n\r\n",
        ParserConfig{
            .allow_obsolete_multiline_headers_in_responses = true,
        },
    );
    try std.testing.expectEqual(Status(usize){ .Complete = 49 }, result);
    try expectedVersion(r.version.?, 1);
    try expectedCode(r.code.?, 200);
    try expectedStrings(r.reason.?, "OK");
    try expectedHeaderLen(r.headers.items.len, 1);
    try expectedStrings(r.headers.items[0].name, "Line-Folded-Header");
    try expectedStrings(r.headers.items[0].value, "");
}

test "test_chunk_size" {
    try expectChunk(
        try parse_chunk_size("0\r\n"),
        Status(ChunkSize){ .Complete = .{ .index = 3, .size = 0 } },
    );
    try expectChunk(
        try parse_chunk_size("12\r\nchunk"),
        Status(ChunkSize){ .Complete = .{ .index = 4, .size = 18 } },
    );
    try expectChunk(
        try parse_chunk_size("3086d\r\n"),
        Status(ChunkSize){ .Complete = .{ .index = 7, .size = 198765 } },
    );
    try expectChunk(
        try parse_chunk_size("3735AB1;foo bar*\r\n"),
        Status(ChunkSize){ .Complete = .{ .index = 18, .size = 57891505 } },
    );
    try expectChunk(
        try parse_chunk_size("3735ab1 ; baz \r\n"),
        Status(ChunkSize){ .Complete = .{ .index = 16, .size = 57891505 } },
    );
    try expectChunk(try parse_chunk_size("77a65\r"), .Partial);
    try expectChunk(try parse_chunk_size("a"), .Partial);
    try expectChunk(
        try parse_chunk_size("ffffffffffffffff\r\n"),
        Status(ChunkSize){ .Complete = .{ .index = 18, .size = std.math.maxInt(u64) } },
    );

    try expectChunkError(parse_chunk_size("567f8a\rfoo"), error.InvalidChunkSize);
    try expectChunkError(parse_chunk_size("567f8a\rfoo"), error.InvalidChunkSize);
    try expectChunkError(parse_chunk_size("567xf8a\r\n"), error.InvalidChunkSize);
    try expectChunkError(parse_chunk_size("1ffffffffffffffff\r\n"), error.InvalidChunkSize);
    try expectChunkError(parse_chunk_size("Affffffffffffffff\r\n"), error.InvalidChunkSize);
    try expectChunkError(parse_chunk_size("fffffffffffffffff\r\n"), error.InvalidChunkSize);
}

fn expectChunk(got: Status(ChunkSize), want: Status(ChunkSize)) !void {
    try std.testing.expectEqual(want, got);
}

fn expectChunkError(got: anytype, want: Error) !void {
    try std.testing.expectError(want, got);
}

test "test_forbid_response_with_multiple_space_delimiters" {
    try res_err(
        "HTTP/1.1   200  OK\r\n\r\n",
        error.Status,
    );
}

test "test_allow_response_with_multiple_space_delimiters" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    const result = try r.parse_with_config(
        "HTTP/1.1   200  OK\r\n\r\n",
        ParserConfig{
            .allow_multiple_spaces_in_response_status_delimiters = true,
        },
    );
    try std.testing.expectEqual(Status(usize){ .Complete = 22 }, result);
    try expectedVersion(r.version.?, 1);
    try expectedCode(r.code.?, 200);
    try expectedStrings(r.reason.?, "OK");
    try expectedHeaderLen(r.headers.items.len, 0);
}

test "test_forbid_response_with_weird_whitespace_delimiters" {
    try res_err(
        "HTTP/1.1 200\rOK\r\n\r\n",
        error.Status,
    );
}

test "test_still_forbid_response_with_weird_whitespace_delimiters" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    try std.testing.expectError(
        error.Status,
        r.parse_with_config(
            "HTTP/1.1 200\rOK\r\n\r\n",
            ParserConfig{
                .allow_multiple_spaces_in_response_status_delimiters = true,
            },
        ),
    );
}

test "test_forbid_request_with_multiple_space_delimiters" {
    try req_err(
        "GET  /    HTTP/1.1\r\n\r\n",
        error.Token,
    );
}

test "test_allow_request_with_multiple_space_delimiters" {
    gpa = std.testing.allocator;
    var r = Request.new();
    defer r.deinit();
    const result = try r.parse_with_config(
        "GET  /    HTTP/1.1\r\n\r\n",
        ParserConfig{
            .allow_multiple_spaces_in_request_line_delimiters = true,
        },
    );
    try std.testing.expectEqual(Status(usize){ .Complete = 22 }, result);
    try expectedStrings(r.method.?, "GET");
    try expectedStrings(r.path.?, "/");
    try expectedVersion(r.version.?, 1);
    try expectedHeaderLen(r.headers.items.len, 0);
}

test "test_forbid_request_with_weird_whitespace_delimiters" {
    try req_err(
        "GET\r/\rHTTP/1.1\r\n\r\n",
        error.Token,
    );
}

test "test_still_forbid_request_with_weird_whitespace_delimiters" {
    gpa = std.testing.allocator;
    var r = Request.new();
    defer r.deinit();
    try std.testing.expectError(
        error.Token,
        r.parse_with_config(
            "GET\r/\rHTTP/1.1\r\n\r\n",
            ParserConfig{
                .allow_multiple_spaces_in_request_line_delimiters = true,
            },
        ),
    );
}

test "test_request_with_multiple_spaces_and_bad_path" {
    gpa = std.testing.allocator;
    var r = Request.new();
    defer r.deinit();
    try std.testing.expectError(
        error.Token,
        r.parse_with_config(
            "GET   /foo>ohno HTTP/1.1\r\n\r\n",
            ParserConfig{
                .allow_multiple_spaces_in_request_line_delimiters = true,
            },
        ),
    );
}

test "test_response_with_spaces_in_code" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    try std.testing.expectError(
        error.Status,
        r.parse_with_config(
            "HTTP/1.1 99 200 OK\r\n\r\n",
            ParserConfig{
                .allow_multiple_spaces_in_response_status_delimiters = true,
            },
        ),
    );
}

test "test_forbid_response_with_invalid_char_between_header_name_and_colon" {
    gpa = std.testing.allocator;
    var r = Response.new();
    defer r.deinit();
    try std.testing.expectError(
        error.HeaderName,
        r.parse_with_config(
            "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials\xFF: true\r\nBread: baguette\r\n\r\n",
            ParserConfig{
                .allow_spaces_after_header_name_in_responses = true,
            },
        ),
    );
}

// URI-TESTS

test "urltest_001" {
    try req(
        "GET /bar;par?b HTTP/1.1\r\nHost: foo\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/bar;par?b");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo");
            }
        },
    );
}

test "urltest_002" {
    try req(
        "GET /x HTTP/1.1\r\nHost: test\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "test");
            }
        },
    );
}

test "urltest_003" {
    try req(
        "GET /x HTTP/1.1\r\nHost: test\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "test");
            }
        },
    );
}

test "urltest_004" {
    try req(
        "GET /foo/foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/foo.com");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_005" {
    try req(
        "GET /foo/:foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:foo.com");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_006" {
    try req(
        "GET /foo/foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/foo.com");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_007" {
    // try req(
    //
    //     |_r| {}
    try req_err(
        "GET  foo.com HTTP/1.1\r\nHost: \r\n\r\n",
        error.Token,
    );
}

test "urltest_008" {
    try req(
        "GET /%20b%20?%20d%20 HTTP/1.1\r\nHost: f\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%20b%20?%20d%20");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "f");
            }
        },
    );
}

test "urltest_009" {
    try req_err(
        "GET x x HTTP/1.1\r\nHost: \r\n\r\n",
        error.Version,
    );
}

test "urltest_010" {
    try req(
        "GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "f");
            }
        },
    );
}

test "urltest_011" {
    try req(
        "GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "f");
            }
        },
    );
}

test "urltest_012" {
    try req(
        "GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "f");
            }
        },
    );
}

test "urltest_013" {
    try req(
        "GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "f");
            }
        },
    );
}

test "urltest_014" {
    try req(
        "GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "f");
            }
        },
    );
}

test "urltest_015" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_016" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_017" {
    try req(
        "GET /foo/:foo.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:foo.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_018" {
    try req(
        "GET /foo/:foo.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:foo.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_019" {
    try req(
        "GET /foo/: HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_020" {
    try req(
        "GET /foo/:a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_021" {
    try req(
        "GET /foo/:/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_022" {
    try req(
        "GET /foo/:/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_023" {
    try req(
        "GET /foo/: HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_024" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_025" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_026" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_027" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_028" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_029" {
    try req(
        "GET /foo/:23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:23");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_030" {
    try req(
        "GET /:23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/:23");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_031" {
    try req(
        "GET /foo/:: HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/::");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_032" {
    try req(
        "GET /foo/::23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/::23");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_033" {
    try req(
        "GET /d HTTP/1.1\r\nHost: c\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/d");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "c");
            }
        },
    );
}

test "urltest_034" {
    try req(
        "GET /foo/:@c:29 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/:@c:29");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_035" {
    try req(
        "GET //@ HTTP/1.1\r\nHost: foo.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "//@");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.com");
            }
        },
    );
}

test "urltest_036" {
    try req(
        "GET /b:c/d@foo.com/ HTTP/1.1\r\nHost: a\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/b:c/d@foo.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "a");
            }
        },
    );
}

test "urltest_037" {
    try req(
        "GET /bar.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/bar.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_038" {
    try req(
        "GET /////// HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "///////");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_039" {
    try req(
        "GET ///////bar.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "///////bar.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_040" {
    try req(
        "GET //:///// HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "//://///");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_041" {
    try req(
        "GET /foo HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_042" {
    try req(
        "GET /bar HTTP/1.1\r\nHost: foo\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo");
            }
        },
    );
}

test "urltest_043" {
    try req(
        "GET /path;a??e HTTP/1.1\r\nHost: foo\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/path;a??e");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo");
            }
        },
    );
}

test "urltest_044" {
    try req(
        "GET /abcd?efgh?ijkl HTTP/1.1\r\nHost: foo\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/abcd?efgh?ijkl");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo");
            }
        },
    );
}

test "urltest_045" {
    try req(
        "GET /abcd HTTP/1.1\r\nHost: foo\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/abcd");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo");
            }
        },
    );
}

test "urltest_046" {
    try req(
        "GET /foo/[61:24:74]:98 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/[61:24:74]:98");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_047" {
    try req(
        "GET /foo/[61:27]/:foo HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/[61:27]/:foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_048" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_049" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_050" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_051" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_052" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_053" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_054" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_055" {
    try req(
        "GET /foo/example.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_056" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_057" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_058" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_059" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_060" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_061" {
    try req(
        "GET /a/b/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/a/b/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_062" {
    try req(
        "GET /a/%20/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/a/%20/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_063" {
    try req(
        "GET /a%2fc HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/a%2fc");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_064" {
    try req(
        "GET /a/%2f/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/a/%2f/c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_065" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_066" {
    try req(
        "GET text/html,test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "text/html,test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_067" {
    try req(
        "GET 1234567890 HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "1234567890");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_068" {
    try req(
        "GET /c:/foo/bar.html HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c:/foo/bar.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_069" {
    try req(
        "GET /c:////foo/bar.html HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c:////foo/bar.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_070" {
    try req(
        "GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_071" {
    try req(
        "GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_072" {
    try req(
        "GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_073" {
    try req(
        "GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/file");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "server");
            }
        },
    );
}

test "urltest_074" {
    try req(
        "GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/file");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "server");
            }
        },
    );
}

test "urltest_075" {
    try req(
        "GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/file");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "server");
            }
        },
    );
}

test "urltest_076" {
    try req(
        "GET /foo/bar.txt HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_077" {
    try req(
        "GET /home/me HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/home/me");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_078" {
    try req(
        "GET /test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_079" {
    try req(
        "GET /test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_080" {
    try req(
        "GET /tmp/mock/test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/tmp/mock/test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_081" {
    try req(
        "GET /tmp/mock/test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/tmp/mock/test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_082" {
    try req(
        "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_083" {
    try req(
        "GET /.foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/.foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_084" {
    try req(
        "GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_085" {
    try req(
        "GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_086" {
    try req(
        "GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_087" {
    try req(
        "GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_088" {
    try req(
        "GET /foo/..bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/..bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_089" {
    try req(
        "GET /foo/ton HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/ton");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_090" {
    try req(
        "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_091" {
    try req(
        "GET /ton HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/ton");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_092" {
    try req(
        "GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_093" {
    try req(
        "GET /foo/%2e%2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/%2e%2");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_094" {
    try req(
        "GET /%2e.bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%2e.bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_095" {
    try req(
        "GET // HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "//");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_096" {
    try req(
        "GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_097" {
    try req(
        "GET /foo/bar/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_098" {
    try req(
        "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_099" {
    try req(
        "GET /%20foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%20foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_100" {
    try req(
        "GET /foo% HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_101" {
    try req(
        "GET /foo%2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%2");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_102" {
    try req(
        "GET /foo%2zbar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%2zbar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_103" {
    try req(
        "GET /foo%2%C3%82%C2%A9zbar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%2%C3%82%C2%A9zbar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_104" {
    try req(
        "GET /foo%41%7a HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%41%7a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_105" {
    try req(
        "GET /foo%C2%91%91 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%C2%91%91");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_106" {
    try req(
        "GET /foo%00%51 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%00%51");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_107" {
    try req(
        "GET /(%28:%3A%29) HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/(%28:%3A%29)");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_108" {
    try req(
        "GET /%3A%3a%3C%3c HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%3A%3a%3C%3c");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_109" {
    try req(
        "GET /foobar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foobar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_110" {
    try req(
        "GET //foo//bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "//foo//bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_111" {
    try req(
        "GET /%7Ffp3%3Eju%3Dduvgw%3Dd HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%7Ffp3%3Eju%3Dduvgw%3Dd");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_112" {
    try req(
        "GET /@asdf%40 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/@asdf%40");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_113" {
    try req(
        "GET /%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_114" {
    try req(
        "GET /%E2%80%A5/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%E2%80%A5/foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_115" {
    try req(
        "GET /%EF%BB%BF/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%EF%BB%BF/foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_116" {
    try req(
        "GET /%E2%80%AE/foo/%E2%80%AD/bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%E2%80%AE/foo/%E2%80%AD/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_117" {
    try req(
        "GET /foo?bar=baz HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo?bar=baz");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.google.com");
            }
        },
    );
}

test "urltest_118" {
    try req(
        "GET /foo?bar=baz HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo?bar=baz");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.google.com");
            }
        },
    );
}

test "urltest_119" {
    try req(
        "GET test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_120" {
    try req(
        "GET /foo%2Ehtml HTTP/1.1\r\nHost: www\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo%2Ehtml");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www");
            }
        },
    );
}

test "urltest_121" {
    try req(
        "GET /foo/html HTTP/1.1\r\nHost: www\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www");
            }
        },
    );
}

test "urltest_122" {
    try req(
        "GET /foo HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.google.com");
            }
        },
    );
}

test "urltest_123" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_124" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_125" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_126" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_127" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_128" {
    try req(
        "GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_129" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_130" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_131" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_132" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_133" {
    try req(
        "GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "example.com/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_134" {
    try req(
        "GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_135" {
    try req(
        "GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_136" {
    try req(
        "GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_137" {
    try req(
        "GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_138" {
    try req(
        "GET /aaa/test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/aaa/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_139" {
    try req(
        "GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_140" {
    try req(
        "GET /%E4%B8%AD/test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%E4%B8%AD/test.txt");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "www.example.com");
            }
        },
    );
}

test "urltest_141" {
    try req(
        "GET /... HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/...");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_142" {
    try req(
        "GET /a HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_143" {
    try req(
        "GET /%EF%BF%BD?%EF%BF%BD HTTP/1.1\r\nHost: x\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%EF%BF%BD?%EF%BF%BD");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "x");
            }
        },
    );
}

test "urltest_144" {
    try req(
        "GET /bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.com");
            }
        },
    );
}

test "urltest_145" {
    try req(
        "GET test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_146" {
    try req(
        "GET x@x.com HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "x@x.com");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_147" {
    try req(
        "GET , HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, ",");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_148" {
    try req(
        "GET blank HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "blank");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_149" {
    try req(
        "GET test?test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "test?test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_150" {
    try req(
        "GET /%60%7B%7D?`{} HTTP/1.1\r\nHost: h\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/%60%7B%7D?`{}");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "h");
            }
        },
    );
}

test "urltest_151" {
    try req(
        "GET /?%27 HTTP/1.1\r\nHost: host\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/?%27");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "host");
            }
        },
    );
}

test "urltest_152" {
    try req(
        "GET /?' HTTP/1.1\r\nHost: host\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/?'");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "host");
            }
        },
    );
}

test "urltest_153" {
    try req(
        "GET /some/path HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/some/path");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_154" {
    try req(
        "GET /smth HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/smth");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_155" {
    try req(
        "GET /some/path HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/some/path");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_156" {
    try req(
        "GET /pa/i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_157" {
    try req(
        "GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "ho");
            }
        },
    );
}

test "urltest_158" {
    try req(
        "GET /pa/i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_159" {
    try req(
        "GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_160" {
    try req(
        "GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "ho");
            }
        },
    );
}

test "urltest_161" {
    try req(
        "GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_162" {
    try req(
        "GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_163" {
    try req(
        "GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "ho");
            }
        },
    );
}

test "urltest_164" {
    try req(
        "GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_165" {
    try req(
        "GET /pa/pa?i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa/pa?i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_166" {
    try req(
        "GET /pa?i HTTP/1.1\r\nHost: ho\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa?i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "ho");
            }
        },
    );
}

test "urltest_167" {
    try req(
        "GET /pa/pa?i HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa/pa?i");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_168" {
    try req(
        "GET sd HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "sd");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_169" {
    try req(
        "GET sd/sd HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "sd/sd");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_170" {
    try req(
        "GET /pa/pa HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa/pa");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_171" {
    try req(
        "GET /pa HTTP/1.1\r\nHost: ho\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "ho");
            }
        },
    );
}

test "urltest_172" {
    try req(
        "GET /pa/pa HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pa/pa");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_173" {
    try req(
        "GET /x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "%C3%B1");
            }
        },
    );
}

test "urltest_174" {
    try req(
        "GET \\.\\./ HTTP/1.1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "\\.\\./");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 0);
            }
        },
    );
}

test "urltest_175" {
    try req(
        "GET :a@example.net HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, ":a@example.net");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_176" {
    try req(
        "GET %NBD HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "%NBD");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_177" {
    try req(
        "GET %1G HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "%1G");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_178" {
    try req(
        "GET /relative_import.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/relative_import.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "127.0.0.1");
            }
        },
    );
}

test "urltest_179" {
    try req(
        "GET /?foo=%7B%22abc%22 HTTP/1.1\r\nHost: facebook.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/?foo=%7B%22abc%22");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "facebook.com");
            }
        },
    );
}

test "urltest_180" {
    try req(
        "GET /jqueryui@1.2.3 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/jqueryui@1.2.3");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "localhost");
            }
        },
    );
}

test "urltest_181" {
    try req(
        "GET /path?query HTTP/1.1\r\nHost: host\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/path?query");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "host");
            }
        },
    );
}

test "urltest_182" {
    try req(
        "GET /foo/bar?a=b&c=d HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar?a=b&c=d");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_183" {
    try req(
        "GET /foo/bar??a=b&c=d HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar??a=b&c=d");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_184" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_185" {
    try req(
        "GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/baz?qux");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.bar");
            }
        },
    );
}

test "urltest_186" {
    try req(
        "GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/baz?qux");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.bar");
            }
        },
    );
}

test "urltest_187" {
    try req(
        "GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/baz?qux");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.bar");
            }
        },
    );
}

test "urltest_188" {
    try req(
        "GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/baz?qux");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.bar");
            }
        },
    );
}

test "urltest_189" {
    try req(
        "GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/baz?qux");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foo.bar");
            }
        },
    );
}

test "urltest_190" {
    try req(
        "GET /C%3A/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C%3A/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_191" {
    try req(
        "GET /C%7C/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C%7C/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_192" {
    try req(
        "GET /C:/Users/Domenic/Dropbox/GitHub/tmpvar/jsdom/test/level2/html/files/pix/submit.gif HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/Users/Domenic/Dropbox/GitHub/tmpvar/jsdom/test/level2/html/files/pix/submit.gif");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_193" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_194" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_195" {
    try req(
        "GET /d: HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/d:");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_196" {
    try req(
        "GET /d:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/d:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_197" {
    try req(
        "GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_198" {
    try req(
        "GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_199" {
    try req(
        "GET /test?x HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_200" {
    try req(
        "GET /test?x HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_201" {
    try req(
        "GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_202" {
    try req(
        "GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_203" {
    try req(
        "GET /?fox HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/?fox");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_204" {
    try req(
        "GET /localhost//cat HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/localhost//cat");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_205" {
    try req(
        "GET /localhost//cat HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/localhost//cat");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_206" {
    try req(
        "GET /mouse HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/mouse");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_207" {
    try req(
        "GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pig");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_208" {
    try req(
        "GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pig");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_209" {
    try req(
        "GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/pig");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_210" {
    try req(
        "GET /localhost//pig HTTP/1.1\r\nHost: lion\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/localhost//pig");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "lion");
            }
        },
    );
}

test "urltest_211" {
    try req(
        "GET /rooibos HTTP/1.1\r\nHost: tea\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/rooibos");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "tea");
            }
        },
    );
}

test "urltest_212" {
    try req(
        "GET /?chai HTTP/1.1\r\nHost: tea\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/?chai");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "tea");
            }
        },
    );
}

test "urltest_213" {
    try req(
        "GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_214" {
    try req(
        "GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_215" {
    try req(
        "GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_216" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_217" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_218" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_219" {
    try req(
        "GET /dir/C HTTP/1.1\r\nHost: host\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/dir/C");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "host");
            }
        },
    );
}

test "urltest_220" {
    try req(
        "GET /dir/C|a HTTP/1.1\r\nHost: host\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/dir/C|a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "host");
            }
        },
    );
}

test "urltest_221" {
    try req(
        "GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_222" {
    try req(
        "GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_223" {
    try req(
        "GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_224" {
    try req(
        "GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/c:/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_225" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_226" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_227" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_228" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_229" {
    try req(
        "GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/C:/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_230" {
    try req(
        "GET /?q=v HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/?q=v");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_231" {
    try req(
        "GET ?x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "?x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "%C3%B1");
            }
        },
    );
}

test "urltest_232" {
    try req(
        "GET ?x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "?x");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "%C3%B1");
            }
        },
    );
}

test "urltest_233" {
    try req(
        "GET // HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "//");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_234" {
    try req(
        "GET //x/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "//x/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_235" {
    try req(
        "GET /someconfig;mode=netascii HTTP/1.1\r\nHost: foobar.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/someconfig;mode=netascii");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "foobar.com");
            }
        },
    );
}

test "urltest_236" {
    try req(
        "GET /Index.ut2 HTTP/1.1\r\nHost: 10.10.10.10\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/Index.ut2");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "10.10.10.10");
            }
        },
    );
}

test "urltest_237" {
    try req(
        "GET /0?baz=bam&qux=baz HTTP/1.1\r\nHost: somehost\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/0?baz=bam&qux=baz");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "somehost");
            }
        },
    );
}

test "urltest_238" {
    try req(
        "GET /sup HTTP/1.1\r\nHost: host\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/sup");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "host");
            }
        },
    );
}

test "urltest_239" {
    try req(
        "GET /foo/bar.git HTTP/1.1\r\nHost: github.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar.git");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "github.com");
            }
        },
    );
}

test "urltest_240" {
    try req(
        "GET /channel?passwd HTTP/1.1\r\nHost: myserver.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/channel?passwd");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "myserver.com");
            }
        },
    );
}

test "urltest_241" {
    try req(
        "GET /foo.bar.org?type=TXT HTTP/1.1\r\nHost: fw.example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo.bar.org?type=TXT");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "fw.example.org");
            }
        },
    );
}

test "urltest_242" {
    try req(
        "GET /ou=People,o=JNDITutorial HTTP/1.1\r\nHost: localhost\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/ou=People,o=JNDITutorial");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "localhost");
            }
        },
    );
}

test "urltest_243" {
    try req(
        "GET /foo/bar HTTP/1.1\r\nHost: github.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "github.com");
            }
        },
    );
}

test "urltest_244" {
    try req(
        "GET ietf:rfc:2648 HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "ietf:rfc:2648");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_245" {
    try req(
        "GET joe@example.org,2001:foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "joe@example.org,2001:foo/bar");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_246" {
    try req(
        "GET /path HTTP/1.1\r\nHost: H%4fSt\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/path");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "H%4fSt");
            }
        },
    );
}

test "urltest_247" {
    try req(
        "GET https://example.com:443/ HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "https://example.com:443/");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_248" {
    try req(
        "GET d3958f5c-0777-0845-9dcf-2cb28783acaf HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "d3958f5c-0777-0845-9dcf-2cb28783acaf");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_249" {
    try req(
        "GET /test?%22 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?%22");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_250" {
    try req(
        "GET /test HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_251" {
    try req(
        "GET /test?%3C HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?%3C");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_252" {
    try req(
        "GET /test?%3E HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?%3E");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_253" {
    try req(
        "GET /test?%E2%8C%A3 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?%E2%8C%A3");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_254" {
    try req(
        "GET /test?%23%23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?%23%23");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_255" {
    try req(
        "GET /test?%GH HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?%GH");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_256" {
    try req(
        "GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_257" {
    try req(
        "GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_258" {
    try req(
        "GET /test-a-colon-slash.html HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test-a-colon-slash.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_259" {
    try req(
        "GET /test-a-colon-slash-slash.html HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test-a-colon-slash-slash.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_260" {
    try req(
        "GET /test-a-colon-slash-b.html HTTP/1.1\r\nHost: \r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test-a-colon-slash-b.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "");
            }
        },
    );
}

test "urltest_261" {
    try req(
        "GET /test-a-colon-slash-slash-b.html HTTP/1.1\r\nHost: b\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test-a-colon-slash-slash-b.html");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "b");
            }
        },
    );
}

test "urltest_262" {
    try req(
        "GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/test?a");
                try expectedVersion(r.version.?, 1);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "example.org");
            }
        },
    );
}

test "urltest_nvidia" {
    try req(
        "GET /nvidia_web_services/controller.gfeclientcontent.php/com.nvidia.services.GFEClientContent.getShieldReady/{\"gcV\":\"2.2.2.0\",\"dID\":\"1341\",\"osC\":\"6.20\",\"is6\":\"1\",\"lg\":\"1033\",\"GFPV\":\"389.08\",\"isO\":\"1\",\"sM\":\"16777216\"} HTTP/1.0\r\nHost: gfwsl.geforce.com\r\n\r\n",
        struct {
            fn check(r: *Request) !void {
                try expectedStrings(r.method.?, "GET");
                try expectedStrings(r.path.?, "/nvidia_web_services/controller.gfeclientcontent.php/com.nvidia.services.GFEClientContent.getShieldReady/{\"gcV\":\"2.2.2.0\",\"dID\":\"1341\",\"osC\":\"6.20\",\"is6\":\"1\",\"lg\":\"1033\",\"GFPV\":\"389.08\",\"isO\":\"1\",\"sM\":\"16777216\"}");
                try expectedVersion(r.version.?, 0);
                try expectedHeaderLen(r.headers.items.len, 1);
                try expectedStrings(r.headers.items[0].name, "Host");
                try expectedStrings(r.headers.items[0].value, "gfwsl.geforce.com");
            }
        },
    );
}
