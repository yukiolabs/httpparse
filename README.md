# httpparse
A push zig library for parsing HTTP/1.x requests and responses. 

```zig
    var r = Request.new();
    // make sure we free any allocated headers
    defer r.deinit();
    std.debug.assert((try r.parse("GET /index.html HTTP/1.1\r\nHost")).is_partial());
    // a partial request, so we try again once we have more data
    std.debug.assert((try r.parse("GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n")).is_complete());
```