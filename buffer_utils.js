BufferUtils = (function() {
  function hex_string_to_buffer(str) {
    var bytes = [];

    // strip 0x prefix
    if (str.length >= 2 && str.substr(0, 2).toLowerCase() == "0x") {
      str = str.substr(2);
    }

    while (str.length > 0) {
      bytes.unshift(parseInt(str.slice(-2), 16));
      str = str.slice(0, -2);
    }

    return new Uint8Array(bytes).buffer;
  }

  function buffer_add(buffer, n) {
    var add_bytes = new Uint8Array(buffer);
    var c = 0;

    for (var i = add_bytes.length-1; i > 0 && n+c > 0; i--) {
      c = add_bytes[i] + (n&0xff) + c;
      add_bytes[i] = c & 0xff;
      c >>= 8;
      n >>= 8;
    }

    return add_bytes.buffer;
  }

  function buffer_equal(abuffer, bbuffer) {
    var a = new Uint8Array(abuffer);
    var b = new Uint8Array(bbuffer);

    if (a.length != b.length) {
      return false;
    }

    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }

    return true;
  }

  function buffer_hex_string(buffer) {
    var bytes = new Uint8Array(buffer);
    var l = [];

    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      l.push((b < 0x10 ? "0" : "") + b.toString(16));
    }

    return l.join(" ");
  }

  return {
    hex_string_to_buffer: hex_string_to_buffer,
    buffer_add: buffer_add,
    buffer_equal: buffer_equal,
    buffer_hex_string: buffer_hex_string
  };
})();

