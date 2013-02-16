// JavaScript CBC and PKCS padding implementation using ArrayBuffer
// Copyright (c) 2013 <mattias.wadman@gmail.com>
//
// MIT License:
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

Crypto = (function() {
  // CBC spec from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
  // PKCS padding spec from http://tools.ietf.org/html/rfc2315

  var pkcs_max_pad_byte_count = 16;

  // both encrypt_aes_cbc and decrypt_aes_cbc are written to not
  // creating new objects in the block loop.
  // some implementation notes:
  // the manual "copy" in the loop start is due to that .subarray
  // creates new view objects.

  // input is ArrayBuffer with 16 byte aligned length
  // key is 16, 24 or 32 byte ArrayBuffer
  // iv is 16 byte ArrayBuffer
  function encrypt_aes_cbc(input, key, iv) {
    var input_u32 = new Uint32Array(input);
    var output_u32 = new Uint32Array(input_u32.length);
    var state_block_u32 = new Uint32Array(AES.block_size_words);
    var prev_cipher_block_u32 = new Uint32Array(AES.block_size_words);
    var w = AES.key_expansion(key);

    prev_cipher_block_u32.set(new Uint32Array(iv));

    for (var i = 0; i < input_u32.length; i += AES.block_size_words) {
      state_block_u32[0] = input_u32[i+0];
      state_block_u32[1] = input_u32[i+1];
      state_block_u32[2] = input_u32[i+2];
      state_block_u32[3] = input_u32[i+3];

      for (var j = 0; j < AES.block_size_words; j++) {
        state_block_u32[j] ^= prev_cipher_block_u32[j];
      }

      AES.cipher(state_block_u32, w);
      output_u32.set(state_block_u32, i);

      prev_cipher_block_u32.set(state_block_u32);
    }

    return output_u32.buffer;
  }

  // input is ArrayBuffer with 16 byte aligned length
  // key is 16, 24 or 32 byte ArrayBuffer
  // iv is 16 byte ArrayBuffer
  function decrypt_aes_cbc(input, key, iv) {
    var input_u32 = new Uint32Array(input);
    var output_u32 = new Uint32Array(input_u32.length);
    var state_block_u32 = new Uint32Array(AES.block_size_words);
    var input_block_u32 = new Uint32Array(AES.block_size_words);
    var prev_input_block_u32 = new Uint32Array(AES.block_size_words);
    var w = AES.key_expansion(key);

    prev_input_block_u32.set(new Uint32Array(iv));

    for (var i = 0; i < input_u32.length; i += AES.block_size_words) {
      input_block_u32[0] = input_u32[i+0];
      input_block_u32[1] = input_u32[i+1];
      input_block_u32[2] = input_u32[i+2];
      input_block_u32[3] = input_u32[i+3];

      state_block_u32.set(input_block_u32);
      AES.inv_cipher(state_block_u32, w);

      for (var j = 0; j < AES.block_size_words; j++) {
        state_block_u32[j] ^= prev_input_block_u32[j];
      }
      output_u32.set(state_block_u32, i);

      prev_input_block_u32.set(input_block_u32);
    }

    return output_u32.buffer;
  }

  // returns a new buffer with only the padding bytes
  function pkcs_pad_buffer_to_append(length) {
    var pad_byte_count = pkcs_max_pad_byte_count - (length % pkcs_max_pad_byte_count);
    var pad_u8 = new Uint8Array(pad_byte_count);
    for (var i = 0; i < pad_byte_count; i++) {
      pad_u8[i] = pad_byte_count;
    }

    return pad_u8.buffer;
  }

  // returns a new buffer with added padding
  function pkcs_pad(buffer) {
    var pad_buffer = pkcs_pad_buffer_to_append(buffer.byteLength);
    var padded_u8 = new Uint8Array(buffer.byteLength + pad_buffer.byteLength);
    padded_u8.set(new Uint8Array(buffer), 0);
    padded_u8.set(new Uint8Array(pad_buffer), buffer.byteLength);

    return padded_u8.buffer;
  }

  // return number of bytes at end of buffer that is padding
  // returns 0 if buffer has invalid pkcs padding
  function pkcs_pad_byte_count(buffer) {
    var padded_u8 = new Uint8Array(buffer);
    if (padded_u8.length == 0) {
      return 0;
    }

    var count = padded_u8[padded_u8.length-1];
    if (count > padded_u8.length || count > pkcs_max_pad_byte_count) {
      return 0;
    }

    return count;
  }

  // returns a new buffer with padding removed
  function pkcs_unpad(buffer) {
    var unpadded_length = buffer.byteLength - pkcs_pad_byte_count(buffer);

    // HACK: slice missing in older versions of nodejs
    if (!buffer.slice) {
      var padded_bytes = new Uint8Array(buffer);
      var unpadded = new Uint8Array(unpadded_length);
      unpadded.set(padded_bytes.subarray(0, unpadded_length));
      return unpadded.buffer;
    }

    return buffer.slice(0, unpadded_length);
  }

  return {
    encrypt_aes_cbc: encrypt_aes_cbc,
    decrypt_aes_cbc: decrypt_aes_cbc,
    pkcs_pad_buffer_to_append: pkcs_pad_buffer_to_append,
    pkcs_pad: pkcs_pad,
    pkcs_pad_byte_count: pkcs_pad_byte_count,
    pkcs_unpad: pkcs_unpad
  };
})();

