// JavaScript AES implementation using ArrayBuffer
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

AES = (function() {
  // spec from http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

  // for performance cipher and inv_cipher do not create new objects
  // instead they take a input buffer and pass it around to keep state
  // and it is also used as output.

  var block_size_bytes = 16;
  var block_size_words = 4;
  var nb = 4;
  var sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ];

  var inv_sbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  ];

  var rcon = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000
  ];

  // from http://www.cs.utsa.edu/~wagner/laws/FFM.html
  function ffmul(a, b) {
    var r = 0;
    var t;

    while (a) {
      if ((a & 1)) {
        r = r ^ b;
      }

      t = b & 0x80;
      b <<= 1;
      if (t) {
        b ^= 0x1b;
      }

      a >>= 1;
    }

    return r;
  }

  function ffmul_table(n) {
    var table = new Array(256);

    for (var i = 0; i < 256; i++) {
      table[i] = ffmul(n, i) & 0xff;
    }

    return table;
  }

  // precompute for factors used in (inv)mix_columns
  var ffmul_t_2 = ffmul_table(2);
  var ffmul_t_3 = ffmul_table(3);
  var ffmul_t_9 = ffmul_table(9);
  var ffmul_t_b = ffmul_table(0xb);
  var ffmul_t_d = ffmul_table(0xd);
  var ffmul_t_e = ffmul_table(0xe);

  function sub_word(w) {
    return (
      sbox[w >>> 24] << 24 |
      sbox[(w >>> 16) & 0xff] << 16 |
      sbox[(w >>> 8) & 0xff] << 8 |
      sbox[w & 0xff]
    );
  }

  function rot_word(w) {
    return w >>> 24 | w << 8;
  }

  function endian_swap32(n) {
    return n >>> 24 | (n & 0xff0000) >>> 8 | (n & 0xff00) << 8 | (n & 0xff) << 24;
  }

  // little endian if first byte in 32 bit uint 1 is 1
  var is_little_endian = ((new Uint8Array((new Uint32Array([1])).buffer))[0] == 1);

  // key is 16, 24 or 32 byte ArrayBuffer
  function key_expansion(key) {
    var key_u8 = new Uint8Array(key);
    var nk = key_u8.length / 4;
    var nr = nk + 6;

    var w = new Uint32Array(nb * (nr+1));
    for (var i = 0; i < nk; i++) {
      w[i] = (
        key_u8[i*4] << 24 |
        key_u8[i*4+1] << 16 |
        key_u8[i*4+2] << 8 |
        key_u8[i*4+3]
      );
    }

    for (var i = nk; i < nb*(nr+1); i++) {
      var temp = w[i - 1];
      if (i % nk == 0) {
        temp = sub_word(rot_word(temp)) ^ rcon[i/nk];
      } else if (nk > 6 && i % nk == 4) {
        temp = sub_word(temp);
      }

      w[i] = w[i - nk] ^ temp;
    }

    // make sure key schedule byte order matches state byte order
    // this is so that correct bytes are xored for add_round_key
    if (is_little_endian) {
      for (var i = 0; i < w.length; i++) {
        w[i] = endian_swap32(w[i]);
      }
    }

    return w;
  }

  // state_u8 is 16 byte Uint8Array (also used as output)
  // w is value from key_expansion
  function cipher(state_u32, w) {
    var nr = (w.length / nb - 1)*4;
    var s0, s1, s2, s3;
    var t0, t1, t2, t3;
    var m0, m1, m2, m3;

    // add_round_key
    s0 = (state_u32[0] ^ w[0]) >>> 0;
    s1 = (state_u32[1] ^ w[1]) >>> 0;
    s2 = (state_u32[2] ^ w[2]) >>> 0;
    s3 = (state_u32[3] ^ w[3]) >>> 0;

    for (var round = 4; round < nr; round += 4) {
      // sub_byte, shift_rows, mix_columns, add_round_key

      t0 = s0;
      t1 = s1;
      t2 = s2;
      t3 = s3;

      m0 = sbox[t0 & 0xff] >>> 0;
      m1 = sbox[(t1 >>> 8) & 0xff] >>> 0;
      m2 = sbox[(t2 >>> 16) & 0xff] >>> 0;
      m3 = sbox[t3 >>> 24] >>> 0;
      s0 = ((
        (ffmul_t_2[m0] ^ ffmul_t_3[m1] ^ m2 ^ m3) |
        (m0 ^ ffmul_t_2[m1] ^ ffmul_t_3[m2] ^ m3) << 8 |
        (m0 ^ m1 ^ ffmul_t_2[m2] ^ ffmul_t_3[m3]) << 16 |
        (ffmul_t_3[m0] ^ m1 ^ m2 ^ ffmul_t_2[m3]) << 24
      ) ^ w[round]) >>> 0;
      m0 = sbox[t1 & 0xff] >>> 0;
      m1 = sbox[(t2 >>> 8) & 0xff] >>> 0;
      m2 = sbox[(t3 >>> 16) & 0xff] >>> 0;
      m3 = sbox[t0 >>> 24] >>> 0;
      s1 = ((
        (ffmul_t_2[m0] ^ ffmul_t_3[m1] ^ m2 ^ m3) |
        (m0 ^ ffmul_t_2[m1] ^ ffmul_t_3[m2] ^ m3) << 8 |
        (m0 ^ m1 ^ ffmul_t_2[m2] ^ ffmul_t_3[m3]) << 16 |
        (ffmul_t_3[m0] ^ m1 ^ m2 ^ ffmul_t_2[m3]) << 24
      ) ^ w[round+1]) >>> 0;
      m0 = sbox[t2 & 0xff] >>> 0;
      m1 = sbox[(t3 >>> 8) & 0xff] >>> 0;
      m2 = sbox[(t0 >>> 16) & 0xff] >>> 0;
      m3 = sbox[t1 >>> 24] >>> 0;
      s2 = ((
        (ffmul_t_2[m0] ^ ffmul_t_3[m1] ^ m2 ^ m3) |
        (m0 ^ ffmul_t_2[m1] ^ ffmul_t_3[m2] ^ m3) << 8 |
        (m0 ^ m1 ^ ffmul_t_2[m2] ^ ffmul_t_3[m3]) << 16 |
        (ffmul_t_3[m0] ^ m1 ^ m2 ^ ffmul_t_2[m3]) << 24
      ) ^ w[round+2]) >>> 0;
      m0 = sbox[t3 & 0xff] >>> 0;
      m1 = sbox[(t0 >>> 8) & 0xff] >>> 0;
      m2 = sbox[(t1 >>> 16) & 0xff] >>> 0;
      m3 = sbox[t2 >>> 24] >>> 0;
      s3 = ((
        (ffmul_t_2[m0] ^ ffmul_t_3[m1] ^ m2 ^ m3) |
        (m0 ^ ffmul_t_2[m1] ^ ffmul_t_3[m2] ^ m3) << 8 |
        (m0 ^ m1 ^ ffmul_t_2[m2] ^ ffmul_t_3[m3]) << 16 |
        (ffmul_t_3[m0] ^ m1 ^ m2 ^ ffmul_t_2[m3]) << 24
      ) ^ w[round+3]) >>> 0;
    }

    // sub_byte, shift_rows, add_round_key
    state_u32[0] = w[nr] ^ (sbox[s0 & 0xff] | sbox[(s1 >>> 8) & 0xff] << 8 | sbox[(s2 >>> 16) & 0xff] << 16 | sbox[s3 >>> 24] << 24);
    state_u32[1] = w[nr+1] ^ (sbox[s1 & 0xff] | sbox[(s2 >>> 8) & 0xff] << 8 | sbox[(s3 >>> 16) & 0xff] << 16 | sbox[s0 >>> 24] << 24);
    state_u32[2] = w[nr+2] ^ (sbox[s2 & 0xff] | sbox[(s3 >>> 8) & 0xff] << 8 | sbox[(s0 >>> 16) & 0xff] << 16 | sbox[s1 >>> 24] << 24);
    state_u32[3] = w[nr+3] ^ (sbox[s3 & 0xff] | sbox[(s0 >>> 8) & 0xff] << 8 | sbox[(s1 >>> 16) & 0xff] << 16 | sbox[s2 >>> 24] << 24);
  }

  // state_u8 is 16 byte Uint8Array (also used as output)
  // w is value from key_expansion
  function inv_cipher(state_u32, w) {
    var nr = (w.length / nb - 1) * 4;
    var s0, s1, s2, s3;
    var t0, t1, t2, t3;

    // add_round_key
    s0 = (state_u32[0] ^ w[nr]) >>> 0;
    s1 = (state_u32[1] ^ w[nr+1]) >>> 0;
    s2 = (state_u32[2] ^ w[nr+2]) >>> 0;
    s3 = (state_u32[3] ^ w[nr+3]) >>> 0;

    for (var round = nr-4; round > 0; round -= 4) {
      // inv_shift_rows, inv_sub_byte, add_round_key

      t0 = s0;
      t1 = s1;
      t2 = s2;
      t3 = s3;
      s0 = ((
          inv_sbox[t0 & 0xff] | inv_sbox[(t3 >>> 8) & 0xff] << 8 | inv_sbox[(t2 >>> 16) & 0xff] << 16 | inv_sbox[t1 >>> 24] << 24
          ) ^ w[round]) >>> 0;
      s1 = ((
          inv_sbox[t1 & 0xff] | inv_sbox[(t0 >>> 8) & 0xff] << 8 | inv_sbox[(t3 >>> 16) & 0xff] << 16 | inv_sbox[t2 >>> 24] << 24
          ) ^ w[round+1]) >>> 0;
      s2 = ((
        inv_sbox[t2 & 0xff] | inv_sbox[(t1 >>> 8) & 0xff] << 8 | inv_sbox[(t0 >>> 16) & 0xff] << 16 | inv_sbox[t3 >>> 24] << 24
        ) ^ w[round+2]) >>> 0;
      s3 = ((
        inv_sbox[t3 & 0xff] | inv_sbox[(t2 >>> 8) & 0xff] << 8 | inv_sbox[(t1 >>> 16) & 0xff] << 16 | inv_sbox[t0 >>> 24] << 24
        ) ^ w[round+3]) >>> 0;

      // inv_mix_columns
      t0 = s0 & 0xff >>> 0;
      t1 = ((s0 >>> 8) & 0xff) >>>0;
      t2 = ((s0 >>> 16) & 0xff) >>> 0;
      t3 = s0 >>> 24;
      s0 = (
        (ffmul_t_e[t0] ^ ffmul_t_b[t1] ^ ffmul_t_d[t2] ^ ffmul_t_9[t3]) |
        (ffmul_t_9[t0] ^ ffmul_t_e[t1] ^ ffmul_t_b[t2] ^ ffmul_t_d[t3]) << 8 |
        (ffmul_t_d[t0] ^ ffmul_t_9[t1] ^ ffmul_t_e[t2] ^ ffmul_t_b[t3]) << 16 |
        (ffmul_t_b[t0] ^ ffmul_t_d[t1] ^ ffmul_t_9[t2] ^ ffmul_t_e[t3]) << 24
      ) >>> 0;
      t0 = (s1 & 0xff) >>> 0;
      t1 = ((s1 >>> 8) & 0xff) >>> 0;
      t2 = ((s1 >>> 16) & 0xff) >>> 0;
      t3 = s1 >>> 24;
      s1 = (
        (ffmul_t_e[t0] ^ ffmul_t_b[t1] ^ ffmul_t_d[t2] ^ ffmul_t_9[t3]) |
        (ffmul_t_9[t0] ^ ffmul_t_e[t1] ^ ffmul_t_b[t2] ^ ffmul_t_d[t3]) << 8 |
        (ffmul_t_d[t0] ^ ffmul_t_9[t1] ^ ffmul_t_e[t2] ^ ffmul_t_b[t3]) << 16 |
        (ffmul_t_b[t0] ^ ffmul_t_d[t1] ^ ffmul_t_9[t2] ^ ffmul_t_e[t3]) << 24
      ) >>> 0;
      t0 = (s2 & 0xff) >>> 0;
      t1 = ((s2 >>> 8) & 0xff) >>> 0;
      t2 = ((s2 >>> 16) & 0xff) >>> 0;
      t3 = s2 >>> 24;
      s2 = (
        (ffmul_t_e[t0] ^ ffmul_t_b[t1] ^ ffmul_t_d[t2] ^ ffmul_t_9[t3]) |
        (ffmul_t_9[t0] ^ ffmul_t_e[t1] ^ ffmul_t_b[t2] ^ ffmul_t_d[t3]) << 8 |
        (ffmul_t_d[t0] ^ ffmul_t_9[t1] ^ ffmul_t_e[t2] ^ ffmul_t_b[t3]) << 16 |
        (ffmul_t_b[t0] ^ ffmul_t_d[t1] ^ ffmul_t_9[t2] ^ ffmul_t_e[t3]) << 24
      ) >>> 0;
      t0 = (s3 & 0xff) >>> 0;
      t1 = ((s3 >>> 8) & 0xff) >>> 0;
      t2 = ((s3 >>> 16) & 0xff) >>> 0;
      t3 = s3 >>> 24;
      s3 = (
        (ffmul_t_e[t0] ^ ffmul_t_b[t1] ^ ffmul_t_d[t2] ^ ffmul_t_9[t3]) |
        (ffmul_t_9[t0] ^ ffmul_t_e[t1] ^ ffmul_t_b[t2] ^ ffmul_t_d[t3]) << 8 |
        (ffmul_t_d[t0] ^ ffmul_t_9[t1] ^ ffmul_t_e[t2] ^ ffmul_t_b[t3]) << 16 |
        (ffmul_t_b[t0] ^ ffmul_t_d[t1] ^ ffmul_t_9[t2] ^ ffmul_t_e[t3]) << 24
      ) >>> 0;
    }

    // inv_shift_rows, inv_sub_byte, add_round_key
    state_u32[0] = w[0] ^ (inv_sbox[s0 & 0xff] | inv_sbox[(s3 >>> 8) & 0xff] << 8 | inv_sbox[(s2 >>> 16) & 0xff] << 16 | inv_sbox[s1 >>> 24] << 24);
    state_u32[1] = w[1] ^ (inv_sbox[s1 & 0xff] | inv_sbox[(s0 >>> 8) & 0xff] << 8 | inv_sbox[(s3 >>> 16) & 0xff] << 16 | inv_sbox[s2 >>> 24] << 24);
    state_u32[2] = w[2] ^ (inv_sbox[s2 & 0xff] | inv_sbox[(s1 >>> 8) & 0xff] << 8 | inv_sbox[(s0 >>> 16) & 0xff] << 16 | inv_sbox[s3 >>> 24] << 24);
    state_u32[3] = w[3] ^ (inv_sbox[s3 & 0xff] | inv_sbox[(s2 >>> 8) & 0xff] << 8 | inv_sbox[(s1 >>> 16) & 0xff] << 16 | inv_sbox[s0 >>> 24] << 24);
  }

  return {
    block_size_bytes: block_size_bytes,
    block_size_words: block_size_words,
    endian_swap32: endian_swap32,
    is_little_endian: is_little_endian,
    key_expansion: key_expansion,
    cipher: cipher,
    inv_cipher: inv_cipher
  };
})();

