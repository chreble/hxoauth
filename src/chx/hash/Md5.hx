/*
 * Copyright (c) 2008, The Caffeine-hx project contributors
 * Original author : Russell Weir
 * Contributors:
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CAFFEINE-HX PROJECT CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE CAFFEINE-HX PROJECT CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package chx.hash;

import chx.BytesUtil;
import haxe.io.Bytes;
import chx.HexUtil;
import chx.I32;
import haxe.Int32;

using haxe.Int32;

class Md5 implements IHash {

	public function new() {
	}

	public function toString() : String {
		return "md5";
	}

	public function calculate( msg:Bytes ) : String {
		return HexUtil.bytesToHex(encode(msg));
	}

	public function calcBin( msg: Bytes ) : Bytes {
		return encode(msg);
	}

	public function getLengthBytes() : Int {
		return 16;
	}

	public function getLengthBits() : Int {
		return 128;
	}

	public function getBlockSizeBytes() : Int {
		return 64;
	}

	public function getBlockSizeBits() : Int {
		return 512;
	}

	public static function encode(msg : Bytes) : Bytes {
		return BytesUtil.ofHex(haxe.Md5.encode(msg.toString()));
	}

/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Copyright (C) Paul Johnston 1999 - 2000.
 * Updated by Greg Holt 2000 - 2001.
 * See http://pajhome.org.uk/site/legal.html for details.
 */

	static var inst = new Md5();

	function bitOR(a:Int32, b: Int32){
		var lsb = a.and(Int32.ofInt(0x1)).or( b.and(Int32.ofInt(0x1)) );
		var msb31 = a.ushr(1).or(b.ushr(1));
		return msb31.shl(1).or(lsb);
	}

	function bitXOR(a:Int32, b: Int32){
		var lsb = a.and(Int32.ofInt(0x1)).xor( b.and(Int32.ofInt(0x1)) );
		var msb31 = a.ushr(1).xor(b.ushr(1));
		return msb31.shl(1).or(lsb);
	}

	function bitAND(a:Int32, b: Int32){
		var lsb = a.and(Int32.ofInt(0x1)).and( b.and(Int32.ofInt(0x1)) );
		var msb31 = a.ushr(1).and(b.ushr(1));
		return msb31.shl(1).or(lsb);
	}

	function str2blks( str : Bytes ) {
		var nblk = ((str.length + 8) >> 6) + 1;
		var blks = new Array<Int32>();
		for( i in 0...(nblk * 16) ) blks[i] = Int32.ofInt(0);

		var i = 0;
		while( i < str.length ) {
			blks[i >> 2] = blks[i >> 2].or(Int32.ofInt(str.get(i)).shl(((str.length * 8 + i) % 4) * 8));
			i++;
		}
		blks[i >> 2] = blks[i >> 2].or(Int32.ofInt(0x80).shl(((str.length * 8 + i) % 4) * 8));
		var l = Int32.ofInt(str.length * 8);
		blks[nblk * 16 - 2] = l.and(Int32.ofInt(0xFF));
		blks[nblk * 16 - 2] = blks[nblk * 16 - 2].or(l.ushr(8).and(Int32.ofInt(0xFF)).shl(8));
		blks[nblk * 16 - 2] = blks[nblk * 16 - 2].or(l.ushr(16).and(Int32.ofInt(0xFF)).shl(16));
		blks[nblk * 16 - 2] = blks[nblk * 16 - 2].or(l.ushr(24).and(Int32.ofInt(0xFF)).shl(24));

		return blks;
	}

	function rol(num: Int32, cnt){
		return num.shl(cnt).or(num.ushr(32 - cnt));
	}

	function cmn(q, a, b, x, s, t) {
		return Util.safeAdd(rol((Util.safeAdd(Util.safeAdd(a, q), Util.safeAdd(x, t))), s), b);
	}

	function ff(a, b: Int32, c, d, x, s, t){
		return cmn(bitOR(bitAND(b, c), bitAND(b.complement(), d)), a, b, x, s, t);
	}

	function gg(a, b, c, d, x, s, t){
		return cmn(bitOR(bitAND(b, d), bitAND(c, d.complement())), a, b, x, s, t);
	}

	function hh(a, b, c, d, x, s, t){
		return cmn(bitXOR(bitXOR(b, c), d), a, b, x, s, t);
	}

	function ii(a, b, c, d: Int32, x, s, t){
		return cmn(bitXOR(c, bitOR(b, d.complement())), a, b, x, s, t);
	}

	function doEncode( str:Bytes ) : Bytes {

		var x = str2blks(str);
		var a = i32(0x6745, 0x2301); 
		var b = i32(0xEFCD, 0xAB89); 
		var c = i32(0x98BA, 0xDCFE); 
		var d = i32(0x1032, 0x5476); 

		var step;

		var i = 0;
		while( i < x.length )  {
			var olda = a;
			var oldb = b;
			var oldc = c;
			var oldd = d;

			step = 0;
			a = ff(a, b, c, d, x[i+ 0], 7 , i32(0xd76a, 0xa478));
			d = ff(d, a, b, c, x[i+ 1], 12, i32(0xe8c7, 0xb756));
			c = ff(c, d, a, b, x[i+ 2], 17, i32(0x2420, 0x70db));
			b = ff(b, c, d, a, x[i+ 3], 22, i32(0xc1bd, 0xceee));
			a = ff(a, b, c, d, x[i+ 4], 7 , i32(0xf57c, 0x0faf));
			d = ff(d, a, b, c, x[i+ 5], 12, i32(0x4787, 0xc62a));
			c = ff(c, d, a, b, x[i+ 6], 17, i32(0xa830, 0x4613));
			b = ff(b, c, d, a, x[i+ 7], 22, i32(0xfd46, 0x9501));
			a = ff(a, b, c, d, x[i+ 8], 7 , i32(0x6980, 0x98d8));
			d = ff(d, a, b, c, x[i+ 9], 12, i32(0x8b44, 0xf7af));
			c = ff(c, d, a, b, x[i+10], 17, i32(0xffff, 0x5bb1));
			b = ff(b, c, d, a, x[i+11], 22, i32(0x895c, 0xd7be));
			a = ff(a, b, c, d, x[i+12], 7 , i32(0x6b90, 0x1122));
			d = ff(d, a, b, c, x[i+13], 12, i32(0xfd98, 0x7193));
			c = ff(c, d, a, b, x[i+14], 17, i32(0xa679, 0x438e));
			b = ff(b, c, d, a, x[i+15], 22, i32(0x49b4, 0x0821));
			a = gg(a, b, c, d, x[i+ 1], 5 , i32(0xf61e, 0x2562));
			d = gg(d, a, b, c, x[i+ 6], 9 , i32(0xc040, 0xb340));
			c = gg(c, d, a, b, x[i+11], 14, i32(0x265e, 0x5a51));
			b = gg(b, c, d, a, x[i+ 0], 20, i32(0xe9b6, 0xc7aa));
			a = gg(a, b, c, d, x[i+ 5], 5 , i32(0xd62f, 0x105d));
			d = gg(d, a, b, c, x[i+10], 9 , i32(0x0244, 0x1453));
			c = gg(c, d, a, b, x[i+15], 14, i32(0xd8a1, 0xe681));
			b = gg(b, c, d, a, x[i+ 4], 20, i32(0xe7d3, 0xfbc8));
			a = gg(a, b, c, d, x[i+ 9], 5 , i32(0x21e1, 0xcde6));
			d = gg(d, a, b, c, x[i+14], 9 , i32(0xc337, 0x07d6));
			c = gg(c, d, a, b, x[i+ 3], 14, i32(0xf4d5, 0x0d87));
			b = gg(b, c, d, a, x[i+ 8], 20, i32(0x455a, 0x14ed));
			a = gg(a, b, c, d, x[i+13], 5 , i32(0xa9e3, 0xe905));
			d = gg(d, a, b, c, x[i+ 2], 9 , i32(0xfcef, 0xa3f8));
			c = gg(c, d, a, b, x[i+ 7], 14, i32(0x676f, 0x02d9));
			b = gg(b, c, d, a, x[i+12], 20, i32(0x8d2a, 0x4c8a));
			a = hh(a, b, c, d, x[i+ 5], 4 , i32(0xfffa, 0x3942));
			d = hh(d, a, b, c, x[i+ 8], 11, i32(0x8771, 0xf681));
			c = hh(c, d, a, b, x[i+11], 16, i32(0x6d9d, 0x6122));
			b = hh(b, c, d, a, x[i+14], 23, i32(0xfde5, 0x380c));
			a = hh(a, b, c, d, x[i+ 1], 4 , i32(0xa4be, 0xea44));
			d = hh(d, a, b, c, x[i+ 4], 11, i32(0x4bde, 0xcfa9));
			c = hh(c, d, a, b, x[i+ 7], 16, i32(0xf6bb, 0x4b60));
			b = hh(b, c, d, a, x[i+10], 23, i32(0xbebf, 0xbc70));
			a = hh(a, b, c, d, x[i+13], 4 , i32(0x289b, 0x7ec6));
			d = hh(d, a, b, c, x[i+ 0], 11, i32(0xeaa1, 0x27fa));
			c = hh(c, d, a, b, x[i+ 3], 16, i32(0xd4ef, 0x3085));
			b = hh(b, c, d, a, x[i+ 6], 23, i32(0x0488, 0x1d05));
			a = hh(a, b, c, d, x[i+ 9], 4 , i32(0xd9d4, 0xd039));
			d = hh(d, a, b, c, x[i+12], 11, i32(0xe6db, 0x99e5));
			c = hh(c, d, a, b, x[i+15], 16, i32(0x1fa2, 0x7cf8));
			b = hh(b, c, d, a, x[i+ 2], 23, i32(0xc4ac, 0x5665));
			a = ii(a, b, c, d, x[i+ 0], 6 , i32(0xf429, 0x2244));
			d = ii(d, a, b, c, x[i+ 7], 10, i32(0x432a, 0xff97));
			c = ii(c, d, a, b, x[i+14], 15, i32(0xab94, 0x23a7));
			b = ii(b, c, d, a, x[i+ 5], 21, i32(0xfc93, 0xa039));
			a = ii(a, b, c, d, x[i+12], 6 , i32(0x655b, 0x59c3));
			d = ii(d, a, b, c, x[i+ 3], 10, i32(0x8f0c, 0xcc92));
			c = ii(c, d, a, b, x[i+10], 15, i32(0xffef, 0xf47d));
			b = ii(b, c, d, a, x[i+ 1], 21, i32(0x8584, 0x5dd1));
			a = ii(a, b, c, d, x[i+ 8], 6 , i32(0x6fa8, 0x7e4f));
			d = ii(d, a, b, c, x[i+15], 10, i32(0xfe2c, 0xe6e0));
			c = ii(c, d, a, b, x[i+ 6], 15, i32(0xa301, 0x4314));
			b = ii(b, c, d, a, x[i+13], 21, i32(0x4e08, 0x11a1));
			a = ii(a, b, c, d, x[i+ 4], 6 , i32(0xf753, 0x7e82));
			d = ii(d, a, b, c, x[i+11], 10, i32(0xbd3a, 0xf235));
			c = ii(c, d, a, b, x[i+ 2], 15, i32(0x2ad7, 0xd2bb));
			b = ii(b, c, d, a, x[i+ 9], 21, i32(0xeb86, 0xd391));

			a = Util.safeAdd(a, olda);
			b = Util.safeAdd(b, oldb);
			c = Util.safeAdd(c, oldc);
			d = Util.safeAdd(d, oldd);

			i += 16;
		}
		return I32.packLE(cast [a,b,c,d]);
	}
	
	private static inline function i32(a: Int, b: Int)
	{
		return Int32.make(a, b);
	}
	
}
