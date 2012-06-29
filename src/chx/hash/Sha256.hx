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

/*
 * Adapted from:
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-256
 * Version 0.3 Copyright Angel Marin 2003-2004 - http://anmar.eu.org/
 * http://anmar.eu.org/projects/jssha2/
 * Distributed under the BSD License
 * Some bits taken from Paul Johnston's SHA-1 implementation
 */

package chx.hash;

import chx.BytesUtil;
import chx.I32;
import chx.HexUtil;
import haxe.Int32;
import haxe.io.Bytes;
import haxe.io.BytesBuffer;

using haxe.Int32;

class Sha256 implements IHash {

	public function new() {
	}

	public function toString() : String {
		return "sha256";
	}

	public function calculate( msg:Bytes ) : String {
		return HexUtil.bytesToHex(encode(msg));
	}

	public function calcBin( msg:Bytes ) : Bytes {
		return encode(msg);
	}

	public function getLengthBytes() : Int {
		return 32;
	}

	public function getLengthBits() : Int {
		return 256;
	}

	public function getBlockSizeBytes() : Int {
		return 64;
	}

	public function getBlockSizeBits() : Int {
		return 512;
	}
	
	private static var charSize : Int = 8;
	public static function encode(s : Bytes) : Bytes {
		var add = 4 - (s.length % 4);
		var len = s.length;
		
		if (add < 4)
		{
			var buf = new BytesBuffer();
			buf.add(s);
			for(i in 0 ... add)
				buf.addByte(0);
			s = buf.getBytes();
		}
		
		var pb = I32.unpackBE(s);
		var res = core_sha256(pb, len * charSize);
		return I32.packBE(cast res);
	}

	static inline function S (X: Int32, n) {
		X = unNull(X);
		return X.ushr( n ).or( X.shl(32 - n) );
	}
	static inline function R (X: Int32, n) {
		X = unNull(X);
		return X .ushr( n );
	}
	static inline function Ch(x: Int32, y: Int32, z: Int32) {
		x = unNull(x);
		y = unNull(y);
		z = unNull(z);
		return x.and(y).xor(x.complement().and( z ));
	}
	static inline function Maj(x: Int32, y: Int32, z: Int32) {
		x = unNull(x);
		y = unNull(y);
		z = unNull(z);
		return x.and(y).xor(x.and(z)).xor(y.and(z));
	}
	static inline function Sigma0256(x: Int32) {
		x = unNull(x);
		return S(x, 2).xor(S(x, 13)).xor(S(x, 22));
	}
	static inline function Sigma1256(x: Int32) {
		x = unNull(x);
		return S(x, 6).xor(S(x, 11)).xor(S(x, 25));
	}
	static inline function Gamma0256(x: Int32) {
		x = unNull(x);
		return S(x, 7).xor(S(x, 18)).xor(R(x, 3));
	}
	static inline function Gamma1256(x: Int32) {
		x = unNull(x);
		return S(x, 17).xor(S(x, 19)).xor(R(x, 10));
	}
	static function core_sha256 (m: Array<Int32>, l) {
		var K : Array<Int32> = [
			i32(0x428A, 0x2F98),i32(0x7137, 0x4491),i32(0xB5C0, 0xFBCF),i32(0xE9B5, 0xDBA5),i32(0x3956, 0xC25B),
			i32(0x59F1, 0x11F1),i32(0x923F, 0x82A4),i32(0xAB1C, 0x5ED5),i32(0xD807, 0xAA98),i32(0x1283, 0x5B01),
			i32(0x2431, 0x85BE),i32(0x550C, 0x7DC3),i32(0x72BE, 0x5D74),i32(0x80DE, 0xB1FE),i32(0x9BDC, 0x06A7),
			i32(0xC19B, 0xF174),i32(0xE49B, 0x69C1),i32(0xEFBE, 0x4786),i32(0x0FC1, 0x9DC6),i32(0x240C, 0xA1CC),
			i32(0x2DE9, 0x2C6F),i32(0x4A74, 0x84AA),i32(0x5CB0, 0xA9DC),i32(0x76F9, 0x88DA),i32(0x983E, 0x5152),
			i32(0xA831, 0xC66D),i32(0xB003, 0x27C8),i32(0xBF59, 0x7FC7),i32(0xC6E0, 0x0BF3),i32(0xD5A7, 0x9147),
			i32(0x06CA, 0x6351),i32(0x1429, 0x2967),i32(0x27B7, 0x0A85),i32(0x2E1B, 0x2138),i32(0x4D2C, 0x6DFC),
			i32(0x5338, 0x0D13),i32(0x650A, 0x7354),i32(0x766A, 0x0ABB),i32(0x81C2, 0xC92E),i32(0x9272, 0x2C85),
			i32(0xA2BF, 0xE8A1),i32(0xA81A, 0x664B),i32(0xC24B, 0x8B70),i32(0xC76C, 0x51A3),i32(0xD192, 0xE819),
			i32(0xD699, 0x0624),i32(0xF40E, 0x3585),i32(0x106A, 0xA070),i32(0x19A4, 0xC116),i32(0x1E37, 0x6C08),
			i32(0x2748, 0x774C),i32(0x34B0, 0xBCB5),i32(0x391C, 0x0CB3),i32(0x4ED8, 0xAA4A),i32(0x5B9C, 0xCA4F),
			i32(0x682E, 0x6FF3),i32(0x748F, 0x82EE),i32(0x78A5, 0x636F),i32(0x84C8, 0x7814),i32(0x8CC7, 0x0208),
			i32(0x90BE, 0xFFFA),i32(0xA450, 0x6CEB),i32(0xBEF9, 0xA3F7),i32(0xC671, 0x78F2)
		];
		var HASH : Array<Int32> = [
			i32(0x6A09, 0xE667), i32(0xBB67, 0xAE85), i32(0x3C6E, 0xF372), i32(0xA54F, 0xF53A),
			i32(0x510E, 0x527F), i32(0x9B05, 0x688C), i32(0x1F83, 0xD9AB), i32(0x5BE0, 0xCD19)
		];
		
		var W = new Array<Int32>();
		
		for (i in 0 ... 65)
			W[i] = Int32.ofInt(0);
		//W[64] = 0;
		
		var a:Int32,b:Int32,c:Int32,d:Int32,e:Int32,f:Int32,g:Int32,h:Int32;
		var T1, T2;
		/* append padding */
		
		var _l = l >> 5;
		if (m[_l] == null)
			m[_l] = Int32.ofInt(0);			
		
		m[l >> 5] = m[l >> 5].or(Int32.ofInt(0x80).shl(24 - l % 32));
		m[((l + 64 >> 9) << 4) + 15] = Int32.ofInt(l);
		var i : Int = 0;
		while ( i < m.length ) {
			a = HASH[0]; b = HASH[1]; c = HASH[2]; d = HASH[3]; e = HASH[4]; f = HASH[5]; g = HASH[6]; h = HASH[7];
			for ( j in 0...64 ) {
				if (j < 16)
					W[j] = m[j + i];
				else
					W[j] = Util.safeAdd(Util.safeAdd(Util.safeAdd(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
				T1 = Util.safeAdd(Util.safeAdd(Util.safeAdd(Util.safeAdd(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
				T2 = Util.safeAdd(Sigma0256(a), Maj(a, b, c));
				h = g; g = f; f = e; e = Util.safeAdd(d, T1); d = c; c = b; b = a; a = Util.safeAdd(T1, T2);
			}
			HASH[0] = Util.safeAdd(a, HASH[0]);
			HASH[1] = Util.safeAdd(b, HASH[1]);
			HASH[2] = Util.safeAdd(c, HASH[2]);
			HASH[3] = Util.safeAdd(d, HASH[3]);
			HASH[4] = Util.safeAdd(e, HASH[4]);
			HASH[5] = Util.safeAdd(f, HASH[5]);
			HASH[6] = Util.safeAdd(g, HASH[6]);
			HASH[7] = Util.safeAdd(h, HASH[7]);
			i += 16;
		}
		return HASH;
	}
	
	private static inline function i32(a: Int, b: Int)
	{
		return Int32.make(a, b);
	}
	
	private static inline function unNull(i: Int32)
	{
		return if (i == null) Int32.ofInt(0) else i;
	}

}
