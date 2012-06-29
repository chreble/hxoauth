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
 * Haxe code platforms adapted from SHA1 Javascript implementation
 * adapted from code covered by the LGPL © 2002-2005 Chris Veness,
 * http://www.movable-type.co.uk/scripts/sha1.html
 *
 * Alternative BSD implementation: http://pajhome.org.uk/crypt/md5/sha1src.html
*/

package chx.hash;

import chx.BytesUtil;
import chx.I32;
import chx.HexUtil;
import haxe.io.Bytes;
import haxe.io.BytesBuffer;
import haxe.Int32;

using haxe.Int32;

class Sha1 implements IHash {
	static var K : Array<Int32> = [i32(0x5a82, 0x7999), i32(0x6ed9, 0xeba1), i32(0x8f1b, 0xbcdc), i32(0xca62, 0xc1d6)];

	public function new() {
	}

	public function toString() : String {
		return "sha1";
	}

	public function calculate( msg:Bytes ) : String {
		return HexUtil.bytesToHex(encode(msg));
	}

	public function calcBin( msg:Bytes ) : Bytes {
		return encode(msg);
	}

	public function getLengthBytes() : Int {
		return 20;
	}

	public function getLengthBits() : Int {
		return 160;
	}

	public function getBlockSizeBytes() : Int {
		return 64;
	}

	public function getBlockSizeBits() : Int {
		return 512;
	}

	/**
		Calculate the Sha1 for a string.
	**/
	public static function encode(msg : Bytes) : Bytes {
		//
		// function 'f' [§4.1.1]
		//
		var f = function(s, x: Int32, y: Int32, z: Int32)
		{
			switch (s) {
			case 0: return x.and(y).xor(x.complement().and(z));           // Ch()
			case 1: return x.xor(y).xor(z);                    // Parity()
			case 2: return x.and(y).xor(x.and(z)).xor(y.and(z));  // Maj()
			case 3: return x.xor(y).xor(z);                    // Parity()
			default: throw "err";
			}
			return Int32.ofInt(0);
		}

		//
		// rotate left (circular left shift) value x by n positions [§3.2.5]
		//
		var ROTL = function(x: Int32, n) {
			return x.shl(n).or(x.ushr(32-n));
		}

		//msg += BytesUtil.ofHex('0x80').toString(); // add trailing '1' bit to string [§5.1.1]
		var bb = new BytesBuffer();
		bb.add(msg);
		bb.addByte(0x80);
		msg = bb.getBytes();

		// convert string msg into 512-bit/16-integer blocks arrays of ints [§5.2.1]
		var l : Int = Math.ceil(msg.length/4) + 2;  // long enough to contain msg plus 2-word length
		var N : Int = Math.ceil(l/16);              // in N 16-int blocks
		var M : Array<Array<Int32>> = new Array();
		for(i in 0...N) {
			M[i] = new Array();
			for(j in 0...16) { // encode 4 chars per integer, big-endian encoding
				M[i][j] = ofInt(msg.get(i*64+j*4)).shl(24).or( ofInt(msg.get(i*64+j*4+1)).shl(16) ).or(
					ofInt(msg.get(i*64+j*4+2)).shl(8)).or(ofInt(msg.get(i*64+j*4+3)));
			}
		}

		// add length (in bits) into final pair of 32-bit integers (big-endian) [5.1.1]
		// note: most significant word would be ((len-1)*8 >>> 32, but since JS converts
		// bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
		M[N-1][14] = Int32.ofInt(Math.floor( ((msg.length-1)*8) / Math.pow(2, 32) ));
		//M[N-1][14] = Math.floor(M[N-1][14]);
		M[N-1][15] = Int32.ofInt(((msg.length-1)*8) & 0xffffffff);

		// set initial hash value [§5.3.1]
		var H0 = i32(0x6745, 0x2301);
		var H1 = i32(0xefcd, 0xab89);
		var H2 = i32(0x98ba, 0xdcfe);
		var H3 = i32(0x1032, 0x5476);
		var H4 = i32(0xc3d2, 0xe1f0);

		// HASH COMPUTATION [§6.1.2]
		var W = new Array<Int32>();
		var a, b, c, d, e;
		for(i in 0...N) {
			// 1 - prepare message schedule 'W'
			for(t in 0...16)
				W[t] = M[i][t];
			for(t in 16...80)
				W[t] = ROTL(W[t-3].xor(W[t-8]).xor(W[t-14]).xor(W[t-16]), 1);

			// 2 - initialise five working variables a, b, c, d, e with previous hash value
			a = H0; b = H1; c = H2; d = H3; e = H4;

			// 3 - main loop
			for(t in 0...80) {
				// seq for blocks of 'f' functions and 'K' constants
				var s = Math.floor(t/20);
				var T = (ROTL(a,5).add(f(s,b,c,d)).add(e).add(K[s]).add(W[t])).and(i32(0xffff, 0xffff));
				e = d;
				d = c;
				c = ROTL(b, 30);
				b = a;
				a = T;
			}

			// 4 - compute the new intermediate hash value
			H0 = (H0.add(a)).and(i32(0xffff, 0xffff));  // note 'addition modulo 2^32'
			H1 = (H1.add(b)).and(i32(0xffff, 0xffff));
			H2 = (H2.add(c)).and(i32(0xffff, 0xffff));
			H3 = (H3.add(d)).and(i32(0xffff, 0xffff));
			H4 = (H4.add(e)).and(i32(0xffff, 0xffff));
    	}

		bb = new BytesBuffer();
		bb.add(I32.encodeBE(H0));
		bb.add(I32.encodeBE(H1));
		bb.add(I32.encodeBE(H2));
		bb.add(I32.encodeBE(H3));
		bb.add(I32.encodeBE(H4));
		return bb.getBytes();
	}
	
	
	private static inline function i32(a: Int, b: Int)
	{
		return Int32.make(a, b);
	}
	
	private static inline function ofInt(i: Null<Int>)
	{
		return if ( i == null ) Int32.ofInt(0) else Int32.ofInt( i );
	}

}
