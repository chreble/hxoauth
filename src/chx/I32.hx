/*
 * Copyright (c) 2009, The Caffeine-hx project contributors
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

package chx;

import haxe.Int32;
import haxe.io.BytesBuffer;
import haxe.io.Bytes;

/**
* Static methods for cross platform use of 32 bit Int. All methods are inline,
* so there is no performance penalty.
*
* The Int32 typedef wraps either an I32 in neko, or Int on all other platforms.
* In general, do not define variables or functions typed as I32, use the
* Int32 typedef instead. This allows for native operations without having to
* call the I32 functions.
*
* @author		Russell Weir
**/
class I32 {
	public static var ZERO : Int32;
	public static var ONE : Int32;
	/** 0xFF **/
	public static var BYTE_MASK : Int32;

	/**
	* Returns byte 4 (highest byte) from the 32 bit int.
	* This is equivalent to v >>> 24 (which is the same as v >> 24 & 0xFF)
	*/
	public static inline function B4(v : Int32) : Int
	{
		return Int32.toInt(Int32.ushr(v,24));
	}

	/**
	* Returns byte 3 (second highest byte) from the 32 bit int.
	* This is equivalent to v >>> 16 & 0xFF
	*/
	public static inline function B3(v : Int32) : Int
	{
		return Int32.toInt(Int32.and(Int32.ushr(v,16), Int32.ofInt(0xFF)));
	}

	/**
	* Returns byte 2 (second lowest byte) from the 32 bit int.
	* This is equivalent to v >>> 8 & 0xFF
	*/
	public static inline function B2(v : Int32) : Int
	{
		return Int32.toInt(Int32.and(Int32.ushr(v,8), Int32.ofInt(0xFF)));
	}

	/**
	* Returns byte 1 (lowest byte) from the 32 bit int.
	* This is equivalent to v & 0xFF
	*/
	public static inline function B1(v : Int32) : Int
	{
		return Int32.toInt(Int32.and(v, Int32.ofInt(0xFF)));
	}

	/**
	* Encode an Int32 to a big endian string.
	**/
	public static function encodeBE(i : Int32) : Bytes
	{
		var sb = new BytesBuffer();
		sb.addByte( B4(i) );
		sb.addByte( B3(i) );
		sb.addByte( B2(i) );
		sb.addByte( B1(i) );
		return sb.getBytes();
	}

	/**
	* Encode an Int32 to a little endian string. Lowest byte is first in string so
	* 0xA0B0C0D0 encodes to [D0,C0,B0,A0]
	**/
	public static function encodeLE(i : Int32) : Bytes
	{
		var sb = new BytesBuffer();
		sb.addByte( B1(i) );
		sb.addByte( B2(i) );
		sb.addByte( B3(i) );
		sb.addByte( B4(i) );
		return sb.getBytes();
	}

	/**
	* Decode 4 big endian encoded bytes to a 32 bit integer.
	**/
	public static function decodeBE( s : Bytes, ?pos : Int ) : Int32
	{
		if(pos == null)
			pos = 0;
		var b0 = Int32.ofInt(s.get(pos+3));
		var b1 = Int32.ofInt(s.get(pos+2));
		var b2 = Int32.ofInt(s.get(pos+1));
		var b3 = Int32.ofInt(s.get(pos));
		b1 = Int32.shl(b1, 8);
		b2 = Int32.shl(b2, 16);
		b3 = Int32.shl(b3, 24);
		var a = Int32.add(b0, b1);
		a = Int32.add(a, b2);
		a = Int32.add(a, b3);
		return a;
	}

	/**
	* Decode 4 little endian encoded bytes to a 32 bit integer.
	**/
	public static function decodeLE( s : Bytes, ?pos : Int ) : Int32
	{
		if(pos == null)
			pos = 0;
		var b0 = Int32.ofInt(s.get(pos));
		var b1 = Int32.ofInt(s.get(pos+1));
		var b2 = Int32.ofInt(s.get(pos+2));
		var b3 = Int32.ofInt(s.get(pos+3));
		b1 = Int32.shl(b1, 8);
		b2 = Int32.shl(b2, 16);
		b3 = Int32.shl(b3, 24);
		var a = Int32.add(b0, b1);
		a = Int32.add(a, b2);
		a = Int32.add(a, b3);
		return a;
	}
	
	/**
	* Convert an array of 32bit integers to a big endian buffer.
	*
	* @param l Array of Int32 types
	* @return Bytes big endian encoded.
	**/
	public static function packBE(l : Array<Int32>) : Bytes
	{
		var sb = new BytesBuffer();
		for(i in 0...l.length) {
			sb.addByte( B4(l[i]) );
			sb.addByte( B3(l[i]) );
			sb.addByte( B2(l[i]) );
			sb.addByte( B1(l[i]) );
		}
		return sb.getBytes();
	}

	/**
	* Convert an array of 32bit integers to a little endian buffer.
	*
	* @param l Array of Int32 types
	* @return Bytes little endian encoded.
	**/
	public static function packLE(l : Array<Int32>) : Bytes
	{
		var sb = new BytesBuffer();
		for(i in 0...l.length) {
			sb.addByte( B1(l[i]) );
			sb.addByte( B2(l[i]) );
			sb.addByte( B3(l[i]) );
			sb.addByte( B4(l[i]) );
		}
		return sb.getBytes();
	}

	/**
	* On platforms where there is a native 32 bit int, this will
	* cast an Int32 array properly without overflows thrown.
	*
	* @throws String Overflow in neko only if 32 bits are required.
	**/
	public static inline function toNativeArray(v : Array<Int32>) : Array<Int> {
		#if neko
			var a = new Array<Int>();
			for(i in v)
				a.push(Int32.toInt(i));
			return a;
		#else
			return cast v;
		#end
	}

	/**
	* Convert a buffer containing 32bit integers to an array of ints.
	* If the buffer length is not a multiple of 4, an exception is thrown
	**/
	public static function unpackLE(s : Bytes) : Array<Int32>
	{
		if(s == null || s.length == 0)
			return new Array();
		if(s.length % 4 != 0)
			throw "Buffer not multiple of 4 bytes";

		var a = new Array<Int32>();
		var pos = 0;
		var i = 0;
		var len = s.length;
		while(pos < len) {
			a[i] = decodeLE( s, pos );
			pos += 4;
			i++;
		}
		return a;
	}

	/**
	* Convert a buffer containing 32bit integers to an array of ints.
	* If the buffer length is not a multiple of 4, an exception is thrown
	**/
	public static function unpackBE(s : Bytes) : Array<Int32>
	{
		if(s == null || s.length == 0)
			return new Array();
		if(s.length % 4 != 0)
			throw "Buffer not multiple of 4 bytes";

		var a = new Array();
		var pos = 0;
		var i = 0;
		while(pos < s.length) {
			a[i] = decodeBE( s, pos );
			pos += 4;
			i++;
		}
		return a;
	}

}
