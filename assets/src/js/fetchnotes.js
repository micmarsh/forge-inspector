/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  SHA-1 implementation in JavaScript | (c) Chris Veness 2002-2010 | www.movable-type.co.uk      */
/*   - see http://csrc.nist.gov/groups/ST/toolkit/secure_hashing.html                             */
/*         http://csrc.nist.gov/groups/ST/toolkit/examples.html                                   */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

var Sha1 = {};  // Sha1 namespace

/**
 * Generates SHA-1 hash of string
 *
 * @param {String} msg                String to be hashed
 * @param {Boolean} [utf8encode=true] Encode msg as UTF-8 before generating hash
 * @returns {String}                  Hash of msg as hex character string
 */
Sha1.hash = function(msg, utf8encode) {
  utf8encode =  (typeof utf8encode == 'undefined') ? true : utf8encode;

  // convert string to UTF-8, as SHA only deals with byte-streams
  if (utf8encode) msg = Utf8.encode(msg);

  // constants [§4.2.1]
  var K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

  // PREPROCESSING

  msg += String.fromCharCode(0x80);  // add trailing '1' bit (+ 0's padding) to string [§5.1.1]

  // convert string msg into 512-bit/16-integer blocks arrays of ints [§5.2.1]
  var l = msg.length/4 + 2;  // length (in 32-bit integers) of msg + ‘1’ + appended length
  var N = Math.ceil(l/16);   // number of 16-integer-blocks required to hold 'l' ints
  var M = new Array(N);

  for (var i=0; i<N; i++) {
    M[i] = new Array(16);
    for (var j=0; j<16; j++) {  // encode 4 chars per integer, big-endian encoding
      M[i][j] = (msg.charCodeAt(i*64+j*4)<<24) | (msg.charCodeAt(i*64+j*4+1)<<16) |
        (msg.charCodeAt(i*64+j*4+2)<<8) | (msg.charCodeAt(i*64+j*4+3));
    } // note running off the end of msg is ok 'cos bitwise ops on NaN return 0
  }
  // add length (in bits) into final pair of 32-bit integers (big-endian) [§5.1.1]
  // note: most significant word would be (len-1)*8 >>> 32, but since JS converts
  // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
  M[N-1][14] = ((msg.length-1)*8) / Math.pow(2, 32); M[N-1][14] = Math.floor(M[N-1][14])
  M[N-1][15] = ((msg.length-1)*8) & 0xffffffff;

  // set initial hash value [§5.3.1]
  var H0 = 0x67452301;
  var H1 = 0xefcdab89;
  var H2 = 0x98badcfe;
  var H3 = 0x10325476;
  var H4 = 0xc3d2e1f0;

  // HASH COMPUTATION [§6.1.2]

  var W = new Array(80); var a, b, c, d, e;
  for (var i=0; i<N; i++) {

    // 1 - prepare message schedule 'W'
    for (var t=0;  t<16; t++) W[t] = M[i][t];
    for (var t=16; t<80; t++) W[t] = Sha1.ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);

    // 2 - initialise five working variables a, b, c, d, e with previous hash value
    a = H0; b = H1; c = H2; d = H3; e = H4;

    // 3 - main loop
    for (var t=0; t<80; t++) {
      var s = Math.floor(t/20); // seq for blocks of 'f' functions and 'K' constants
      var T = (Sha1.ROTL(a,5) + Sha1.f(s,b,c,d) + e + K[s] + W[t]) & 0xffffffff;
      e = d;
      d = c;
      c = Sha1.ROTL(b, 30);
      b = a;
      a = T;
    }

    // 4 - compute the new intermediate hash value
    H0 = (H0+a) & 0xffffffff;  // note 'addition modulo 2^32'
    H1 = (H1+b) & 0xffffffff;
    H2 = (H2+c) & 0xffffffff;
    H3 = (H3+d) & 0xffffffff;
    H4 = (H4+e) & 0xffffffff;
  }

  return Sha1.toHexStr(H0) + Sha1.toHexStr(H1) +
    Sha1.toHexStr(H2) + Sha1.toHexStr(H3) + Sha1.toHexStr(H4);
}

//
// function 'f' [§4.1.1]
//
Sha1.f = function(s, x, y, z)  {
  switch (s) {
  case 0: return (x & y) ^ (~x & z);           // Ch()
  case 1: return x ^ y ^ z;                    // Parity()
  case 2: return (x & y) ^ (x & z) ^ (y & z);  // Maj()
  case 3: return x ^ y ^ z;                    // Parity()
  }
}

//
// rotate left (circular left shift) value x by n positions [§3.2.5]
//
Sha1.ROTL = function(x, n) {
  return (x<<n) | (x>>>(32-n));
}

//
// hexadecimal representation of a number
//   (note toString(16) is implementation-dependant, and
//   in IE returns signed numbers when used on full words)
//
Sha1.toHexStr = function(n) {
  var s="", v;
  for (var i=7; i>=0; i--) { v = (n>>>(i*4)) & 0xf; s += v.toString(16); }
  return s;
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  Utf8 class: encode / decode between multi-byte Unicode characters and UTF-8 multiple          */
/*              single-byte character encoding (c) Chris Veness 2002-2010                         */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

var Utf8 = {};  // Utf8 namespace

/**
 * Encode multi-byte Unicode string into utf-8 multiple single-byte characters
 * (BMP / basic multilingual plane only)
 *
 * Chars in range U+0080 - U+07FF are encoded in 2 chars, U+0800 - U+FFFF in 3 chars
 *
 * @param {String} strUni Unicode string to be encoded as UTF-8
 * @returns {String} encoded string
 */
Utf8.encode = function(strUni) {
  // use regular expressions & String.replace callback function for better efficiency
  // than procedural approaches
  var strUtf = strUni.replace(
      /[\u0080-\u07ff]/g,  // U+0080 - U+07FF => 2 bytes 110yyyyy, 10zzzzzz
      function(c) {
        var cc = c.charCodeAt(0);
        return String.fromCharCode(0xc0 | cc>>6, 0x80 | cc&0x3f); }
    );
  strUtf = strUtf.replace(
      /[\u0800-\uffff]/g,  // U+0800 - U+FFFF => 3 bytes 1110xxxx, 10yyyyyy, 10zzzzzz
      function(c) {
        var cc = c.charCodeAt(0);
        return String.fromCharCode(0xe0 | cc>>12, 0x80 | cc>>6&0x3F, 0x80 | cc&0x3f); }
    );
  return strUtf;
}

/**
 * Decode utf-8 encoded string back into multi-byte Unicode characters
 *
 * @param {String} strUtf UTF-8 string to be decoded back to Unicode
 * @returns {String} decoded string
 */
Utf8.decode = function(strUtf) {
  // note: decode 3-byte chars first as decoded 2-byte strings could appear to be 3-byte char!
  var strUni = strUtf.replace(
      /[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,  // 3-byte chars
      function(c) {  // (note parentheses for precence)
        var cc = ((c.charCodeAt(0)&0x0f)<<12) | ((c.charCodeAt(1)&0x3f)<<6) | ( c.charCodeAt(2)&0x3f);
        return String.fromCharCode(cc); }
    );
  strUni = strUni.replace(
      /[\u00c0-\u00df][\u0080-\u00bf]/g,                 // 2-byte chars
      function(c) {  // (note parentheses for precence)
        var cc = (c.charCodeAt(0)&0x1f)<<6 | c.charCodeAt(1)&0x3f;
        return String.fromCharCode(cc); }
    );
  return strUni;
}
/* A JavaScript implementation of the Secure Hash Standard
 * Version 0.3 Copyright Angel Marin 2003-2004 - http://anmar.eu.org/
 * Distributed under the BSD License
 * Some bits taken from Paul Johnston's SHA-1 implementation
 */
var chrsz   = 8;   /* bits per input character. 8 - ASCII; 16 - Unicode      */
var hexcase = 0;    /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = "=";  /* base-64 pad character. "=" for strict RFC compliance   */

function safe_add (x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

function S (X, n) {return ( X >>> n ) | (X << (32 - n));}

function R (X, n) {return ( X >>> n );}

function Ch(x, y, z) {return ((x & y) ^ ((~x) & z));}

function Maj(x, y, z) {return ((x & y) ^ (x & z) ^ (y & z));}

function Sigma0256(x) {return (S(x, 2) ^ S(x, 13) ^ S(x, 22));}

function Sigma1256(x) {return (S(x, 6) ^ S(x, 11) ^ S(x, 25));}

function Gamma0256(x) {return (S(x, 7) ^ S(x, 18) ^ R(x, 3));}

function Gamma1256(x) {return (S(x, 17) ^ S(x, 19) ^ R(x, 10));}

function Sigma0512(x) {return (S(x, 28) ^ S(x, 34) ^ S(x, 39));}

function Sigma1512(x) {return (S(x, 14) ^ S(x, 18) ^ S(x, 41));}

function Gamma0512(x) {return (S(x, 1) ^ S(x, 8) ^ R(x, 7));}

function Gamma1512(x) {return (S(x, 19) ^ S(x, 61) ^ R(x, 6));}

function core_sha256 (m, l) {
    var K = new Array(0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0xFC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x6CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2);
    var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
    var W = new Array(64);
    var a, b, c, d, e, f, g, h, i, j;
    var T1, T2;

    /* append padding */
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >> 9) << 4) + 15] = l;

    for ( var i = 0; i<m.length; i+=16 ) {
        a = HASH[0];
        b = HASH[1];
        c = HASH[2];
        d = HASH[3];
        e = HASH[4];
        f = HASH[5];
        g = HASH[6];
        h = HASH[7];

        for ( var j = 0; j<64; j++) {
            if (j < 16) W[j] = m[j + i];
            else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);

            T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
            T2 = safe_add(Sigma0256(a), Maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = safe_add(d, T1);
            d = c;
            c = b;
            b = a;
            a = safe_add(T1, T2);
        }
        
        HASH[0] = safe_add(a, HASH[0]);
        HASH[1] = safe_add(b, HASH[1]);
        HASH[2] = safe_add(c, HASH[2]);
        HASH[3] = safe_add(d, HASH[3]);
        HASH[4] = safe_add(e, HASH[4]);
        HASH[5] = safe_add(f, HASH[5]);
        HASH[6] = safe_add(g, HASH[6]);
        HASH[7] = safe_add(h, HASH[7]);
    }
    return HASH;
}

function core_sha512 (m, l) {
    var K = new Array(0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817);
    var HASH = new Array(0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179);
    var W = new Array(80);
    var a, b, c, d, e, f, g, h, i, j;
    var T1, T2;

}

function str2binb (str) {
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
  return bin;
}

function binb2str (bin) {
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (24 - i%32)) & mask);
  return str;
}

function binb2hex (binarray) {
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
  }
  return str;
}

function binb2b64 (binarray) {
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}

function hex_sha256(s){return binb2hex(core_sha256(str2binb(s),s.length * chrsz));}
function b64_sha256(s){return binb2b64(core_sha256(str2binb(s),s.length * chrsz));}
function str_sha256(s){return binb2str(core_sha256(str2binb(s),s.length * chrsz));}
(function(p){"function"==typeof define?define(p):"function"==typeof YUI?YUI.add("es5",p):p()})(function(){function p(a){a=+a;a!==a?a=0:0!==a&&(a!==1/0&&a!==-(1/0))&&(a=(0<a||-1)*Math.floor(Math.abs(a)));return a}function s(a){var b=typeof a;return null===a||"undefined"===b||"boolean"===b||"number"===b||"string"===b}Function.prototype.bind||(Function.prototype.bind=function(a){var b=this;if("function"!=typeof b)throw new TypeError("Function.prototype.bind called on incompatible "+b);var d=q.call(arguments,
1),c=function(){if(this instanceof c){var e=b.apply(this,d.concat(q.call(arguments)));return Object(e)===e?e:this}return b.apply(a,d.concat(q.call(arguments)))};b.prototype&&(c.prototype=Object.create(b.prototype));return c});var k=Function.prototype.call,o=Object.prototype,q=Array.prototype.slice,h=k.bind(o.toString),t=k.bind(o.hasOwnProperty);t(o,"__defineGetter__")&&(k.bind(o.__defineGetter__),k.bind(o.__defineSetter__),k.bind(o.__lookupGetter__),k.bind(o.__lookupSetter__));if(2!=[1,2].splice(0).length){var x=
Array.prototype.splice;Array.prototype.splice=function(a,b){return arguments.length?x.apply(this,[a===void 0?0:a,b===void 0?this.length-a:b].concat(q.call(arguments,2))):[]}}if(1!=[].unshift(0)){var y=Array.prototype.unshift;Array.prototype.unshift=function(){y.apply(this,arguments);return this.length}}Array.isArray||(Array.isArray=function(a){return h(a)=="[object Array]"});var k=Object("a"),l="a"!=k[0]||!(0 in k);Array.prototype.forEach||(Array.prototype.forEach=function(a,b){var d=n(this),c=l&&
h(this)=="[object String]"?this.split(""):d,e=-1,f=c.length>>>0;if(h(a)!="[object Function]")throw new TypeError;for(;++e<f;)e in c&&a.call(b,c[e],e,d)});Array.prototype.map||(Array.prototype.map=function(a,b){var d=n(this),c=l&&h(this)=="[object String]"?this.split(""):d,e=c.length>>>0,f=Array(e);if(h(a)!="[object Function]")throw new TypeError(a+" is not a function");for(var g=0;g<e;g++)g in c&&(f[g]=a.call(b,c[g],g,d));return f});Array.prototype.filter||(Array.prototype.filter=function(a,b){var d=
n(this),c=l&&h(this)=="[object String]"?this.split(""):d,e=c.length>>>0,f=[],g;if(h(a)!="[object Function]")throw new TypeError(a+" is not a function");for(var i=0;i<e;i++)if(i in c){g=c[i];a.call(b,g,i,d)&&f.push(g)}return f});Array.prototype.every||(Array.prototype.every=function(a,b){var d=n(this),c=l&&h(this)=="[object String]"?this.split(""):d,e=c.length>>>0;if(h(a)!="[object Function]")throw new TypeError(a+" is not a function");for(var f=0;f<e;f++)if(f in c&&!a.call(b,c[f],f,d))return false;
return true});Array.prototype.some||(Array.prototype.some=function(a,b){var d=n(this),c=l&&h(this)=="[object String]"?this.split(""):d,e=c.length>>>0;if(h(a)!="[object Function]")throw new TypeError(a+" is not a function");for(var f=0;f<e;f++)if(f in c&&a.call(b,c[f],f,d))return true;return false});Array.prototype.reduce||(Array.prototype.reduce=function(a){var b=n(this),d=l&&h(this)=="[object String]"?this.split(""):b,c=d.length>>>0;if(h(a)!="[object Function]")throw new TypeError(a+" is not a function");
if(!c&&arguments.length==1)throw new TypeError("reduce of empty array with no initial value");var e=0,f;if(arguments.length>=2)f=arguments[1];else{do{if(e in d){f=d[e++];break}if(++e>=c)throw new TypeError("reduce of empty array with no initial value");}while(1)}for(;e<c;e++)e in d&&(f=a.call(void 0,f,d[e],e,b));return f});Array.prototype.reduceRight||(Array.prototype.reduceRight=function(a){var b=n(this),d=l&&h(this)=="[object String]"?this.split(""):b,c=d.length>>>0;if(h(a)!="[object Function]")throw new TypeError(a+
" is not a function");if(!c&&arguments.length==1)throw new TypeError("reduceRight of empty array with no initial value");var e,c=c-1;if(arguments.length>=2)e=arguments[1];else{do{if(c in d){e=d[c--];break}if(--c<0)throw new TypeError("reduceRight of empty array with no initial value");}while(1)}do c in this&&(e=a.call(void 0,e,d[c],c,b));while(c--);return e});if(!Array.prototype.indexOf||-1!=[0,1].indexOf(1,2))Array.prototype.indexOf=function(a){var b=l&&h(this)=="[object String]"?this.split(""):
n(this),d=b.length>>>0;if(!d)return-1;var c=0;arguments.length>1&&(c=p(arguments[1]));for(c=c>=0?c:Math.max(0,d+c);c<d;c++)if(c in b&&b[c]===a)return c;return-1};if(!Array.prototype.lastIndexOf||-1!=[0,1].lastIndexOf(0,-3))Array.prototype.lastIndexOf=function(a){var b=l&&h(this)=="[object String]"?this.split(""):n(this),d=b.length>>>0;if(!d)return-1;var c=d-1;arguments.length>1&&(c=Math.min(c,p(arguments[1])));for(c=c>=0?c:d-Math.abs(c);c>=0;c--)if(c in b&&a===b[c])return c;return-1};if(!Object.keys){var v=
!0,w="toString toLocaleString valueOf hasOwnProperty isPrototypeOf propertyIsEnumerable constructor".split(" "),z=w.length,r;for(r in{toString:null})v=!1;Object.keys=function(a){if(typeof a!="object"&&typeof a!="function"||a===null)throw new TypeError("Object.keys called on a non-object");var b=[],d;for(d in a)t(a,d)&&b.push(d);if(v)for(d=0;d<z;d++){var c=w[d];t(a,c)&&b.push(c)}return b}}if(!Date.prototype.toISOString||-1===(new Date(-621987552E5)).toISOString().indexOf("-000001"))Date.prototype.toISOString=
function(){var a,b,d,c;if(!isFinite(this))throw new RangeError("Date.prototype.toISOString called on non-finite value.");c=this.getUTCFullYear();a=this.getUTCMonth();c=c+Math.floor(a/12);a=[(a%12+12)%12+1,this.getUTCDate(),this.getUTCHours(),this.getUTCMinutes(),this.getUTCSeconds()];c=(c<0?"-":c>9999?"+":"")+("00000"+Math.abs(c)).slice(0<=c&&c<=9999?-4:-6);for(b=a.length;b--;){d=a[b];d<10&&(a[b]="0"+d)}return c+"-"+a.slice(0,2).join("-")+"T"+a.slice(2).join(":")+"."+("000"+this.getUTCMilliseconds()).slice(-3)+
"Z"};r=!1;try{r=Date.prototype.toJSON&&null===(new Date(NaN)).toJSON()&&-1!==(new Date(-621987552E5)).toJSON().indexOf("-000001")&&Date.prototype.toJSON.call({toISOString:function(){return true}})}catch(G){}r||(Date.prototype.toJSON=function(){var a=Object(this),b;a:if(s(a))b=a;else{b=a.valueOf;if(typeof b==="function"){b=b.call(a);if(s(b))break a}b=a.toString;if(typeof b==="function"){b=b.call(a);if(s(b))break a}throw new TypeError;}if(typeof b==="number"&&!isFinite(b))return null;b=a.toISOString;
if(typeof b!="function")throw new TypeError("toISOString property is not callable");return b.call(a)});var g=Date,m=function(a,b,d,c,e,f,h){var i=arguments.length;if(this instanceof g){i=i==1&&String(a)===a?new g(m.parse(a)):i>=7?new g(a,b,d,c,e,f,h):i>=6?new g(a,b,d,c,e,f):i>=5?new g(a,b,d,c,e):i>=4?new g(a,b,d,c):i>=3?new g(a,b,d):i>=2?new g(a,b):i>=1?new g(a):new g;i.constructor=m;return i}return g.apply(this,arguments)},u=function(a,b){var d=b>1?1:0;return A[b]+Math.floor((a-1969+d)/4)-Math.floor((a-
1901+d)/100)+Math.floor((a-1601+d)/400)+365*(a-1970)},B=RegExp("^(\\d{4}|[+-]\\d{6})(?:-(\\d{2})(?:-(\\d{2})(?:T(\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.(\\d{3}))?)?(Z|(?:([-+])(\\d{2}):(\\d{2})))?)?)?)?$"),A=[0,31,59,90,120,151,181,212,243,273,304,334,365],j;for(j in g)m[j]=g[j];m.now=g.now;m.UTC=g.UTC;m.prototype=g.prototype;m.prototype.constructor=m;m.parse=function(a){var b=B.exec(a);if(b){var d=Number(b[1]),c=Number(b[2]||1)-1,e=Number(b[3]||1)-1,f=Number(b[4]||0),h=Number(b[5]||0),i=Number(b[6]||
0),j=Number(b[7]||0),m=!b[4]||b[8]?0:Number(new g(1970,0)),k=b[9]==="-"?1:-1,l=Number(b[10]||0),b=Number(b[11]||0);if(f<(h>0||i>0||j>0?24:25)&&h<60&&i<60&&j<1E3&&c>-1&&c<12&&l<24&&b<60&&e>-1&&e<u(d,c+1)-u(d,c)){d=((u(d,c)+e)*24+f+l*k)*60;d=((d+h+b*k)*60+i)*1E3+j+m;if(-864E13<=d&&d<=864E13)return d}return NaN}return g.parse.apply(this,arguments)};Date=m;Date.now||(Date.now=function(){return(new Date).getTime()});if("0".split(void 0,0).length){var C=String.prototype.split;String.prototype.split=function(a,
b){return a===void 0&&b===0?[]:C.apply(this,arguments)}}if("".substr&&"b"!=="0b".substr(-1)){var D=String.prototype.substr;String.prototype.substr=function(a,b){return D.call(this,a<0?(a=this.length+a)<0?0:a:a,b)}}j="\t\n\x0B\f\r \u00a0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029\ufeff";if(!String.prototype.trim||j.trim()){j="["+j+"]";var E=RegExp("^"+j+j+"*"),F=RegExp(j+j+"*$");String.prototype.trim=function(){if(this===void 0||this===
null)throw new TypeError("can't convert "+this+" to object");return String(this).replace(E,"").replace(F,"")}}var n=function(a){if(a==null)throw new TypeError("can't convert "+a+" to object");return Object(a)}});
/*!
 * Copyright (c) 2013 Kinvey, Inc. All rights reserved.
 *
 * Licensed to Kinvey, Inc. under one or more contributor
 * license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership.  Kinvey, Inc. licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
(function(undefined) {

  // Save reference to global object (window in browser, global on server).
  var root = this;

  /**
   * Top-level namespace. Exported for browser and CommonJS.
   *
   * @name Kinvey
   * @namespace
   */
  var Kinvey;
  if('undefined' !== typeof exports) {
    Kinvey = exports;
  }
  else {
    Kinvey = root.Kinvey = {};
  }

  // Define a base class for all Kinvey classes. Provides a property method for
  // class inheritance. This method is available to all child definitions.
  var Base = Object.defineProperty(function() { }, 'extend', {
    value: function(prototype, properties) {
      // Create class definition
      var constructor = prototype && prototype.hasOwnProperty('constructor') ? prototype.constructor : this;
      var def = function() {
        constructor.apply(this, arguments);
      };

      // Set prototype by merging child prototype into parents.
      def.prototype = (function(parent, child) {
        Object.getOwnPropertyNames(child).forEach(function(property) {
          Object.defineProperty(parent, property, Object.getOwnPropertyDescriptor(child, property));
        });
        return parent;
      }(Object.create(this.prototype), prototype || {}));

      // Set static properties.
      if(properties) {
        for(var prop in properties) {
          if(properties.hasOwnProperty(prop)) {
            def[prop] = properties[prop];
          }
        }
      }

      // Add extend to definition.
      Object.defineProperty(def, 'extend', Object.getOwnPropertyDescriptor(this, 'extend'));

      // Return definition.
      return def;
    }
  });

  // Convenient method for binding context to anonymous functions.
  var bind = function(thisArg, fn) {
    fn || (fn = function() { });
    return fn.bind ? fn.bind(thisArg) : function() {
      return fn.apply(thisArg, arguments);
    };
  };

  // Merges multiple source objects into one newly created object.
  var merge = function(/*sources*/) {
    var target = {};
    Array.prototype.slice.call(arguments, 0).forEach(function(source) {
      for(var prop in source) {
        target[prop] = source[prop];
      }
    });
    return target;
  };

  // Define the Storage class. Simple wrapper around the localStorage interface.
  var Storage = {
    get: function(key) {
      var value = localStorage.getItem(key);
      return value ? JSON.parse(value) : null;
    },
    set: function(key, value) {
      localStorage.setItem(key, JSON.stringify(value));
    },
    remove: function(key) {
      localStorage.removeItem(key);
    }
  };

  /*globals btoa*/

  // Not all browsers support the timeout natively yet.
  var supportsTimeout = XMLHttpRequest.prototype.hasOwnProperty('timeout');

  // Define the Xhr mixin.
  var Xhr = (function() {
    /**
     * Base 64 encodes string.
     *
     * @private
     * @param {string} value
     * @return {string} Encoded string.
     */
    var base64 = function(value) {
      return btoa(value);
    };

    /**
     * Returns authorization string.
     *
     * @private
     * @param {boolean} forceAppc Force use of application credentials.
     * @return {Object} Authorization.
     */
    var getAuth = function(forceAppc) {
      // Use master secret if specified.
      if(null != Kinvey.masterSecret) {// undefined or null
        return 'Basic ' + this._base64(Kinvey.appKey + ':' + Kinvey.masterSecret);
      }

      // Use Session Auth if there is a current user, and application credentials
      // are not forced.
      var user = Kinvey.getCurrentUser();
      if(!forceAppc && null !== user) {
        return 'Kinvey ' + user.getToken();
      }

      // Use application credentials as last resort.
      return 'Basic ' + this._base64(Kinvey.appKey + ':' + Kinvey.appSecret);
    };

    /**
     * Returns device information.
     *
     * @private
     * @return {string} Device information.
     */
    var getDeviceInfo = function() {
      // Try the most common browsers, fall back to navigator.appName otherwise.
      var ua = navigator.userAgent.toLowerCase();

      var rChrome = /(chrome)\/([\w]+)/;
      var rSafari = /(safari)\/([\w.]+)/;
      var rFirefox = /(firefox)\/([\w.]+)/;
      var rOpera = /(opera)(?:.*version)?[ \/]([\w.]+)/;
      var rIE = /(msie) ([\w.]+)/i;

      var browser = rChrome.exec(ua) || rSafari.exec(ua) || rFirefox.exec(ua) || rOpera.exec(ua) || rIE.exec(ua) || [ ];

      // Build device information.
      // Example: "js/0.9.14 linux-chrome 18 0".
      return [
        (window.cordova ? 'js-phonegap' : 'js') + '/0.9.14',
        navigator.platform + '-' + (browser[1] || navigator.appName),
        browser[2] || 0,
        0 // always set device ID to 0.
      ].map(function(value) {
        return value.toString().toLowerCase().replace(' ', '_');
      }).join(' ');
    };

    /**
     * Sends a request against Kinvey.
     *
     * @private
     * @param {string} method Request method.
     * @param {string} url Request URL.
     * @param {string} body Request body.
     * @param {Object} options
     * @param {integer} [options.timeout] Request timeout (ms).
     * @param {function(response, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    var send = function(method, url, body, options) {
      options || (options = {});
      'undefined' !== typeof options.timeout || (options.timeout = this.options.timeout);
      options.success || (options.success = this.options.success);
      options.error || (options.error = this.options.error);

      // For now, include authorization in this adapter. Ideally, it should
      // have some external interface.
      if(null === Kinvey.getCurrentUser() && Kinvey.Store.AppData.USER_API !== this.api && null == Kinvey.masterSecret && !options.appc) {
        return Kinvey.User.create({}, merge(options, {
          success: bind(this, function() {
            this._send(method, url, body, options);
          })
        }));
      }

      // Add host to URL.
      url = Kinvey.HOST + url;

      // Headers.
      var headers = {
        Accept: 'application/json, text/javascript',
        Authorization: this._getAuth(options.appc),
        'X-Kinvey-API-Version': Kinvey.API_VERSION,
        'X-Kinvey-Device-Information': this._getDeviceInfo()
      };
      body && (headers['Content-Type'] = 'application/json; charset=utf-8');

      // Add header for compatibility with Android 2.2, 2.3.3 and 3.2.
      // @link http://www.kinvey.com/blog/item/179-how-to-build-a-service-that-supports-every-android-browser
      if('GET' === method && 'undefined' !== typeof window && window.location) {
        headers['X-Kinvey-Origin'] = window.location.protocol + '//' + window.location.host;
      }

      // Execute request.
      this._xhr(method, url, body, merge(options, {
        headers: headers,
        success: function(response, info) {
          // Response is expected to be either empty, or valid JSON.
          response = response ? JSON.parse(response) : null;
          options.success(response, info);
        },
        error: function(response, info) {
          // Response could be valid JSON if the error occurred at Kinvey.
          try {
            response = JSON.parse(response);
          }
          catch(_) {// Or just the error type if something else went wrong.
            var error = {
              abort: 'The request was aborted',
              error: 'The request failed',
              timeout: 'The request timed out'
            };

            // Execute application-level handler.
            response = {
              error: Kinvey.Error.REQUEST_FAILED,
              description: error[response] || error.error,
              debug: ''
            };
          }

          // Return.
          options.error(response, info);
        }
      }));
    };

    /**
     * Sends a request.
     *
     * @private
     * @param {string} method Request method.
     * @param {string} url Request URL.
     * @param {string} body Request body.
     * @param {Object} options
     * @param {Object} [options.headers] Request headers.
     * @param {integer} [options.timeout] Request timeout (ms).
     * @param {function(status, response)} [options.success] Success callback.
     * @param {function(type)} [options.error] Failure callback.
     */
    var xhr = function(method, url, body, options) {
      options || (options = {});
      options.headers || (options.headers = {});
      'undefined' !== typeof options.timeout || (options.timeout = this.options.timeout);
      options.success || (options.success = this.options.success);
      options.error || (options.error = this.options.error);

      // Create request.
      var request = new XMLHttpRequest();
      request.open(method, url);
      request.timeout = options.timeout;

      // Pass headers to request.
      for(var name in options.headers) {
        if(options.headers.hasOwnProperty(name)) {
          request.setRequestHeader(name, options.headers[name]);
        }
      }

      // Handle response when it completes.
      request.onload = function() {
        // Success implicates status 2xx (Successful), or 304 (Not Modified).
        request.timer && clearTimeout(request.timer);// Stop timer.
        if(2 === parseInt(this.status / 100, 10) || 304 === this.status) {
          options.success(this.responseText, { network: true });
        }
        else {
          options.error(this.responseText, { network: true });
        }
      };

      // Define request error handler.
      request.onabort = request.onerror = request.ontimeout = function(event) {
        // request.eventType is populated on patched timeout.
        request.timer && clearTimeout(request.timer);// Stop timer.
        options.error(request.eventType || event.type, { network: true });
      };

      // Fire request.
      request.send(body);

      // Patch timeout if not supported natively.
      if(!supportsTimeout && 'function' === typeof setTimeout && 'function' === typeof clearTimeout) {
        request.timer = setTimeout(function() {
          // Abort the request, and set event to timeout explicitly.
          request.eventType = 'timeout';
          request.abort();
        }, request.timeout);
      }
    };

    // Attach to context.
    return function() {
      this._base64 = base64;
      this._getAuth = getAuth;
      this._getDeviceInfo = getDeviceInfo;
      this._send = send;
      this._xhr = xhr;
      return this;
    };
  }());

  // Current user.
  var currentUser = null;

  /**
   * API version.
   *
   * @constant
   */
  Kinvey.API_VERSION = 2;

  /**
   * Host.
   *
   * @constant
   */
  Kinvey.HOST = 'https://baas.kinvey.com';

  /**
   * SDK version.
   *
   * @constant
   */
  Kinvey.SDK_VERSION = '0.9.14';

  /**
   * Returns current user, or null if not set.
   *
   * @return {Kinvey.User} Current user.
   */
  Kinvey.getCurrentUser = function() {
    return currentUser;
  };

  /**
   * Initializes library for use with Kinvey services. Never use the master
   * secret in client-side code.
   *
   * @example <code>
   * Kinvey.init({
   *   appKey: 'your-app-key',
   *   appSecret: 'your-app-secret'
   * });
   * </code>
   *
   * @param {Object} options Kinvey credentials. Object expects properties:
   *          "appKey", and "appSecret" or "masterSecret". Optional: "sync".
   * @throws {Error}
   *           <ul>
   *           <li>On empty appKey,</li>
   *           <li>On empty appSecret and masterSecret.</li>
   *           </ul>
   */
  Kinvey.init = function(options) {
    options || (options = {});
    if(null == options.appKey) {
      throw new Error('appKey must be defined');
    }
    if(null == options.appSecret && null == options.masterSecret) {
      throw new Error('appSecret or masterSecret must be defined');
    }

    // Store credentials.
    Kinvey.appKey = options.appKey;
    Kinvey.appSecret = options.appSecret || null;
    Kinvey.masterSecret = options.masterSecret || null;

    // Restore current user.
    Kinvey.User._restore();

    // Synchronize app in the background.
    options.sync && Kinvey.Sync && Kinvey.Sync.application();
  };

  /**
   * Round trips a request to the server and back, helps ensure connectivity.
   *
   * @example <code>
   * Kinvey.ping({
   *   success: function(response) {
   *     console.log('Ping successful', response.kinvey, response.version);
   *   },
   *   error: function(error) {
   *     console.log('Ping failed', error.message);
   *   }
   * });
   * </code>
   *
   * @param {Object} [options]
   * @param {function(response, info)} [options.success] Success callback.
   * @param {function(error, info)} [options.error] Failure callback.
   */
  Kinvey.ping = function(options) {
    // Ping always targets the Kinvey backend.
    new Kinvey.Store.AppData(null).query(null, options);
  };

  /**
   * Sets the current user. This method is only used by the Kinvey.User
   * namespace.
   *
   * @private
   * @param {Kinvey.User} user Current user.
   */
  Kinvey.setCurrentUser = function(user) {
    currentUser = user;
  };

  /**
   * Kinvey Error namespace definition. Holds all possible errors.
   *
   * @namespace
   */
  Kinvey.Error = {
    // Client-side.
    /** @constant */
    DATABASE_ERROR: 'DatabaseError',

    /** @constant */
    NO_NETWORK: 'NoNetwork',

    /** @constant */
    REQUEST_FAILED: 'RequestFailed',

    /** @constant */
    RESPONSE_PROBLEM: 'ResponseProblem',

    // Server-side.
    /** @constant */
    ENTITY_NOT_FOUND: 'EntityNotFound',

    /** @constant */
    COLLECTION_NOT_FOUND: 'CollectionNotFound',

    /** @constant */
    APP_NOT_FOUND: 'AppNotFound',

    /** @constant */
    USER_NOT_FOUND: 'UserNotFound',

    /** @constant */
    BLOB_NOT_FOUND: 'BlobNotFound',

    /** @constant */
    INVALID_CREDENTIALS: 'InvalidCredentials',

    /** @constant */
    KINVEY_INTERNAL_ERROR_RETRY: 'KinveyInternalErrorRetry',

    /** @constant */
    KINVEY_INTERNAL_ERROR_STOP: 'KinveyInternalErrorStop',

    /** @constant */
    USER_ALREADY_EXISTS: 'UserAlreadyExists',

    /** @constant */
    DUPLICATE_END_USERS: 'DuplicateEndUsers',

    /** @constant */
    INSUFFICIENT_CREDENTIALS: 'InsufficientCredentials',

    /** @constant */
    WRITES_TO_COLLECTION_DISALLOWED: 'WritesToCollectionDisallowed',

    /** @constant */
    INDIRECT_COLLECTION_ACCESS_DISALLOWED : 'IndirectCollectionAccessDisallowed',

    /** @constant */
    APP_PROBLEM: 'AppProblem',

    /** @constant */
    PARAMETER_VALUE_OUT_OF_RANGE: 'ParameterValueOutOfRange',

    /** @constant */
    CORS_DISABLED: 'CORSDisabled',

    /** @constant */
    INVALID_QUERY_SYNTAX: 'InvalidQuerySyntax',

    /** @constant */
    MISSING_QUERY: 'MissingQuery',

    /** @constant */
    JSON_PARSE_ERROR: 'JSONParseError',

    /** @constant */
    MISSING_REQUEST_HEADER: 'MissingRequestHeader',

    /** @constant */
    INCOMPLETE_REQUEST_BODY: 'IncompleteRequestBody',

    /** @constant */
    MISSING_REQUEST_PARAMETER: 'MissingRequestParameter',

    /** @constant */
    INVALID_IDENTIFIER: 'InvalidIdentifier',

    /** @constant */
    BAD_REQUEST: 'BadRequest',

    /** @constant */
    FEATURE_UNAVAILABLE: 'FeatureUnavailable',

    /** @constant */
    API_VERSION_NOT_IMPLEMENTED: 'APIVersionNotImplemented',

    /** @constant */
    API_VERSION_NOT_AVAILABLE: 'APIVersionNotAvailable',

    /** @constant */
    INPUT_VALIDATION_FAILED: 'InputValidationFailed',

    /** @constant */
    BL_RUNTIME_ERROR: 'BLRuntimeError',

    /** @constant */
    BL_SYNTAX_ERROR: 'BLSyntaxError',

    /** @constant */
    BL_TIMEOUT_ERROR: 'BLTimeoutError',

    /** @constant */
    BL_VIOLATION_ERROR: 'BLViolationError',

    /** @constant */
    BL_INTERNAL_ERROR: 'BLInternalError',

    /** @constant */
    STALE_REQUEST: 'StaleRequest'
  };

  // Assign unique id to every object, so we can save circular references.
  var objectId = 0;

  // Define the Kinvey Entity class.
  Kinvey.Entity = Base.extend({
    // Identifier attribute.
    ATTR_ID: '_id',

    // Map.
    map: {},

    /**
     * Creates a new entity.
     *
     * @example <code>
     * var entity = new Kinvey.Entity({}, 'my-collection');
     * var entity = new Kinvey.Entity({ key: 'value' }, 'my-collection');
     * </code>
     *
     * @name Kinvey.Entity
     * @constructor
     * @param {Object} [attr] Attribute object.
     * @param {string} collection Owner collection.
     * @param {Object} options Options.
     * @throws {Error} On empty collection.
     */
    constructor: function(attr, collection, options) {
      if(null == collection) {
        throw new Error('Collection must not be null');
      }
      this.attr = attr || {};
      this.collection = collection;
      this.metadata = null;

      // Options.
      options || (options = {});
      options.map && (this.map = options.map);
      this.store = Kinvey.Store.factory(options.store, this.collection, options.options);

      // Assign object id.
      this.__objectId = ++objectId;
    },

    /** @lends Kinvey.Entity# */

    /**
     * Destroys entity.
     *
     * @param {Object} [options]
     * @param {function(entity, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    destroy: function(options) {
      options || (options = {});
      this.store.remove(this.toJSON(true), merge(options, {
        success: bind(this, function(_, info) {
          options.success && options.success(this, info);
        })
      }));
    },

    /**
     * Returns attribute, or null if not set.
     *
     * @param {string} key Attribute key.
     * @throws {Error} On empty key.
     * @return {*} Attribute.
     */
    get: function(key) {
      if(null == key) {
        throw new Error('Key must not be null');
      }

      // Return attribute, or null if attribute is null or undefined.
      var value = this.attr[key];
      return null != value ? value : null;
    },

    /**
     * Returns id or null if not set.
     *
     * @return {string} id
     */
    getId: function() {
      return this.get(this.ATTR_ID);
    },

    /**
     * Returns metadata.
     *
     * @return {Kinvey.Metadata} Metadata.
     */
    getMetadata: function() {
      // Lazy load metadata object, and return it.
      this.metadata || (this.metadata = new Kinvey.Metadata(this.attr));
      return this.metadata;
    },

    /**
     * Returns whether entity is persisted.
     *
     * @return {boolean}
     */
    isNew: function() {
      return null === this.getId();
    },

    /**
     * Loads entity by id.
     *
     * @param {string} id Entity id.
     * @param {Object} [options]
     * @param {function(entity, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @throws {Error} On empty id.
     */
    load: function(id, options) {
      if(null == id) {
        throw new Error('Id must not be null');
      }
      options || (options = {});

      this.store.query(id, merge(options, {
        success: bind(this, function(response, info) {
          // Maintain collection store type and configuration.
          var opts = { store: this.store.name, options: this.store.options };

          // Resolve references, and update attributes.
          this.attr = Kinvey.Entity._resolve(this.map, response, options.resolve, opts);
          this.metadata = null;// Reset.
          options.success && options.success(this, info);
        })
      }));
    },

    /**
     * Saves entity.
     *
     * @param {Object} [options]
     * @param {function(entity, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    save: function(options) {
      options || (options = {});

      // Save references first, then save original.
      this._saveReferences(merge(options, {
        success: bind(this, function(outAttr) {
          this.store.save(this.toJSON(true), merge(options, {
            success: bind(this, function(response, info) {
              // Replace flat references with real objects. outAttr is an
              // array containing fields to replace with the replacement object.
              while(outAttr[0]) {
                var resolve = outAttr.shift();
                var segments = resolve.attr.split('.');
                var doc = response;

                // Descent in doc and look for segment.
                while(segments[0]) {
                  var field = segments.shift();

                  // If the path is not fully traversed, continue.
                  if(segments[0]) {
                    doc = doc[field];
                  }
                  else {// Replace field value with replacement object.
                    doc[field] = resolve.obj;
                  }
                }
              }

              // Update attributes.
              this.attr = response;
              this.metadata = null;// Reset.
              options.success && options.success(this, info);
            })
          }));
        }),
        error: options.error
      }));
    },

    /**
     * Sets attribute.
     *
     * @param {string} key Attribute key.
     * @param {*} value Attribute value.
     * @throws {Error} On empty key.
     */
    set: function(key, value) {
      if(null == key) {
        throw new Error('Key must not be null');
      }
      this.attr[key] = value;
    },

    /**
     * Sets id.
     *
     * @param {string} id Id.
     * @throws {Error} On empty id.
     */
    setId: function(id) {
      if(null == id) {
        throw new Error('Id must not be null');
      }
      this.set(this.ATTR_ID, id);
    },

    /**
     * Sets metadata.
     *
     * @param {Kinvey.Metadata} metadata Metadata object.
     * @throws {Error} On invalid instance.
     */
    setMetadata: function(metadata) {
      if(metadata && !(metadata instanceof Kinvey.Metadata)) {
        throw new Error('Metadata must be an instanceof Kinvey.Metadata');
      }
      this.metadata = metadata || null;
    },

    /**
     * Returns JSON representation. Used by JSON#stringify.
     *
     * @param {boolean} [doNotFlatten] If false, returns entity using reference syntax.
     * @returns {Object} JSON representation.
     */
    toJSON: function(doNotFlatten) {
      if(true === doNotFlatten) {
        // stringify and then parse again, so all attributes are actually plain
        // JSON. Otherwise, references will still be Kinvey.Entity-s.
        var result = JSON.parse(JSON.stringify(this.attr));
        this.metadata && (result._acl = this.metadata.toJSON()._acl);
        return result;
      }

      // Flatten entity by returning it in reference syntax.
      return {
        _type: 'KinveyRef',
        _collection: this.collection,
        _id: this.getId()
      };
    },

    /**
     * Removes attribute.
     *
     * @param {string} key Attribute key.
     */
    unset: function(key) {
      delete this.attr[key];
    },

    /**
     * Saves references.
     *
     * @private
     * @param {Object} options
     * @param {function(outAttr)} options.success Success callback.
     * @param {function(error, info)} options.error Failure callback.
     * @param {Array} __obj List of objects already saved.
     */
    _saveReferences: function(options) {
      // To be able to save circular references, track already saved objects.
      var saved = options.__obj || [];

      // outAttr contains the path and replacement object of a reference.
      var outAttr = [];

      // To check for references, check each and every attribute.
      var stack = [];
      Object.keys(this.attr).forEach(function(attr) {
        if(this.attr[attr] instanceof Object) {
          stack.push({ attr: attr, doc: this.attr[attr] });
        }
      }, this);

      // Define function to check a single item in the stack. If a reference
      // is found, save it (asynchronously).
      var saveSingleReference = function() {
        // If there is more to check, do that first.
        if(stack[0]) {
          var item = stack.shift();
          var attr = item.attr;
          var doc = item.doc;// Always an object.

          // doc is an object. First case: doc is an entity.
          if(doc instanceof Kinvey.Entity) {
            // If entity is already saved, it is referenced circularly. In that
            // case, add it to outAttr directly and skip saving it again.
            if(-1 !== saved.indexOf(doc.__objectId)) {
              outAttr.push({ attr: attr, obj: doc });
              return saveSingleReference();// Proceed.
            }

            // Save doc if user has permission to do so.
            saved.push(doc.__objectId);
            if(doc.getMetadata().hasWritePermissions()) {
              doc.save(merge(options, {
                success: function(obj) {
                  outAttr.push({ attr: attr, obj: obj });
                  saveSingleReference();// Proceed.
                },
                error: options.error,
                __obj: saved// Pass tracking.
              }));
            }
            else {// Proceed without saving.
              outAttr.push({ attr: attr, obj: doc });
              saveSingleReference();// Proceed.
            }
          }

          // Second case: doc is an array. Only immediate references are saved.
          else if(doc instanceof Array) {
            // Instead of calling a function for every member, filter array so
            // only references remain.
            var refs = [];
            for(var i in doc) {
              if(doc[i] instanceof Kinvey.Entity) {
                refs.push({ index: i, doc: doc[i] });
              }
            }

            // Define function to save the found references in the array.
            var saveArrayReference = function(i) {
              // If there is more to check, do that first.
              if(i < refs.length) {
                var index = refs[i].index;
                var member = refs[i].doc;

                // If entity is already saved, it is referenced circularly.
                // In that case, add it to outAttr directly and skip saving
                // it again.
                if(-1 !== saved.indexOf(member.__objectId)) {
                  outAttr.push({ attr: attr + '.' + index, obj: member });
                  return saveArrayReference(++i);// Proceed.
                }

                // Save member if user has permission to do so.
                saved.push(member.__objectId);
                if(member.getMetadata().hasWritePermissions()) {
                  member.save(merge(options, {
                    success: function(obj) {
                      outAttr.push({ attr: attr + '.' + index, obj: obj });
                      saveArrayReference(++i);// Proceed.
                    },
                    error: options.error,
                    __obj: saved// Pass tracking.
                  }));
                }
                else {// Proceed without saving.
                  outAttr.push({ attr: attr + '.' + index, obj: member });
                  saveArrayReference(++i);// Proceed.
                }
              }

              // Otherwise, array is traversed.
              else {
                saveSingleReference();// Proceed.
              }
            };
            saveArrayReference(0);// Trigger.
          }

          // Third and last case: doc is a plain object.
          else {
            // Check each and every attribute by adding them to the stack.
            Object.keys(doc).forEach(function(cAttr) {
              if(doc[cAttr] instanceof Object) {
                stack.push({ attr: attr + '.' + cAttr, doc: doc[cAttr] });
              }
            });
            saveSingleReference();// Proceed.
          }
        }

        // Otherwise, stack is empty and thus all references are saved.
        else {
          options.success(outAttr);
        }
      };
      saveSingleReference();// Trigger.
    }
  }, {
    /** @lends Kinvey.Entity */

    /**
     * Resolves references in attr according to entity definition.
     *
     * @private
     * @param {Object} map Entity mapping.
     * @param {Object} attr Attributes.
     * @param {Array} [resolve] Fields to resolve.
     * @param {Object} [options] Options.
     * @return {Object} Relational data structure.
     */
    _resolve: function(map, attr, resolve, options) {
      resolve = resolve ? resolve.slice(0) : [];// Copy by value.

      // Parse to be resolved references one-by-one. If there are no references,
      // there is no performance penalty :)
      while(resolve[0]) {
        var path = resolve.shift();
        var segments = path.split('.');
        var doc = attr;

        // Track path for entity mapping purposes.
        var currentPath = '';
        var currentMap = map;

        // Descent in doc and look for segment.
        while(segments[0]) {
          // (Top-level) field name of doc.
          var field = segments.shift();
          currentPath += (currentPath ? '.' : '') + field;
          var ClassDef = currentMap[currentPath] || Kinvey.Entity;

          // Check and resolve top-level reference. Otherwise: descent deeper.
          if(doc.hasOwnProperty(field) && null != doc[field]) {// doc does have field.
            // First case: field is a (resolved) reference.
            if('KinveyRef' === doc[field]._type || doc[field] instanceof Kinvey.Entity) {
              if('KinveyRef' === doc[field]._type) {// Unresolved reference.
                // Resolve only if actual object is embedded, or the to-be-resolved
                // reference is a attribute of the currently found reference.
                if(segments[0] || doc[field]._obj) {
                  // The actual object may not be embedded, so we need to set
                  // the object id explicitly (otherwise, save() will fail).
                  var id = doc[field]._id;
                  doc[field] = new ClassDef(doc[field]._obj, doc[field]._collection, options);
                  doc[field].setId(id);
                }
                else {// The desired resolve doesnâ€™t have its object embedded.
                  break;
                }
              }

              // Current path and map are to be reset relative to the new entity.
              currentPath = '';
              currentMap = doc[field].map;
              doc = doc[field].attr;
            }

            // Second case: field is an array.
            else if(doc[field] instanceof Array) {
              // Only immediate members will be checked are resolved.
              for(var i in doc[field]) {
                var member = doc[field][i];
                if(member && 'KinveyRef' === member._type && member._obj) {
                  doc[field][i] = new ClassDef(member._obj, member._collection, options);
                }
              }
            }

            // Third and last case: field is a plain object.
            else {
              doc = doc[field];
            }
          }
          else {// doc does not have field; skip reference.
            break;
          }
        }
      }

      // Attributes now contain all resolved references.
      return attr;
    }
  });

  // Define the Kinvey Collection class.
  Kinvey.Collection = Base.extend({
    // List of entities.
    list: [],

    // Mapped entity class.
    entity: Kinvey.Entity,

    /**
     * Creates new collection.
     *
     * @example <code>
     * var collection = new Kinvey.Collection('my-collection');
     * </code>
     *
     * @constructor
     * @name Kinvey.Collection
     * @param {string} name Collection name.
     * @param {Object} [options] Options.
     * @throws {Error}
     *           <ul>
     *           <li>On empty name,</li>
     *           <li>On invalid query instance.</li>
     *           </ul>
     */
    constructor: function(name, options) {
      if(null == name) {
        throw new Error('Name must not be null');
      }
      this.name = name;

      // Options.
      options || (options = {});
      this.setQuery(options.query || new Kinvey.Query());
      this.store = Kinvey.Store.factory(options.store, this.name, options.options);
    },

    /** @lends Kinvey.Collection# */

    /**
     * Aggregates entities in collection.
     *
     * @param {Kinvey.Aggregation} aggregation Aggregation object.
     * @param {Object} [options]
     * @param {function(aggregation, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    aggregate: function(aggregation, options) {
      if(!(aggregation instanceof Kinvey.Aggregation)) {
        throw new Error('Aggregation must be an instanceof Kinvey.Aggregation');
      }
      aggregation.setQuery(this.query);// respect collection query.
      this.store.aggregate(aggregation.toJSON(), options);
    },

    /**
     * Clears collection.
     *
     * @param {Object} [options]
     * @param {function(info)} [success] Success callback.
     * @param {function(error, info)} [error] Failure callback.
     */
    clear: function(options) {
      options || (options = {});
      this.store.removeWithQuery(this.query.toJSON(), merge(options, {
        success: bind(this, function(_, info) {
          this.list = [];
          options.success && options.success(info);
        })
      }));
    },

    /**
     * Counts number of entities.
     *
     * @example <code>
     * var collection = new Kinvey.Collection('my-collection');
     * collection.count({
     *   success: function(i) {
     *    console.log('Number of entities: ' + i);
     *   },
     *   error: function(error) {
     *     console.log('Count failed', error.description);
     *   }
     * });
     * </code>
     *
     * @param {Object} [options]
     * @param {function(count, info)} [success] Success callback.
     * @param {function(error, info)} [error] Failure callback.
     */
    count: function(options) {
      options || (options = {});

      var aggregation = new Kinvey.Aggregation();
      aggregation.setInitial({ count: 0 });
      aggregation.setReduce(function(doc, out) {
        out.count += 1;
      });
      aggregation.setQuery(this.query);// Apply query.

      this.store.aggregate(aggregation.toJSON(), merge(options, {
        success: function(response, info) {
          // Aggregation can return an empty array, when the count is 0.
          var count = response[0] ? response[0].count : 0;
          options.success && options.success(count, info);
        }
      }));
    },

    /**
     * Fetches entities in collection.
     *
     * @param {Object} [options]
     * @param {function(list, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    fetch: function(options) {
      options || (options = {});

      // Send request.
      this.store.queryWithQuery(this.query.toJSON(), merge(options, {
        success: bind(this, function(response, info) {
          this.list = [];
          response.forEach(function(attr) {
            // Maintain collection store type and configuration.
            var opts = { store: this.store.name, options: this.store.options };

            // Resolve references, and create the new entity.
            attr = Kinvey.Entity._resolve(this.entity.prototype.map, attr, options.resolve, opts);
            this.list.push(new this.entity(attr, this.name, opts));
          }, this);
          options.success && options.success(this.list, info);
        })
      }));
    },

    /**
     * Sets query.
     *
     * @param {Kinvey.Query} [query] Query.
     * @throws {Error} On invalid instance.
     */
    setQuery: function(query) {
      if(query && !(query instanceof Kinvey.Query)) {
        throw new Error('Query must be an instanceof Kinvey.Query');
      }
      this.query = query || new Kinvey.Query();
    },

    /**
     * Returns JSON representation. Used by JSON#stringify.
     *
     * @returns {Array} JSON representation.
     */
    toJSON: function() {
      var result = [];
      this.list.forEach(function(entity) {
        result.push(entity.toJSON(true));
      });
      return result;
    }
  });

  // Function to get the cache key for this app.
  var CACHE_TAG = function() {
    return 'Kinvey.' + Kinvey.appKey;
  };

  // Define the Kinvey User class.
  Kinvey.User = Kinvey.Entity.extend({
    // Credential attributes.
    ATTR_USERNAME: 'username',
    ATTR_PASSWORD: 'password',

    // Authorization token.
    token: null,

    /**
     * Creates a new user.
     *
     * @example <code>
     * var user = new Kinvey.User();
     * var user = new Kinvey.User({ key: 'value' });
     * </code>
     *
     * @name Kinvey.User
     * @constructor
     * @extends Kinvey.Entity
     * @param {Object} [attr] Attributes.
     */
    constructor: function(attr) {
      Kinvey.Entity.prototype.constructor.call(this, attr, 'user');
    },

    /** @lends Kinvey.User# */

    /**
     * Destroys user. Use with caution.
     *
     * @override
     * @see Kinvey.Entity#destroy
     */
    destroy: function(options) {
      options || (options = {});

      // Destroying the user will automatically invalidate its token, so no
      // need to logout explicitly.
      Kinvey.Entity.prototype.destroy.call(this, merge(options, {
        success: bind(this, function(_, info) {
          this._logout();
          options.success && options.success(this, info);
        })
      }));
    },

    /**
     * Returns social identity, or null if not set.
     *
     * @return {Object} Identity.
     */
    getIdentity: function() {
      return this.get('_socialIdentity');
    },

    /**
     * Returns token, or null if not set.
     *
     * @return {string} Token.
     */
    getToken: function() {
      return this.token;
    },

    /**
     * Returns username, or null if not set.
     *
     * @return {string} Username.
     */
    getUsername: function() {
      return this.get(this.ATTR_USERNAME);
    },

    /**
     * Returns whether the user email address was verified.
     *
     * @return {boolean}
     */
    isVerified: function() {
      // Obtain email verification status from metadata object.
      var email = this.getMetadata().kmd.emailVerification;
      if(email) {
        return 'confirmed' === email.status;
      }
      return false;
    },

    /**
     * Logs in user.
     *
     * @example <code>
     * var user = new Kinvey.User();
     * user.login('username', 'password', {
     *   success: function() {
     *     console.log('Login successful');
     *   },
     *   error: function(error) {
     *     console.log('Login failed', error);
     *   }
     * });
     * </code>
     *
     * @param {string} username Username.
     * @param {string} password Password.
     * @param {Object} [options]
     * @param {function(entity, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    login: function(username, password, options) {
      this._doLogin({
        username: username,
        password: password
      }, options || {});
    },

    /**
     * Logs in user given a Facebook OAuth 2.0 token.
     *
     * @param {Object} tokens
     * @param {string} access_token OAuth access token.
     * @param {integer} expires_in Expiration interval.
     * @param {Object} [attr] User attributes.
     * @param {Object} [options]
     * @param {function(user, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @throws {Error} On incomplete tokens.
     */
    loginWithFacebook: function(tokens, attr, options) {
      tokens || (tokens = {});
      if(!(tokens.access_token && tokens.expires_in)) {
        throw new Error('Missing required token: access_token and/or expires_in');
      }

      // Merge token with user attributes.
      attr || (attr = {});
      attr._socialIdentity = { facebook: tokens };

      // Login or register.
      this._loginWithProvider(attr, options || {});
    },

    /**
     * Logs in user given a Google+ OAuth 2.0 token.
     *
     * @param {Object} tokens
     * @param {string} access_token OAuth access token.
     * @param {integer} expires_in Expiration interval.
     * @param {Object} [attr] User attributes.
     * @param {Object} [options]
     * @param {function(user, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @throws {Error} On incomplete tokens.
     */
    loginWithGoogle: function(tokens, attr, options) {
      tokens || (tokens = {});
      if(!(tokens.access_token && tokens.expires_in)) {
        throw new Error('Missing required token: access_token and/or expires_in');
      }

      // Merge tokens with user attributes.
      attr || (attr = {});
      attr._socialIdentity = { google: tokens };

      // Login, or register.
      this._loginWithProvider(attr, options || {});
    },

    /**
     * Logs in user given a LinkedIn OAuth 1.0a token.
     *
     * @param {Object} tokens
     * @param {string} tokens.access_token OAuth access token.
     * @param {string} tokens.access_token_secret OAuth access token secret.
     * @param {string} [tokens.consumer_key] LinkedIn application key.
     * @param {string} [tokens.consumer_secret] LinkedIn application secret.
     * @param {Object} [attr] User attributes.
     * @param {Object} [options]
     * @param {function(user, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @throws {Error} On incomplete tokens.
     */
    loginWithLinkedIn: function(tokens, attr, options) {
      tokens || (tokens = {});
      if(!(tokens.access_token && tokens.access_token_secret)) {
        throw new Error('Missing required token: access_token and/or access_token_secret');
      }

      // Merge tokens with user attributes.
      attr || (attr = {});
      attr._socialIdentity = { linkedIn: tokens };

      // Login, or register. Set flag whether protocol is OAuth1.0a.
      this._loginWithProvider(attr, merge(options, {
        oauth1: tokens.consumer_key && tokens.consumer_secret ? null : 'linkedIn'
      }));
    },

    /**
     * Logs in user given a Twitter OAuth 1.0a token.
     *
     * @param {Object} tokens
     * @param {string} tokens.access_token OAuth access token.
     * @param {string} tokens.access_token_secret OAuth access token secret.
     * @param {string} tokens.consumer_key Twitter application key.
     * @param {string} tokens.consumer_secret Twitter application secret.
     * @param {Object} [attr] User attributes.
     * @param {Object} [options]
     * @param {function(user, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @throws {Error} On incomplete tokens.
     */
    loginWithTwitter: function(tokens, attr, options) {
      tokens || (tokens = {});
      if(!(tokens.access_token && tokens.access_token_secret)) {
        throw new Error('Missing required token: access_token and/or access_token_secret');
      }

      // Merge tokens with user attributes.
      attr || (attr = {});
      attr._socialIdentity = { twitter: tokens };

      // Login, or register.
      this._loginWithProvider(attr, merge(options, {
        oauth1: tokens.consumer_key && tokens.consumer_secret ? null : 'twitter'
      }));
    },

    /**
     * Logs out user.
     *
     * @param {Object} [options] Options.
     * @param {function(info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    logout: function(options) {
      options || (options = {});

      // Make sure we only logout the current user.
      if(!this.isLoggedIn) {
        options.success && options.success({});
        return;
      }
      this.store.logout({}, merge(options, {
        success: bind(this, function(_, info) {
          this._logout();
          options.success && options.success(info);
        })
      }));
    },

    /**
     * Purges social identity for provider.
     *
     * @param {string} provider Provider.
     */
    purgeIdentity: function(provider) {
      var identity = this.getIdentity();
      if(identity && identity[provider]) {
        identity[provider] = null;
      }
    },

    /**
     * Saves a user.
     *
     * @override
     * @see Kinvey.Entity#save
     */
    save: function(options) {
      options || (options = {});
      if(!this.isLoggedIn) {
        options.error && options.error({
          code: Kinvey.Error.BAD_REQUEST,
          description: 'This operation is not allowed',
          debug: 'Cannot save a user which is not logged in.'
        }, {});
        return;
      }

      // Parent method will always update.
      Kinvey.Entity.prototype.save.call(this, merge(options, {
        success: bind(this, function(_, info) {
          // Extract token.
          var token = this.attr._kmd.authtoken;
          delete this.attr._kmd.authtoken;
          this._login(token);// Refresh.

          options.success && options.success(this, info);
        })
      }));
    },

    /**
     * Sets a new password.
     *
     * @param {string} password New password.
     */
    setPassword: function(password) {
      this.set(this.ATTR_PASSWORD, password);
    },

    /**
     * Removes any user saved on disk.
     *
     * @private
     */
    _deleteFromDisk: function() {
      Storage.remove(CACHE_TAG());
    },

    /**
     * Performs login.
     *
     * @private
     * @param {Object} attr Attributes.
     * @param {Object} options Options.
     */
    _doLogin: function(attr, options) {
      // Make sure only one user is active at the time.
      var currentUser = Kinvey.getCurrentUser();
      if(null !== currentUser) {
        currentUser.logout(merge(options, {
          success: bind(this, function() {
            this._doLogin(attr, options);
          })
        }));
        return;
      }

      // Send request.
      this.store.login(attr, merge(options, {
        success: bind(this, function(response, info) {
          // Extract token.
          var token = response._kmd.authtoken;
          delete response._kmd.authtoken;

          // Update attributes. This does not include the users password.
          this.attr = response;
          this._login(token);

          options.success && options.success(this, info);
        })
      }));
    },

    /**
     * Marks user as logged in. This method should never be called standalone,
     * but always involve some network request.
     *
     * @private
     * @param {string} token Token.
     */
    _login: function(token) {
      // The master secret does not need a current user.
      if(null == Kinvey.masterSecret) {
        Kinvey.setCurrentUser(this);
        this.isLoggedIn = true;
        this.token = token;
        this._saveToDisk();
      }
    },

    /**
     * Logs in or create user with a given identity.
     *
     * @private
     * @param {Object} [attr] User attributes.
     * @param {Object} [options]
     * @param {function(user, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     */
    _loginWithProvider: function(attr, options) {
      // Login, or create when there is no user with this identity.
      this._doLogin(attr, merge(options, {
        error: bind(this, function(error, info) {
          // If user could not be found, register.
          if(Kinvey.Error.USER_NOT_FOUND === error.error) {
            // Pass current instance to render result in.
            return Kinvey.User.create(attr, merge(options, { __target: this }));
          }

          // Something else went wrong (invalid token?), error out.
          options.error && options.error(error, info);
        })
      }));
    },

    /**
     * Marks user no longer as logged in.
     *
     * @private
     */
    _logout: function() {
      // The master secret does not need a current user.
      if(null == Kinvey.masterSecret) {
        Kinvey.setCurrentUser(null);
        this.isLoggedIn = false;
        this.token = null;
        this._deleteFromDisk();
      }
    },

    /**
     * Saves current user to disk.
     *
     * @private
     */
    _saveToDisk: function() {
      var attr = this.toJSON(true);
      delete attr.password;// Never save password.
      Storage.set(CACHE_TAG(), {
        token: this.token,
        user: attr
      });
    }
  }, {
    /** @lends Kinvey.User */

    /**
     * Creates the current user.
     *
     * @example <code>
     * Kinvey.User.create({
     *   username: 'username'
     * }, {
     *   success: function(user) {
     *     console.log('User created', user);
     *   },
     *   error: function(error) {
     *     console.log('User not created', error.message);
     *   }
     * });
     * </code>
     *
     * @param {Object} attr Attributes.
     * @param {Object} [options]
     * @param {function(user)} [options.success] Success callback.
     * @param {function(error)} [options.error] Failure callback.
     * @return {Kinvey.User} The user instance (not necessarily persisted yet).
     */
    create: function(attr, options) {
      options || (options = {});

      // Create the new user.
      var user = options.__target || new Kinvey.User();
      user.attr = attr;// Set attributes.

      // Make sure only one user is active at the time.
      var currentUser = Kinvey.getCurrentUser();
      if(null !== currentUser) {
        currentUser.logout(merge(options, {
          success: function() {
            // Try again. Use the already instantiated user as target.
            Kinvey.User.create(attr, merge(options, {
              _target: user
            }));
          }
        }));
      }
      else {// Save the instantiated user.
        Kinvey.Entity.prototype.save.call(user, merge(options, {
          success: bind(user, function(_, info) {
            // Extract token.
            var token = this.attr._kmd.authtoken;
            delete this.attr._kmd.authtoken;
            this._login(token);

            options.success && options.success(this, info);
          })
        }));
      }

      // Return the user instance.
      return user;
    },

    /**
     * Initializes a current user. Returns the current user, otherwise creates
     * an implicit user. This method is called internally when doing a network
     * request. Manually invoking this function is however allowed.
     *
     * @param {Object} [options]
     * @param {function(user)} [options.success] Success callback.
     * @param {function(error)} [options.error] Failure callback.
     * @return {Kinvey.User} The user instance. (not necessarily persisted yet).
     */
    init: function(options) {
      options || (options = {});

      // Check whether there already is a current user.
      var user = Kinvey.getCurrentUser();
      if(null !== user) {
        options.success && options.success(user, {});
        return user;
      }

      // No cached user available, create implicit user.
      return Kinvey.User.create({}, options);
    },

    /**
     * Resets password for a user.
     *
     * @param {string} username User name.
     * @param {Object} [options]
     * @param {function()} [options.success] Success callback.
     * @param {function(error)} [options.error] Failure callback.
     */
    resetPassword: function(username, options) {
      var store = new Kinvey.Store.Rpc();
      store.resetPassword(username, options);
    },

    /**
     * Verifies e-mail for a user.
     *
     * @param {string} username User name.
     * @param {Object} [options]
     * @param {function()} [options.success] Success callback.
     * @param {function(error)} [options.error] Failure callback.
     */
    verifyEmail: function(username, options) {
      var store = new Kinvey.Store.Rpc();
      store.verifyEmail(username, options);
    },

    /**
     * Restores user stored locally on the device. This method is called by
     * Kinvey.init(), and should not be called anywhere else.
     *
     * @private
     */
    _restore: function() {
      // Retrieve and restore user from storage.
      var data = Storage.get(CACHE_TAG());
      if(null !== data && null != data.token && null != data.user) {
        new Kinvey.User(data.user)._login(data.token);
      }
      else {// No user, reset.
        Kinvey.setCurrentUser(null);
      }
    }
  });

  // Define the Kinvey UserCollection class.
  Kinvey.UserCollection = Kinvey.Collection.extend({
    // Mapped entity class.
    entity: Kinvey.User,

    /**
     * Creates new user collection.
     *
     * @example <code>
     * var collection = new Kinvey.UserCollection();
     * </code>
     *
     * @name Kinvey.UserCollection
     * @constructor
     * @extends Kinvey.Collection
     * @param {Object} options Options.
     */
    constructor: function(options) {
      Kinvey.Collection.prototype.constructor.call(this, 'user', options);
    },

    /** @lends Kinvey.UserCollection# */

    /**
     * Clears collection. This action is not allowed.
     *
     * @override
     */
    clear: function(options) {
      options && options.error && options.error({
        code: Kinvey.Error.BAD_REQUEST,
        description: 'This operation is not allowed',
        debug: ''
      });
    }
  });

  // Define the Kinvey Metadata class.
  Kinvey.Metadata = Base.extend({
    /**
     * Creates a new metadata instance.
     *
     * @name Kinvey.Metadata
     * @constructor
     * @param {Object} [attr] Attributes containing metadata.
     */
    constructor: function(attr) {
      attr || (attr = {});
      this.acl = attr._acl || {};
      this.acl.groups || (this.acl.groups = {});
      this.kmd = attr._kmd || {};
    },

    /** @lends Kinvey.Metadata# */

    /**
     * Adds item read permissions for user.
     *
     * @param {string} user User id.
     */
    addReader: function(user) {
      this.acl.r || (this.acl.r = []);
      if(-1 === this.acl.r.indexOf(user)) {
        this.acl.r.push(user);
      }
    },

    /**
     * Adds item read permissions for group.
     *
     * @param {string} group Group id.
     */
    addReaderGroup: function(group) {
      this.acl.groups.r || (this.acl.groups.r = []);
      if(-1 === this.acl.groups.r.indexOf(group)) {
        this.acl.groups.r.push(group);
      }
    },

    /**
     * Adds item write permissions for user.
     *
     * @param {string} user User id.
     */
    addWriter: function(user) {
      this.acl.w || (this.acl.w = []);
      if(-1 === this.acl.w.indexOf(user)) {
        this.acl.w.push(user);
      }
    },

    /**
     * Adds item write permission for user group.
     *
     * @param {string} group Group id.
     */
    addWriterGroup: function(group) {
      this.acl.groups.w || (this.acl.groups.w = []);
      if(-1 === this.acl.groups.w.indexOf(group)) {
        this.acl.groups.w.push(group);
      }
    },

    /**
     * Returns the entity owner, or null if not set.
     *
     * @return {string} user User id.
     */
    creator: function() {
      return this.acl.creator || null;
    },

    /**
     * Returns all reader groups.
     *
     * @return {Array} List of groups.
     */
    getReaderGroups: function() {
      return this.acl.groups.r || [];
    },

    /**
     * Returns all readers.
     *
     * @return {Array} List of readers.
     */
    getReaders: function() {
      return this.acl.r || [];
    },

    /**
     * Returns all writer groups.
     *
     * @return {Array} List of groups.
     */
    getWriterGroups: function() {
      return this.acl.groups.w || [];
    },

    /**
     * Returns all writers.
     *
     * @return {Array} List of writers.
     */
    getWriters: function() {
      return this.acl.w || [];
    },

    /**
     * Returns whether the current user owns the item. This method
     * is only useful when the class is created with a predefined
     * ACL.
     *
     * @returns {boolean}
     */
    isOwner: function() {
      var owner = this.acl.creator;
      var currentUser = Kinvey.getCurrentUser();

      // If owner is undefined, assume entity is just created.
      if(owner) {
        return !!currentUser && owner === currentUser.getId();
      }
      return true;
    },

    /**
     * Returns last modified date, or null if not set.
     *
     * @return {string} ISO-8601 formatted date.
     */
    lastModified: function() {
      return this.kmd.lmt || null;
    },

    /**
     * Returns whether the current user has write permissions.
     *
     * @returns {Boolean}
     */
    hasWritePermissions: function() {
      if(this.isOwner() || this.isGloballyWritable()) {
        return true;
      }

      var currentUser = Kinvey.getCurrentUser();
      if(currentUser && this.acl.w) {
        return -1 !== this.acl.w.indexOf(currentUser.getId());
      }
      return false;
    },

    /**
     * Returns whether the item is globally readable.
     *
     * @returns {Boolean}
     */
    isGloballyReadable: function() {
      return !!this.acl.gr;
    },

    /**
     * Returns whether the item is globally writable.
     *
     * @returns {Boolean}
     */
    isGloballyWritable: function() {
      return !!this.acl.gw;
    },

    /**
     * Removes item read permissions for user.
     *
     * @param {string} user User id.
     */
    removeReader: function(user) {
      if(this.acl.r) {
        var index = this.acl.r.indexOf(user);
        if(-1 !== index) {
          this.acl.r.splice(index, 1);
        }
      }
    },

    /**
     * Removes item read permissions for group.
     *
     * @param {string} group Group id.
     */
    removeReaderGroup: function(group) {
      if(this.acl.groups.r) {
        var index = this.acl.groups.r.indexOf(group);
        if(-1 !== index) {
          this.acl.groups.r.splice(index, 1);
        }
      }
    },

    /**
     * Removes item write permissions for user.
     *
     * @param {string} user User id.
     */
    removeWriter: function(user) {
      if(this.acl.w) {
        var index = this.acl.w.indexOf(user);
        if(-1 !== index) {
          this.acl.w.splice(index, 1);
        }
      }
    },

    /**
     * Removes item write permissions for group.
     *
     * @param {string} group Group id.
     */
    removeWriterGroup: function(group) {
      if(this.acl.groups.w) {
        var index = this.acl.groups.w.indexOf(group);
        if(-1 !== index) {
          this.acl.groups.w.splice(index, 1);
        }
      }
    },

    /**
     * Sets whether the item is globally readable.
     *
     * @param {Boolean} flag
     */
    setGloballyReadable: function(flag) {
      this.acl.gr = !!flag;
    },

    /**
     * Sets whether the item is globally writable.
     *
     * @param {Boolean} flag
     */
    setGloballyWritable: function(flag) {
      this.acl.gw = !!flag;
    },

    /**
     * Returns JSON representation. Used by JSON#stringify.
     *
     * @returns {object} JSON representation.
     */
    toJSON: function() {
      return {
        _acl: this.acl,
        _kmd: this.kmd
      };
    }
  });

  // Define the Kinvey Query class.
  Kinvey.Query = Base.extend({
    // Key under condition.
    currentKey: null,

    /**
     * Creates a new query.
     *
     * @example <code>
     * var query = new Kinvey.Query();
     * </code>
     *
     * @name Kinvey.Query
     * @constructor
     * @param {Object} [builder] One of Kinvey.Query.* builders.
     */
    constructor: function(builder) {
      this.builder = builder || Kinvey.Query.factory();
    },

    /** @lends Kinvey.Query# */

    /**
     * Sets an all condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must be an Array containing both "foo" and "bar".
     * var query = new Kinvey.Query();
     * query.on('field').all(['foo', 'bar']);
     * </code>
     *
     * @param {Array} expected Array of expected values.
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    all: function(expected) {
      if(!(expected instanceof Array)) {
        throw new Error('Argument must be of type Array');
      }
      this._set(Kinvey.Query.ALL, expected);
      return this;
    },

    /**
     * Sets an AND condition.
     *
     * @example <code>
     * // Attribute "field1" must have value "foo", and "field2" must have value "bar".
     * var query1 = new Kinvey.Query();
     * var query2 = new Kinvey.Query();
     * query1.on('field1').equal('foo');
     * query2.on('field2').equal('bar');
     * query1.and(query2);
     * </code>
     *
     * @param {Kinvey.Query} query Query to AND.
     * @throws {Error} On invalid instance.
     * @return {Kinvey.Query} Current instance.
     */
    and: function(query) {
      this._set(Kinvey.Query.AND, query.builder, true);// do not throw.
      return this;
    },

    /**
     * Sets an equal condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have value "foo".
     * var query = new Kinvey.Query();
     * query.on('field').equal('foo');
     * </code>
     *
     * @param {*} expected Expected value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    equal: function(expected) {
      this._set(Kinvey.Query.EQUAL, expected);
      return this;
    },

    /**
     * Sets an exist condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must exist.
     * var query = new Kinvey.Query();
     * query.on('field').exist();
     * </code>
     *
     * @param {boolean} [expected] Boolean indicating whether field must be
     *          present. Defaults to true.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    exist: function(expected) {
      // Make sure the argument is of type boolean.
      expected = 'undefined' !== typeof expected ? !!expected : true;

      this._set(Kinvey.Query.EXIST, expected);
      return this;
    },

    /**
     * Sets a greater than condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value greater than 25.
     * var query = new Kinvey.Query();
     * query.on('field').greaterThan(25);
     * </code>
     *
     * @param {*} value Compared value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    greaterThan: function(value) {
      this._set(Kinvey.Query.GREATER_THAN, value);
      return this;
    },

    /**
     * Sets a greater than equal condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value greater than or equal to 25.
     * var query = new Kinvey.Query();
     * query.on('field').greaterThanEqual(25);
     * </code>
     *
     * @param {*} value Compared value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    greaterThanEqual: function(value) {
      this._set(Kinvey.Query.GREATER_THAN_EQUAL, value);
      return this;
    },

    /**
     * Sets an in condition on the current key. Method has underscore
     * postfix since "in" is a reserved word.
     *
     * @example <code>
     * // Attribute "field" must be an Array containing "foo" and/or "bar".
     * var query = new Kinvey.Query();
     * query.on('field').in_(['foo', 'bar']);
     * </code>
     *
     * @param {Array} expected Array of expected values.
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    in_: function(expected) {
      if(!(expected instanceof Array)) {
        throw new Error('Argument must be of type Array');
      }
      this._set(Kinvey.Query.IN, expected);
      return this;
    },

    /**
     * Sets a less than condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value less than 25.
     * var query = new Kinvey.Query();
     * query.on('field').lessThan(25);
     * </code>
     *
     * @param {*} value Compared value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    lessThan: function(value) {
      this._set(Kinvey.Query.LESS_THAN, value);
      return this;
    },

    /**
     * Sets a less than equal condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value less than or equal to 25.
     * var query = new Kinvey.Query();
     * query.on('field').lessThanEqual(25);
     * </code>
     *
     * @param {*} value Compared value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    lessThanEqual: function(value) {
      this._set(Kinvey.Query.LESS_THAN_EQUAL, value);
      return this;
    },

    /**
     * Sets a near sphere condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must be a point within a 10 mile radius of [-71, 42].
     * var query = new Kinvey.Query();
     * query.on('field').nearSphere([-71, 42], 10);
     * </code>
     *
     * @param {Array} point Point [lng, lat].
     * @param {number} [maxDistance] Max distance from point in miles.
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    nearSphere: function(point, maxDistance) {
      if(!(point instanceof Array) || 2 !== point.length) {
        throw new Error('Point must be of type Array[lng, lat]');
      }
      this._set(Kinvey.Query.NEAR_SPHERE, {
        point: point,
        maxDistance: 'undefined' !== typeof maxDistance ? maxDistance : null
      });
      return this;
    },

    /**
     * Sets a not equal condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value not equal to "foo".
     * var query = new Kinvey.Query();
     * query.on('field').notEqual('foo');
     * </code>
     *
     * @param {*} value Unexpected value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    notEqual: function(unexpected) {
      this._set(Kinvey.Query.NOT_EQUAL, unexpected);
      return this;
    },

    /**
     * Sets a not in condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value not equal to "foo" or "bar".
     * var query = new Kinvey.Query();
     * query.on('field').notIn(['foo', 'bar']);
     * </code>
     *
     * @param {Array} unexpected Array of unexpected values.
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    notIn: function(unexpected) {
      if(!(unexpected instanceof Array)) {
        throw new Error('Argument must be of type Array');
      }
      this._set(Kinvey.Query.NOT_IN, unexpected);
      return this;
    },

    /**
     * Sets key under condition.
     *
     * @param {string} key Key under condition.
     * @return {Kinvey.Query} Current instance.
     */
    on: function(key) {
      this.currentKey = key;
      return this;
    },

    /**
     * Sets an OR condition.
     *
     * @example <code>
     * // Attribute "field1" must have value "foo", or "field2" must have value "bar".
     * var query1 = new Kinvey.Query();
     * var query2 = new Kinvey.Query();
     * query1.on('field1').equal('foo');
     * query2.on('field2').equal('bar');
     * query1.or(query2);
     * </code>
     *
     * @param {Kinvey.Query} query Query to OR.
     * @throws {Error} On invalid instance.
     * @return {Kinvey.Query} Current instance.
     */
    or: function(query) {
      this._set(Kinvey.Query.OR, query.builder, true);// do not throw.
      return this;
    },

    /**
     * Sets a not in condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must have a value starting with foo.
     * var query = new Kinvey.Query();
     * query.on('field').regex(/^foo/);
     * </code>
     *
     * @param {object} expected Regular expression.
     * @throws {Error} On invalid regular expression.
     * @return {Kinvey.Query} Current instance.
     */
    regex: function(expected) {
      this._set(Kinvey.Query.REGEX, expected);
      return this;
    },

    /**
     * Resets all filters.
     *
     * @return {Kinvey.Query} Current instance.
     */
    reset: function() {
      this.builder.reset();
      return this;
    },

    /**
     * Sets the query limit.
     *
     * @param {number} limit Limit.
     * @return {Kinvey.Query} Current instance.
     */
    setLimit: function(limit) {
      this.builder.setLimit(limit);
      return this;
    },

    /**
     * Sets the query skip.
     *
     * @param {number} skip Skip.
     * @return {Kinvey.Query} Current instance.
     */
    setSkip: function(skip) {
      this.builder.setSkip(skip);
      return this;
    },

    /**
     * Sets a size condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must be an Array with 25 elements.
     * var query = new Kinvey.Query();
     * query.on('field').size(25);
     * </code>
     *
     * @param {number} expected Expected value.
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    size: function(expected) {
      this._set(Kinvey.Query.SIZE, expected);
      return this;
    },

    /**
     * Sets the query sort.
     *
     * @param {number} [direction] Sort direction, or null to reset sort.
     *          Defaults to ascending.
     * @return {Kinvey.Query} Current instance.
     */
    sort: function(direction) {
      if(null !== direction) {
        direction = direction || Kinvey.Query.ASC;
      }
      this.builder.setSort(this.currentKey, direction);
      return this;
    },

    /**
     * Returns JSON representation.
     *
     * @return {Object} JSON representation.
     */
    toJSON: function() {
      return this.builder.toJSON();
    },

    /**
     * Sets a within box condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must be a point within the box [-72, 41], [-70, 43].
     * var query = new Kinvey.Query();
     * query.on('field').withinBox([[-72, 41], [-70, 43]]);
     * </code>
     *
     * @param {Array} points Array of two points [[lng, lat], [lng, lat]].
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    withinBox: function(points) {
      if(!(points instanceof Array) || 2 !== points.length) {
        throw new Error('Points must be of type Array[[lng, lat], [lng, lat]]');
      }
      this._set(Kinvey.Query.WITHIN_BOX, points);
      return this;
    },

    /**
     * Sets a within center sphere condition on the current key.
     *
     * @example <code>
     * // Attribute "field" must be a point within a 10 mile radius of [-71, 42].
     * var query = new Kinvey.Query();
     * query.on('field').withinCenterSphere([-72, 41], 0.0025);
     * </code>
     *
     * @param {Array} point Point [lng, lat].
     * @param {number} radius Radius in radians.
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    withinCenterSphere: function(point, radius) {
      if(!(point instanceof Array) || 2 !== point.length) {
        throw new Error('Point must be of type Array[lng, lat]');
      }
      this._set(Kinvey.Query.WITHIN_CENTER_SPHERE, {
        center: point,
        radius: radius
      });
      return this;
    },

    /**
     * Sets a within polygon condition on the current key.
     *
     * @param {Array} points Array of points [[lng, lat], ...].
     * @throws {Error}
     *           <ul>
     *           <li>On invalid argument,</li>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     * @return {Kinvey.Query} Current instance.
     */
    withinPolygon: function(points) {
      if(!(points instanceof Array)) {
        throw new Error('Points must be of type Array[[lng, lat], ...]');
      }
      this._set(Kinvey.Query.WITHIN_POLYGON, points);
      return this;
    },

    /**
     * Helper function to forward condition to builder.
     *
     * @private
     * @throws {Error}
     *           <ul>
     *           <li>When there is no key under condition,</li>
     *           <li>When the condition is not supported by the builder.</li>
     *           </ul>
     */
    _set: function(operator, value, bypass) {
      // Bypass flag can be used to avoid throwing an error.
      if(null === this.currentKey && !bypass) {
        throw new Error('Key under condition must not be null');
      }
      this.builder.addCondition(this.currentKey, operator, value);
    }
  }, {
    /** @lends Kinvey.Query */

    // Basic operators.
    /**
     * Equal operator. Checks if an element equals the specified expression.
     *
     * @constant
     */
    EQUAL: 16,

    /**
     * Exist operator. Checks if an element exists.
     *
     * @constant
     */
    EXIST: 17,

    /**
     * Less than operator. Checks if an element is less than the specified
     * expression.
     *
     * @constant
     */
    LESS_THAN: 18,

    /**
     * Less than or equal to operator. Checks if an element is less than or
     * equal to the specified expression.
     *
     * @constant
     */
    LESS_THAN_EQUAL: 19,

    /**
     * Greater than operator. Checks if an element is greater than the
     * specified expression.
     *
     * @constant
     */
    GREATER_THAN: 20,

    /**
     * Greater than or equal to operator. Checks if an element is greater
     * than or equal to the specified expression.
     *
     * @constant
     */
    GREATER_THAN_EQUAL: 21,

    /**
     * Not equal operator. Checks if an element does not equals the
     * specified expression.
     *
     * @constant
     */
    NOT_EQUAL: 22,

    /**
     * Regular expression operator. Checks if an element matches the specified
     * expression.
     *
     * @constant
     */
    REGEX: 23,

    // Geoqueries.
    /**
     * Near sphere operator. Checks if an element is close to the point in
     * the specified expression.
     *
     * @constant
     */
    NEAR_SPHERE: 1024,

    /**
     * Within box operator. Checks if an element is within the box shape as
     * defined by the expression.
     *
     * @constant
     */
    WITHIN_BOX: 1025,

    /**
     * Within center sphere operator. Checks if an element is within a
     * center sphere as defined by the expression.
     *
     * @constant
     */
    WITHIN_CENTER_SPHERE: 1026,

    /**
     * Within polygon operator. Checks if an element is within a polygon
     * shape as defined by the expression.
     *
     * @constant
     */
    WITHIN_POLYGON: 1027,

    /**
     * Max distance operator. Checks if an element is within a certain
     * distance to the point in the specified expression. This operator
     * requires the use of the near operator as well.
     *
     * @constant
     */
    MAX_DISTANCE: 1028,

    // Set membership
    /**
     * In operator. Checks if an element matches any values in the specified
     * expression.
     *
     * @constant
     */
    IN: 2048,

    /**
     * Not in operator. Checks if an element does not match any value in the
     * specified expression.
     *
     * @constant
     */
    NOT_IN: 2049,

    // Joining operators.
    /**
     * And operator. Supported implicitly.
     *
     * @constant
     */
    AND: 4096,

    /**
     * Or operator. Not supported.
     *
     * @constant
     */
    OR: 4097,

    // Array operators.
    /**
     * All operator. Checks if an element matches all values in the
     * specified expression
     *
     * @constant
     */
    ALL: 8192,

    /**
     * Size operator. Checks if the size of an element matches the specified
     * expression.
     *
     * @constant
     */
    SIZE: 8193,

    // Sort operators.
    /**
     * Ascending sort operator.
     *
     * @constant
     */
    ASC: 16384,

    /**
     * Descending sort operator.
     *
     * @constant
     */
    DESC: 16385,

    /**
     * Returns a query builder.
     *
     * @return {Object} One of Kinvey.Query.* builders.
     */
    factory: function() {
      // Currently, only the Mongo builder is supported.
      return new Kinvey.Query.MongoBuilder();
    }
  });

  // Define the Kinvey Query MongoBuilder class.
  Kinvey.Query.MongoBuilder = Base.extend({
    // Conditions.
    limit: null,
    skip: null,
    sort: null,
    query: null,

    /**
     * Creates a new MongoDB query builder.
     *
     * @name Kinvey.Query.MongoBuilder
     * @constructor
     */
    constructor: function() {
      //
    },

    /** @lends Kinvey.Query.MongoBuilder# */

    /**
     * Adds condition.
     *
     * @param {string} field Field.
     * @param {number} condition Condition.
     * @param {*} value Expression.
     * @throws {Error} On unsupported condition.
     */
    addCondition: function(field, condition, value) {
      switch(condition) {
        // Basic operators.
        // @see http://www.mongodb.org/display/DOCS/Advanced+Queries
        case Kinvey.Query.EQUAL:
          this.query || (this.query = {});
          this.query[field] = value;
          break;
        case Kinvey.Query.EXIST:
          this._set(field, { $exists: value });
          break;
        case Kinvey.Query.LESS_THAN:
          this._set(field, {$lt: value});
          break;
        case Kinvey.Query.LESS_THAN_EQUAL:
          this._set(field, {$lte: value});
          break;
        case Kinvey.Query.GREATER_THAN:
          this._set(field, {$gt: value});
          break;
        case Kinvey.Query.GREATER_THAN_EQUAL:
          this._set(field, {$gte: value});
          break;
        case Kinvey.Query.NOT_EQUAL:
          this._set(field, {$ne: value});
          break;
        case Kinvey.Query.REGEX:
          // Filter through RegExp, this will throw an error on invalid regex.
          var regex = new RegExp(value);
          var options = ((regex.global) ? 'g' : '') + ((regex.ignoreCase) ? 'i' : '') + ((regex.multiline) ? 'm' : '');
          this._set(field, { $regex: regex.source, $options: options });
          break;

        // Geoqueries.
        // @see http://www.mongodb.org/display/DOCS/Geospatial+Indexing
        case Kinvey.Query.NEAR_SPHERE:
          var query = { $nearSphere: value.point };
          value.maxDistance && (query.$maxDistance = value.maxDistance);
          this._set(field, query);
          break;
        case Kinvey.Query.WITHIN_BOX:
          this._set(field, {$within: {$box: value}});
          break;
        case Kinvey.Query.WITHIN_CENTER_SPHERE:
          this._set(field, {$within: {$centerSphere: [value.center, value.radius] }});
          break;
        case Kinvey.Query.WITHIN_POLYGON:
          this._set(field, {$within: {$polygon: value}});
          break;

        // Set membership.
        // @see http://www.mongodb.org/display/DOCS/Advanced+Queries
        case Kinvey.Query.IN:
          this._set(field, {$in: value});
          break;
        case Kinvey.Query.NOT_IN:
          this._set(field, {$nin: value});
          break;

        // Joining operators.
        case Kinvey.Query.AND:
          if(!(value instanceof Kinvey.Query.MongoBuilder)) {
            throw new Error('Query must be of type Kinvey.Query.Mongobuilder');
          }
          this.query = { $and: [this.query || {}, value.query || {}] };
          break;
        case Kinvey.Query.OR:
          if(!(value instanceof Kinvey.Query.MongoBuilder)) {
            throw new Error('Query must be of type Kinvey.Query.Mongobuilder');
          }
          this.query = { $or: [this.query || {}, value.query || {}] };
          break;

        // Array operators.
        // @see http://www.mongodb.org/display/DOCS/Advanced+Queries
        case Kinvey.Query.ALL:
          this._set(field, {$all: value});
          break;
        case Kinvey.Query.SIZE:
          this._set(field, {$size: value});
          break;

        // Other operator.
        default:
          throw new Error('Condition ' + condition + ' is not supported');
      }
    },

    /**
     * Resets query.
     *
     */
    reset: function() {
      this.query = null;
    },

    /**
     * Sets query limit.
     *
     * @param {number} limit Limit, or null to reset limit.
     */
    setLimit: function(limit) {
      this.limit = limit;
    },

    /**
     * Sets query skip.
     *
     * @param {number} skip Skip, or null to reset skip.
     */
    setSkip: function(skip) {
      this.skip = skip;
    },

    /**
     * Sets query sort.
     *
     * @param {string} field Field.
     * @param {number} direction Sort direction, or null to reset sort.
     */
    setSort: function(field, direction) {
      if(null == direction) {
        this.sort = null;// hard reset
        return;
      }

      // Set sort value.
      var value = Kinvey.Query.ASC === direction ? 1 : -1;
      this.sort = {};// reset
      this.sort[field] = value;
    },

    /**
     * Returns JSON representation. Used by JSON#stringify.
     *
     * @return {Object} JSON representation.
     */
    toJSON: function() {
      var result = {};
      this.limit && (result.limit = this.limit);
      this.skip && (result.skip = this.skip);
      this.sort && (result.sort = this.sort);
      this.query && (result.query = this.query);
      return result;
    },

    /**
     * Helper function to apply complex expression on field.
     *
     * @private
     */
    _set: function(field, expression) {
      this.query || (this.query = {});

      // Complex condition.
      this.query[field] instanceof Object || (this.query[field] = {});
      for(var operator in expression) {
        if(expression.hasOwnProperty(operator)) {
          this.query[field][operator] = expression[operator];
        }
      }
    }
  });

  // Define the Kinvey Aggregation class.
  Kinvey.Aggregation = Base.extend({
    /**
     * Creates a new aggregation.
     *
     * @example <code>
     * var aggregation = new Kinvey.Aggregation();
     * </code>
     *
     * @name Kinvey.Aggregation
     * @constructor
     * @param {Object} [builder] One of Kinvey.Aggregation.* builders.
     */
    constructor: function(builder) {
      this.builder = builder || Kinvey.Aggregation.factory();
    },

    /** @lends Kinvey.Aggregation# */

    /**
     * Adds key under condition.
     *
     * @param {string} key Key under condition.
     * @return {Kinvey.Aggregation} Current instance.
     */
    on: function(key) {
      this.builder.on(key);
      return this;
    },

    /**
     * Sets the finalize function. Currently not supported.
     *
     * @param {function(doc, counter)} fn Finalize function.
     * @return {Kinvey.Aggregation} Current instance.
     */
    setFinalize: function(fn) {
      this.builder.setFinalize(fn);
    },

    /**
     * Sets the initial counter object.
     *
     * @param {Object} counter Counter object.
     * @return {Kinvey.Aggregation} Current instance.
     */
    setInitial: function(counter) {
      this.builder.setInitial(counter);
      return this;
    },

    /**
     * Sets query.
     *
     * @param {Kinvey.Query} [query] query.
     * @throws {Error} On invalid instance.
     * @return {Kinvey.Aggregation} Current instance.
     */
    setQuery: function(query) {
      if(query && !(query instanceof Kinvey.Query)) {
        throw new Error('Query must be an instanceof Kinvey.Query');
      }
      this.builder.setQuery(query);
      return this;
    },

    /**
     * Sets the reduce function.
     *
     * @param {function(doc, counter)} fn Reduce function.
     * @return {Kinvey.Aggregation} Current instance.
     */
    setReduce: function(fn) {
      this.builder.setReduce(fn);
      return this;
    },

    /**
     * Returns JSON representation.
     *
     * @return {Object} JSON representation.
     */
    toJSON: function() {
      return this.builder.toJSON();
    }
  }, {
    /** @lends Kinvey.Aggregation */

    /**
     * Returns an aggregation builder.
     *
     * @return {Object} One of Kinvey.Aggregation.* builders.
     */
    factory: function() {
      // Currently, only the Mongo builder is supported.
      return new Kinvey.Aggregation.MongoBuilder();
    }
  });

  // Define the Kinvey Aggregation MongoBuilder class.
  Kinvey.Aggregation.MongoBuilder = Base.extend({
    // Fields.
    finalize: function() { },
    initial: { count: 0 },
    keys: null,
    reduce: function(doc, out) {
      out.count++;
    },
    query: null,

    /**
     * Creates a new MongoDB aggregation builder.
     *
     * @name Kinvey.Aggregation.MongoBuilder
     * @constructor
     */
    constructor: function() {
      // Set keys property explicitly on this instance, otherwise the prototype
      // will be overloaded.
      this.keys = {};
    },

    /** @lends Kinvey.Aggregation.MongoBuilder# */

    /**
     * Adds key under condition.
     *
     * @param {string} key Key under condition.
     * @return {Kinvey.Aggregation} Current instance.
     */
    on: function(key) {
      this.keys[key] = true;
    },

    /**
     * Sets the finalize function.
     *
     * @param {function(counter)} fn Finalize function.
     */
    setFinalize: function(fn) {
      this.finalize = fn;
    },

    /**
     * Sets the initial counter object.
     *
     * @param {Object} counter Counter object.
     */
    setInitial: function(counter) {
      this.initial = counter;
    },

    /**
     * Sets query.
     *
     * @param {Kinvey.Query} [query] query.
     */
    setQuery: function(query) {
      this.query = query;
      return this;
    },

    /**
     * Sets the reduce function.
     *
     * @param {function(doc, out)} fn Reduce function.
     */
    setReduce: function(fn) {
      this.reduce = fn;
    },

    /**
     * Returns JSON representation.
     *
     * @return {Object} JSON representation.
     */
    toJSON: function() {
      // Required fields.
      var result = {
        finalize: this.finalize.toString(),
        initial: this.initial,
        key: this.keys,
        reduce: this.reduce.toString()
      };

      // Optional fields.
      var query = this.query && this.query.toJSON().query;
      query && (result.condition = query);

      return result;
    }
  });

  /**
   * Kinvey Store namespace. Home to all stores.
   *
   * @namespace
   */
  Kinvey.Store = {
    /**
     * AppData store.
     *
     * @constant
     */
    APPDATA: 'appdata',

    /**
     * Cached store.
     *
     * @constant
     */
    CACHED: 'cached',

    /**
     * Offline store.
     *
     * @constant
     */
    OFFLINE: 'offline',

    /**
     * Returns store.
     *
     * @param {string} collection Collection name.
     * @param {string} name Store, or store name.
     * @param {Object} options Store options.
     * @return {Kinvey.Store.*} One of Kinvey.Store.*.
     */
    factory: function(name, collection, options) {
      // Create store by name.
      if(Kinvey.Store.CACHED === name) {
        return new Kinvey.Store.Cached(collection, options);
      }
      if(Kinvey.Store.OFFLINE === name) {
        return new Kinvey.Store.Offline(collection, options);
      }

      // By default, use the AppData store.
      return new Kinvey.Store.AppData(collection, options);
    }
  };

  // Define the Kinvey.Store.Rpc class.
  Kinvey.Store.Rpc = Base.extend({
    // Default options.
    options: {
      timeout: 10000,// Timeout in ms.

      success: function() { },
      error: function() { }
    },

    /**
     * Constructor
     *
     * @name Kinvey.Store.Rpc
     * @constructor
     * @param {Object} [options] Options.
     */
    constructor: function(options) {
      options && this.configure(options);
    },

    /**
     * Configures store.
     *
     * @param {Object} options
     * @param {function(response, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @param {integer} [options.timeout] Request timeout (in milliseconds).
     */
    configure: function(options) {
      'undefined' !== typeof options.timeout && (this.options.timeout = options.timeout);

      options.success && (this.options.success = options.success);
      options.error && (this.options.error = options.error);
    },

    /**
     * Resets password for a user.
     *
     * @param {string} username User name.
     * @param {Object} [options] Options.
     */
    resetPassword: function(username, options) {
      // Force use of application credentials by adding appc option.
      var url = this._getUrl([username, 'user-password-reset-initiate']);
      this._send('POST', url, null, merge(options, { appc: true }));
    },

    /**
     * Verifies e-mail for a user.
     *
     * @param {string} username User name.
     * @param {Object} [options] Options.
     */
    verifyEmail: function(username, options) {
      // Force use of application credentials by adding appc option.
      var url = this._getUrl([username, 'user-email-verification-initiate']);
      this._send('POST', url, null, merge(options, { appc: true }));
    },

    /**
     * Constructs URL.
     *
     * @private
     * @param {Array} parts URL parts.
     * @return {string} URL.
     */
    _getUrl: function(parts) {
      var url = '/rpc/' + Kinvey.appKey;

      // Add url parts.
      parts.forEach(function(part) {
        url += '/' + part;
      });

      // Android < 4.0 caches all requests aggressively. For now, work around
      // by adding a cache busting query string.
      return url + '?_=' + new Date().getTime();
    }
  });

  // Apply mixin.
  Xhr.call(Kinvey.Store.Rpc.prototype);

  // Define the Kinvey.Store.AppData class.
  Kinvey.Store.AppData = Base.extend({
    // Store name.
    name: Kinvey.Store.APPDATA,

    // Default options.
    options: {
      timeout: 10000,// Timeout in ms.

      success: function() { },
      error: function() { }
    },

    /**
     * Creates a new store.
     *
     * @name Kinvey.Store.AppData
     * @constructor
     * @param {string} collection Collection name.
     * @param {Object} [options] Options.
     */
    constructor: function(collection, options) {
      this.api = Kinvey.Store.AppData.USER_API === collection ? Kinvey.Store.AppData.USER_API : Kinvey.Store.AppData.APPDATA_API;
      this.collection = collection;

      // Options.
      options && this.configure(options);
    },

    /** @lends Kinvey.Store.AppData# */

    /**
     * Aggregates objects from the store.
     *
     * @param {Object} aggregation Aggregation.
     * @param {Object} [options] Options.
     */
    aggregate: function(aggregation, options) {
      var url = this._getUrl({ id: '_group' });
      this._send('POST', url, JSON.stringify(aggregation), options);
    },

    /**
     * Configures store.
     *
     * @param {Object} options
     * @param {function(response, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @param {integer} [options.timeout] Request timeout (in milliseconds).
     */
    configure: function(options) {
      'undefined' !== typeof options.timeout && (this.options.timeout = options.timeout);

      options.success && (this.options.success = options.success);
      options.error && (this.options.error = options.error);
    },

    /**
     * Logs in user.
     *
     * @param {Object} object
     * @param {Object} [options] Options.
     */
    login: function(object, options) {
      // OAuth1.0a hook to allow login without providing app key and secret.
      if(options.oauth1 && Kinvey.OAuth) {
        return Kinvey.OAuth.login(options.oauth1, object, options);
      }

      // Regular login.
      var url = this._getUrl({ id: 'login' });
      this._send('POST', url, JSON.stringify(object), options);
    },

    /**
     * Logs out user.
     *
     * @param {Object} object
     * @param {Object} [options] Options.
     */
    logout: function(object, options) {
      var url = this._getUrl({ id: '_logout' });
      this._send('POST', url, null, options);
    },

    /**
     * Queries the store for a specific object.
     *
     * @param {string} id Object id.
     * @param {Object} [options] Options.
     */
    query: function(id, options) {
      options || (options = {});

      // Force use of application credentials if pinging.
      null === id && (options.appc = true);

      var url = this._getUrl({ id: id, resolve: options.resolve });
      this._send('GET', url, null, options);
    },

    /**
     * Queries the store for multiple objects.
     *
     * @param {Object} query Query object.
     * @param {Object} [options] Options.
     */
    queryWithQuery: function(query, options) {
      options || (options = {});

      var url = this._getUrl({ query: query, resolve: options.resolve });
      this._send('GET', url, null, options);
    },

    /**
     * Removes object from the store.
     *
     * @param {Object} object Object to be removed.
     * @param {Object} [options] Options.
     */
    remove: function(object, options) {
      var url = this._getUrl({ id: object._id });
      this._send('DELETE', url, null, options);
    },

    /**
     * Removes multiple objects from the store.
     *
     * @param {Object} query Query object.
     * @param {Object} [options] Options.
     */
    removeWithQuery: function(query, options) {
      var url = this._getUrl({ query: query });
      this._send('DELETE', url, null, options);
    },

    /**
     * Saves object to the store.
     *
     * @param {Object} object Object to be saved.
     * @param {Object} [options] Options.
     */
    save: function(object, options) {
      // OAuth1.0a hook to allow login without providing app key and secret.
      if(options.oauth1 && Kinvey.Store.AppData.USER_API === this.api && Kinvey.OAuth) {
        return Kinvey.OAuth.create(options.oauth1, object, options);
      }

      // Regular save, create the object if nonexistent, update otherwise.
      var method = object._id ? 'PUT' : 'POST';

      var url = this._getUrl({ id: object._id });
      this._send(method, url, JSON.stringify(object), options);
    },

    /**
     * Encodes value for use in query string.
     *
     * @private
     * @param {*} value Value to be encoded.
     * @return {string} Encoded value.
     */
    _encode: function(value) {
      if(value instanceof Object) {
        value = JSON.stringify(value);
      }
      return encodeURIComponent(value);
    },

    /**
     * Constructs URL.
     *
     * @private
     * @param {Object} parts URL parts.
     * @return {string} URL.
     */
    _getUrl: function(parts) {
      var url = '/' + this.api + '/' + this._encode(Kinvey.appKey) + '/';

      // Only the AppData API has explicit collections.
      if(Kinvey.Store.AppData.APPDATA_API === this.api && null != this.collection) {
        url += this._encode(this.collection) + '/';
      }
      parts.id && (url += this._encode(parts.id));

      // Build query string.
      var param = [];
      if(null != parts.query) {
        // Required query parts.
        param.push('query=' + this._encode(parts.query.query || {}));

        // Optional query parts.
        parts.query.limit && param.push('limit=' + this._encode(parts.query.limit));
        parts.query.skip && param.push('skip=' + this._encode(parts.query.skip));
        parts.query.sort && param.push('sort=' + this._encode(parts.query.sort));
      }

      // Resolve references.
      if(parts.resolve) {
        param.push('resolve=' + parts.resolve.map(this._encode).join(','));
      }

      // Android < 4.0 caches all requests aggressively. For now, work around
      // by adding a cache busting query string.
      param.push('_=' + new Date().getTime());

      return url + '?' + param.join('&');
    }
  }, {
    // Path constants.
    APPDATA_API: 'appdata',
    USER_API: 'user'
  });

  // Apply mixin.
  Xhr.call(Kinvey.Store.AppData.prototype);

  // Grab database implementation.
  var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
  var IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || {};

  // Define the Database class.
  var Database = Base.extend({
    /**
     * Creates a new database.
     *
     * @name Database
     * @constructor
     * @private
     * @param {string} collection Collection name.
     */
    constructor: function(collection) {
      this.name = 'Kinvey.' + Kinvey.appKey;// Unique per app.
      this.collection = collection;
    },

    /** @lends Database# */

    // As a convenience, implement the store interface.

    /**
     * Aggregates objects in database.
     *
     * @param {Object} aggregation Aggregation object.
     * @param {Object} [options]
     */
    aggregate: function(aggregation, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(Database.AGGREGATION_STORE, Database.READ_ONLY, bind(this, function(txn) {
        // Retrieve aggregation.
        var key = this._getKey(aggregation);
        var req = txn.objectStore(Database.AGGREGATION_STORE).get(key);

        // Handle transaction status.
        txn.oncomplete = function() {
          // If result is null, return an error.
          var result = req.result;
          if(result) {
            options.success(result.response, { cached: true });
          }
          else {
            options.error(Kinvey.Error.DATABASE_ERROR, 'Aggregation is not in database.');
          }
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Queries the database for a specific object.
     *
     * @param {string} id Object id.
     * @param {Object} [options]
     */
    query: function(id, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(this.collection, Database.READ_ONLY, bind(this, function(txn) {
        // Retrieve object.
        var req = txn.objectStore(this.collection).get(id);

        // Handle transaction status.
        txn.oncomplete = bind(this, function() {
          // If result is null, return a not found error.
          var result = req.result;
          if(result) {
            // Resolve references before returning.
            this._resolve(result, options.resolve, function() {
              options.success(result, { cached: true });
            });
          }
          else {
            options.error(Kinvey.Error.ENTITY_NOT_FOUND, 'This entity could not be found.');
          }
        });
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Queries the database for multiple objects.
     *
     * @param {Object} query Query object.
     * @param {Object} [options]
     */
    queryWithQuery: function(query, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction([this.collection, Database.QUERY_STORE], Database.READ_ONLY, bind(this, function(txn) {
        // Prepare response.
        var response = [];

        // Retrieve query.
        var key = this._getKey(query);
        var req = txn.objectStore(Database.QUERY_STORE).get(key);
        req.onsuccess = bind(this, function() {
          var result = req.result;
          if(result) {
            // Open store.
            var store = txn.objectStore(this.collection);

            // Retrieve objects.
            result.response.forEach(function(id, i) {
              var req = store.get(id);
              req.onsuccess = function() {
                response[i] = req.result;// Insert in order.
              };
            });
          }
        });

        // Handle transaction status.
        txn.oncomplete = bind(this, function() {
          if(req.result) {
            // Remove undefined (non-existant objects) array members.
            response = response.filter(function(value) {
              return 'undefined' !== typeof value;
            });

            // Resolve references before returning.
            var pending = response.length;
            if(0 !== pending) {// Items found.
              response.forEach(function(object) {
                this._resolve(object, options.resolve, function() {
                  !--pending && options.success(response, { cached: true });
                });
              }, this);
            }
            else {// No items found, return directly.
              options.success(response, { cached: true });
            }
          }
          else {
            options.error(Kinvey.Error.DATABASE_ERROR, 'Query is not in database.');
          }
        });
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Removes object from the database.
     *
     * @param {Object} object Object to be removed.
     * @param {Object} [options]
     */
    remove: function(object, options) {
      options = this._options(options);

      // Open transaction. Only open transaction store if we need it.
      var stores = [this.collection];
      !options.silent && stores.push(Database.TRANSACTION_STORE);
      this._transaction(stores, Database.READ_WRITE, bind(this, function(txn) {
        // Open store.
        var store = txn.objectStore(this.collection);

        // Retrieve object, to see if there is any metadata we need.
        var req = store.get(object._id);
        req.onsuccess = bind(this, function() {
          var result = req.result || object;

          // Remove object and add transaction.
          store['delete'](result._id);
          !options.silent && this._addTransaction(txn.objectStore(Database.TRANSACTION_STORE), result);
        });

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(null, { cached: true });
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Removes multiple objects from the database.
     *
     * @param {Object} query Query object.
     * @param {Object} [options]
     */
    removeWithQuery: function(query, options) {
      // First, retrieve all items, so we can remove them one by one.
      this.queryWithQuery(query, merge(options, {
        success: bind(this, function(list) {
          // Open transaction. Only open transaction store if we need it.
          var stores = [this.collection, Database.QUERY_STORE];
          !options.silent && stores.push(Database.TRANSACTION_STORE);
          this._transaction(stores, Database.READ_WRITE, bind(this, function(txn) {
            // Remove query.
            var key = this._getKey(query);
            txn.objectStore(Database.QUERY_STORE)['delete'](key);

            // Remove objects and add transaction.
            var store = txn.objectStore(this.collection);
            list.forEach(function(object) {
              store['delete'](object._id);
            });
            !options.silent && this._addTransaction(txn.objectStore(Database.TRANSACTION_STORE), list);

            // Handle transaction status.
            txn.oncomplete = function() {
              options.success(null, { cached: true });
            };
            txn.onabort = txn.onerror = function() {
              options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
            };
          }), options.error);
        })
      }));
    },

    /**
     * Saves object to the database.
     *
     * @param {Object} object Object to be saved.
     * @param {Object} [options]
     */
    save: function(object, options) {
      options = this._options(options);

      // Open transaction. Only open transaction store if we need it.
      var stores = [this.collection];
      !options.silent && stores.push(Database.TRANSACTION_STORE);
      this._transaction(stores, Database.READ_WRITE, bind(this, function(txn) {
        // Open store.
        var store = txn.objectStore(this.collection);

        // Store object in store. If entity is new, assign an ID. This is done
        // manually to overcome IndexedDBs approach to only assigns integers.
        object._id || (object._id = this._getRandomId());

        // Retrieve object to see if there is any metadata we need.
        var req = store.get(object._id);
        req.onsuccess = bind(this, function() {
          var result = req.result;
          if(result) {
            null == object._acl && result._acl && (object._acl = result._acl);
            null == object._kmd && result._kmd && (object._kmd = result._kmd);
          }

          // Save object and add transaction.
          txn.objectStore(this.collection).put(object);
          !options.silent && this._addTransaction(txn.objectStore(Database.TRANSACTION_STORE), object);
        });

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(object, { cached: true });
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    // Data management.

    /**
     * Clears the entire database.
     *
     * @param {Object} [options]
     */
    clear: function(options) {
      options = this._options(options);

      // Delete all collections through a mutation operation.
      this._mutate(function(db) {
        var store;
        while(null != (store = db.objectStoreNames.item(0))) {
          db.deleteObjectStore(store);
        }
     }, function() {
       // Success callback should be called without arguments.
       options.success();
     }, options.error);
    },

    /**
     * Retrieves multiple objects at once.
     *
     * @param {Array} list List of object ids.
     * @param {Object} [options]
     */
    multiQuery: function(list, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(this.collection, Database.READ_ONLY, bind(this, function(txn) {
        // Prepare response.
        var response = {};

        // Open store.
        var store = txn.objectStore(this.collection);

        // Retrieve objects.
        list.forEach(function(id) {
          var req = store.get(id);
          req.onsuccess = function() {
            response[id] = req.result || null;
          };
        });

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(response, { cached: true });
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Removes multiple objects at once.
     *
     * @param {Array} list List of object ids.
     * @param {Object} [options]
     */
    multiRemove: function(list, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(this.collection, Database.READ_WRITE, bind(this, function(txn) {
        // Open store.
        var store = txn.objectStore(this.collection);

        // Remove objects.
        list.forEach(function(id) {
          store['delete'](id);
        });

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(null, { cached: true });
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Writes data to database.
     *
     * @param {string} type Data type.
     * @param {*} key Data key.
     * @param {*} data Data.
     * @param {Object} [options]
     */
    put: function(type, key, data, options) {
      // Do not record transactions.
      options = merge(options, { silent: true });

      // Take advantage of store methods.
      switch(type) {
        case 'aggregate':
          this._putAggregation(key, data, options);
          break;
        case 'query':// query, remove and save.
          null !== data ? this._putSave(data, options) : this.remove(key, options);
          break;
        case 'queryWithQuery':// queryWithQuery and removeWithQuery.
          null !== data ? this._putQueryWithQuery(key, data, options) : this.removeWithQuery(key, options);
          break;
      }
    },

    /**
     * Writes aggregation to database.
     *
     * @private
     * @param {Object} aggregation Aggregation object.
     * @param {Array} response Aggregation.
     * @param {Object} [options]
     */
    _putAggregation: function(aggregation, response, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(Database.AGGREGATION_STORE, Database.READ_WRITE, bind(this, function(txn) {
        // Open store.
        var store = txn.objectStore(Database.AGGREGATION_STORE);

        // Save or delete aggregation.
        var key = this._getKey(aggregation);
        null !== response ? store.put({
          aggregation: key,
          response: response
        }) : store['delete'](key);

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(response);
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Writes query and resulting objects to database.
     *
     * @private
     * @param {Object} query Query object.
     * @param {Array} response Response.
     * @param {Object} [options]
     */
    _putQueryWithQuery: function(query, response, options) {
      options = this._options(options);

      // Define handler to save the query and its result.
      var result = [];// Result is a list of object ids.
      var progress = bind(this, function() {
        // Open transaction.
        this._transaction(Database.QUERY_STORE, Database.READ_WRITE, bind(this, function(txn) {
          // Save query and its results.
          txn.objectStore(Database.QUERY_STORE).put({
            query: this._getKey(query),
            response: result
          });

          // Handle transaction status.
          txn.oncomplete = function() {
            options.success(response);
          };
          txn.onabort = txn.onerror = function() {
            options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
          };
        }), options.error);
      });

      // Quick way out, return if no objects are to be saved.
      var pending = response.length;
      if(0 === response.length) {
        return progress();
      }

      // Save objects (in parallel).
      response.forEach(function(object, i) {
        this.put('query', null, object, merge(options, {
          success: function(response) {
            result[i] = response._id;// Insert in order.
            !--pending && progress();
          },
          error: function() {
            !--pending && progress();
          }
        }));
      }, this);
    },

    /**
     * Writes object to database.
     *
     * @private
     * @param {Object} object Object.
     * @param {Object} options Options.
     */
    _putSave: function(object, options) {
      // Extract references from object, if specified.
      if(options.resolve && options.resolve.length) {
        this._saveReferences(object, options.resolve, bind(this, function(response) {
          this.save(response, merge(options, { resolve: [], silent: true }));
        }));
        return;
      }

      // No references, save at once. Always silent.
      this.save(object, merge(options, { silent: true }));
    },

    // Transaction management.

    /**
     * Returns pending transactions.
     *
     * @param {object} [options]
     */
    getTransactions: function(options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(Database.TRANSACTION_STORE, Database.READ_ONLY, bind(this, function(txn) {
        // Prepare response.
        var response = {};

        // Open store.
        var store = txn.objectStore(Database.TRANSACTION_STORE);

        // If this instance is tied to a particular collection, retrieve
        // transactions for that collection only.
        if(Database.TRANSACTION_STORE !== this.collection) {
          var req = store.get(this.collection);
          req.onsuccess = bind(this, function() {
            var result = req.result;
            result && (response[this.collection] = result.transactions);
          });
        }
        else {// Iterate over all collections, and collect their transactions.
          var it = store.openCursor();
          it.onsuccess = function() {
            var cursor = it.result;
            if(cursor) {
              var result = cursor.value;
              response[result.collection] = result.transactions;

              // Proceed.
              cursor['continue']();
            }
          };
        }

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(response);
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Removes transactions.
     *
     * @param {Object} transactions
     * @param {Object} [options]
     */
    removeTransactions: function(transactions, options) {
      options = this._options(options);

      // Open transaction.
      this._transaction(Database.TRANSACTION_STORE, Database.READ_WRITE, bind(this, function(txn) {
        // Open store.
        var store = txn.objectStore(Database.TRANSACTION_STORE);

        // Retrieve transactions for this collection.
        var req = store.get(this.collection);
        req.onsuccess = bind(this, function() {
          var result = req.result;
          if(result) {
            // Remove all committed transactions.
            transactions.forEach(function(id) {
              delete result.transactions[id];
            });

            // Update store.
            Object.keys(result.transactions).length ? store.put(result) : store['delete'](this.collection);
          }
        });

        // Handle transaction status.
        txn.oncomplete = function() {
          options.success(transactions, { cached: true });
        };
        txn.onabort = txn.onerror = function() {
          options.error(Kinvey.Error.DATABASE_ERROR, txn.error || 'Failed to execute transaction.');
        };
      }), options.error);
    },

    /**
     * Adds a transaction for object to transaction store.
     *
     * @private
     * @param {IDBObjectStore} store Transaction store.
     * @param {Array|Object} objects Object(s) under transaction.
     */
    _addTransaction: function(store, objects) {
      objects instanceof Array || (objects = [objects]);

      // Append new transactions to this collection.
      var req = store.get(this.collection);
      req.onsuccess = bind(this, function() {
        var result = req.result || {
          collection: this.collection,
          transactions: {}
        };

        // Add and save transaction. Add timestamp as value.
        objects.forEach(function(object) {
          result.transactions[object._id] = object._kmd ? object._kmd.lmt : null;
        });
        store.put(result);
      });
    },

    // Reference resolve methods.

    /**
     * Resolves object references.
     *
     * @private
     * @param {Object} object
     * @param {Array} resolve Fields to resolve.
     * @param {function(response)} complete Complete callback.
     */
    _resolve: function(object, resolve, complete) {
      resolve = resolve ? resolve.slice(0) : [];// Copy by value.

      // Define function to resolve all desired references.
      var resolveSingleReference = bind(this, function() {
        if(resolve[0]) {// If there is more to be resolved, do that first.
          var segments = resolve.shift().split('.');
          this._resolveSingleSegment(segments, object, resolveSingleReference);
        }
        else {// All desired references are resolved.
          complete(object);
        }
      });
      resolveSingleReference();// Trigger.
    },

    /**
     * Resolves a single reference in a document.
     *
     * @private
     * @param {Array} segments Field path to be resolved.
     * @param {Object} doc Document to search in.
     * @param {function()} complete Complete callback.
     */
    _resolveSingleSegment: function(segments, doc, complete) {
      // If the path is not fully traversed, do that first.
      if(segments[0]) {
        var field = segments.shift();

        // Check and resolve top-level reference. Otherwise: descent deeper.
        if(doc.hasOwnProperty(field) && null != doc[field]) {
          // First case: field is a (unresolved) reference.
          if('KinveyRef' === doc[field]._type && null != doc[field]._collection && null != doc[field]._id) {
            if('undefined' === typeof doc[field]._obj) {// Unresolved reference.
              // Query for reference.
              var db = this.collection === doc[field]._collection ? this : new Database(doc[field]._collection);
              db.query(doc[field]._id, {
                resolve: [segments.join('.')],// Relative to reference.
                success: function(response) {
                  doc[field]._obj = response;
                  complete();// Proceed.
                },
                error: function() {// Reference could not be resolved.
                  doc[field]._obj = null;
                  complete();// Proceed.
                }
              });
              return;// Terminate, proceed after query() completes.
            }

            // Already resolved reference, descent into.
            if(null !== doc[field]._obj) {// Resolved reference, descent into.
              this._resolveSingleSegment(segments, doc[field]._obj, complete);
            }
            else {// Resolved reference is null, dead-end.
              complete();
            }
          }

          // Second case: field is an array. Only immediate members are resolved.
          else if(doc[field] instanceof Array) {
            // Define function to resolve a member in the aray.
            var resolveArrayReference = bind(this, function(i) {
              // If there is more to resolve, do that first.
              if(i < doc[field].length) {
                var member = doc[field][i];
                if(null != member && 'KinveyRef' === member._type && null != member._collection && null != member._id && 'undefined' === typeof member._obj) {
                  // Unresolved reference found, resolve.
                  var db = this.collection === member._collection ? this : new Database(member._collection);
                  db.query(member._id, {
                    success: function(response) {
                      doc[field][i]._obj = response;
                      resolveArrayReference(++i);// Proceed.
                    },
                    error: function() {// Reference could not be resolved.
                      doc[field][i]._obj = null;
                      resolveArrayReference(++i);// Proceed.
                    }
                  });
                }
                else {// Not a reference.
                  resolveArrayReference(++i);// Proceed.
                }
              }

              // Otherwise, array is traversed.
              else {
                complete();// Proceed.
              }
            });
            return resolveArrayReference(0);// Trigger.
          }

          // Third and last case: field is a scalar or plain object. Descent.
          else {
            this._resolveSingleSegment(segments, doc[field], complete);
          }
        }
        else {// doc does not have field, skip reference.
          complete();
        }
      }
      else {// Path is fully traversed, all work has been done.
        complete();
      }
    },

    /**
     * Extract and saves references from object attributes.
     *
     * @private
     * @param {Object} object Attributes.
     * @param {Array} references List of references.
     * @param {function(response)} complete Complete callback.
     */
    _saveReferences: function(object, references, complete) {
      // Because references could be nested, first search for all references
      // and store them in a stack.
      var stack = [];

      // If there are references to resolve, do that first.
      while(references[0]) {
        var segments = references.shift().split('.');
        var doc = object;

        // Descent into doc.
        while(segments[0]) {
          var field = segments.shift();

          if(doc.hasOwnProperty(field) && null != doc[field]) {
            // First case: field is a embedded document.
            if('KinveyRef' === doc[field]._type && null != doc[field]._collection && null != doc[field]._id && null != doc[field]._obj) {
              if(-1 === stack.indexOf(doc[field])) {// Add to stack (once).
                stack.push(doc[field]);
              }

              // Descent into document.
              doc = doc[field]._obj;
            }

            // Second case: field is an array. Only save immediate members.
            else if(doc[field] instanceof Array) {
              for(var i in doc[field]) {
                var member = doc[field][i];
                if(null != member && 'KinveyRef' === member._type && null != member._collection && null != member._id && null != member._obj) {
                  stack.push(doc[field][i]);// Add to stack.
                }
              }
            }

            // Third case: field is a plain object.
            else if(doc[field] instanceof Object) {
              doc = doc[field];// Descent into doc.
            }
          }
        }
      }

      // All references are now in stack. Save them by starting with the last
      // item. This will ensure nested references are saved first, so we can
      // remove the _obj property afterwards.
      var save = bind(this, function(i) {
        if(i >= 0) {// If the stack is not empty yet, save.
          var item = stack[i];

          // Save item.
          var db = this.collection === item._collection ? this : new Database(item._collection);
          db.put('query', null, item._obj, {
            success: function() {
              delete item._obj;// Delete embedded document.
              save(--i);
            },
            error: function() {// Delete embedded document.
              delete item._obj;
              save(--i);
            }
          });
        }
        else {// Stack is empty, return object without embedded references.
          complete(object);
        }
      });
      save(stack.length - 1);// Trigger.
    },

    // IndexedDB convenience methods.

    /**
     * Returns a random id. Actually, this method concatenates the current
     * timestamp with a random string.
     *
     * @return {string} Random id.
     */
    _getRandomId: function() {
      return new Date().getTime().toString() + Math.random().toString(36).substring(2, 12);
    },

    /**
     * Returns key.
     *
     * @private
     * @param {Object} object
     * @return {string} Key.
     */
    _getKey: function(object) {
      object.collection = this.collection;
      return JSON.stringify(object);
    },

    /**
     * Returns schema for database store.
     *
     * @private
     * @param {string} store Store name.
     * @return {Object} Schema.
     */
    _getSchema: function(store) {
      // Map defining primary key for metadata stores. If the store is not
      // a metadata store, simply return _id (see below).
      var key = {};
      key[Database.TRANSACTION_STORE] = 'collection';
      key[Database.AGGREGATION_STORE] = 'aggregation';
      key[Database.QUERY_STORE] = 'query';

      // Return schema.
      return {
        name: store,
        options: { keyPath: key[store] || '_id' }
      };
    },

    /**
     * Mutates the database schema.
     *
     * @private
     * @param {function()} upgrade Upgrade callback.
     * @param {function(database)} success Success callback.
     * @param {function(error)} error Failure callback.
     */
    _mutate: function(upgrade, success, error) {
      this._open(null, null, bind(this, function(database) {
        var version = parseInt(database.version || 0, 10) + 1;
        this._open(version, upgrade, success, error);
      }), error);
    },

    /**
     * Opens the database.
     *
     * @private
     * @param {integer} [version] Database version.
     * @param {function()} [update] Upgrade callback.
     * @param {function(database)} success Success callback.
     * @param {function(error)} error Failure callback.
     */
    _open: function(version, upgrade, success, error) {
      // Extend success callback to handle method concurrency.
      var fnSuccess = success;
      success = bind(this, function(db) {
        // If idle, handle next request in queue.
        if(Database.isIdle) {
          var next = Database.queue.shift();
          next && this._open.apply(this, next);
        }
        fnSuccess(db);
      });

      // Concurrency control, allow only one request at the time, queue others.
      if(!Database.isIdle) {
        return Database.queue.push(arguments);
      }

      // Reuse if possible.
      if(null != Database.instance && (null == version || Database.instance.version === version)) {
        return success(Database.instance);
      }

      // No reuse, we need to do more complicated stuff in a blocking manner.
      Database.isIdle = false;

      // If we only want to change the version, check for outdated setVersion.
      var req;
      if(Database.instance && Database.instance.setVersion) {// old.
        req = Database.instance.setVersion(version);
        req.onsuccess = function() {
          upgrade(Database.instance);

          // @link https://groups.google.com/a/chromium.org/forum/?fromgroups#!topic/chromium-html5/VlWI87JFKMk
          var txn = req.result;
          txn.oncomplete = function() {
            // We're done, reset flag.
            Database.isIdle = true;
            success(Database.instance);
          };
        };
        req.onblocked = req.onerror = function() {
          error(Kinvey.Error.DATABASE_ERROR, req.error || 'Mutation error.');
        };
        return;
      }

      // If no version is specified, use the latest version.
      if(null == version) {
        req = indexedDB.open(this.name);
      }
      else {// open specific version
        req = indexedDB.open(this.name, version);
      }

      // Handle database status.
      req.onupgradeneeded = function() {
        Database.instance = req.result;
        upgrade && upgrade(Database.instance);
      };
      req.onsuccess = bind(this, function() {
        Database.instance = req.result;

        // Handle versionchange when another process alters it.
        Database.instance.onversionchange = function() {
          if(Database.instance) {
            Database.instance.close();
            Database.instance = null;
          }
        };

        // We're done, reset flag.
        Database.isIdle = true;
        success(Database.instance);
      });
      req.onblocked = req.onerror = function() {
        error(Kinvey.Error.DATABASE_ERROR, 'Failed to open the database.');
      };
    },

    /**
     * Returns complete options object.
     *
     * @param {Object} options Options.
     * @return {Object} Options.
     */
    _options: function(options) {
      options || (options = {});

      // Create convenient error handler shortcut.
      var fnError = options.error || function() { };
      options.error = function(error, description) {
        fnError({
          error: error,
          description: description || error,
          debug: ''
        }, { cached: true });
      };
      options.success || (options.success = function() { });

      return options;
    },

    /**
     * Opens transaction for store(s).
     *
     * @private
     * @param {Array|string} stores Store name(s).
     * @param {string} mode Transaction mode.
     * @param {function(transaction)} success Success callback.
     * @param {function(error)} error Failure callback.
     */
    _transaction: function(stores, mode, success, error) {
      !(stores instanceof Array) && (stores = [stores]);

      // Open database.
      this._open(null, null, bind(this, function(db) {
        // Make sure all stores exist.
        var missingStores = [];
        stores.forEach(function(store) {
          if(!db.objectStoreNames.contains(store)) {
            missingStores.push(store);
          }
        });

        // Create missing stores.
        if(0 !== missingStores.length) {
          this._mutate(bind(this, function(db) {
            missingStores.forEach(function(store) {
              // Since another process may already have created the store
              // concurrently, check again whether the store exists.
              if(!db.objectStoreNames.contains(store)) {
                var schema = this._getSchema(store);
                db.createObjectStore(schema.name, schema.options);
              }
            }, this);
          }), function(db) {// Return a transaction.
            success(db.transaction(stores, mode));
          }, error);
        }
        else {// Return a transaction.
          success(db.transaction(stores, mode));
        }
      }), error);
    }
  }, {
    /** @lends Database */

    // Transaction modes.
    READ_ONLY: IDBTransaction.READ_ONLY || 'readonly',
    READ_WRITE: IDBTransaction.READ_WRITE || 'readwrite',

    // Stores.
    AGGREGATION_STORE: '_aggregations',
    QUERY_STORE: '_queries',
    TRANSACTION_STORE: '_transactions',

    // Concurrency mechanism to queue database open requests.
    isIdle: true,
    queue: [],

    // For performance reasons, keep one database open for the whole app.
    instance: null
  });

  // Define the Kinvey.Store.Cached class.
  Kinvey.Store.Cached = Base.extend({
    // Store name.
    name: Kinvey.Store.CACHED,

    // Store options.
    options: {
      policy: null,
      store: { },// AppData store options.

      success: function() { },
      error: function() { },
      complete: function() { }
    },

    /**
     * Creates new cached store.
     *
     * @name Kinvey.Store.Cached
     * @constructor
     * @param {string} collection Collection.
     * @param {Object} [options] Options.
     */
    constructor: function(collection, options) {
      this.collection = collection;

      // This class bridges between the AppData store and local database.
      this.db = new Database(collection);
      this.store = Kinvey.Store.factory(Kinvey.Store.APPDATA, collection);

      // Options.
      this.options.policy = Kinvey.Store.Cached.NETWORK_FIRST;// Default policy.
      options && this.configure(options);
    },

    /** @lends Kinvey.Store.Cached# */

    /**
     * Aggregates objects from the store.
     *
     * @param {Object} aggregation Aggregation object.
     * @param {Object} [options] Options.
     */
    aggregate: function(aggregation, options) {
      options = this._options(options);
      this._read('aggregate', aggregation, options);
    },

    /**
     * Configures store.
     *
     * @param {Object} options
     * @param {string} [options.policy] Cache policy.
     * @param {Object} [options.store] Store options.
     * @param {function(response, info)} [options.success] Success callback.
     * @param {function(error, info)} [options.error] Failure callback.
     * @param {function()} [options.complete] Complete callback.
     */
    configure: function(options) {
      // Store options.
      options.policy && (this.options.policy = options.policy);
      options.store && (this.options.store = options.store);

      // Callback options.
      options.success && (this.options.success = options.success);
      options.error && (this.options.error = options.error);
      options.complete && (this.options.complete = options.complete);
    },

    /**
     * Logs in user.
     *
     * @param {Object} object
     * @param {Object} [options] Options.
     */
    login: function(object, options) {
      options = this._options(options);
      this.store.login(object, options);
    },

    /**
     * Logs out user.
     *
     * @param {Object} object
     * @param {Object} [options] Options.
     */
    logout: function(object, options) {
      options = this._options(options);
      this.store.logout(object, options);
    },

    /**
     * Queries the store for a specific object.
     *
     * @param {string} id Object id.
     * @param {Object} [options] Options.
     */
    query: function(id, options) {
      options = this._options(options);
      this._read('query', id, options);
    },

    /**
     * Queries the store for multiple objects.
     *
     * @param {Object} query Query object.
     * @param {Object} [options] Options.
     */
    queryWithQuery: function(query, options) {
      options = this._options(options);
      this._read('queryWithQuery', query, options);
    },

    /**
     * Removes object from the store.
     *
     * @param {Object} object Object to be removed.
     * @param {Object} [options] Options.
     */
    remove: function(object, options) {
      options = this._options(options);
      this._write('remove', object, options);
    },

    /**
     * Removes multiple objects from the store.
     *
     * @param {Object} query Query object.
     * @param {Object} [options] Options.
     */
    removeWithQuery: function(query, options) {
      options = this._options(options);
      this._write('removeWithQuery', query, options);
    },

    /**
     * Saves object to the store.
     *
     * @param {Object} object Object to be saved.
     * @param {Object} [options] Options.
     */
    save: function(object, options) {
      options = this._options(options);
      this._write('save', object, options);
    },

    /**
     * Returns full options object.
     *
     * @private
     * @param {Object} options Options.
     * @return {Object} Options.
     */
    _options: function(options) {
      options || (options = {});

      // Store options.
      options.policy || (options.policy = this.options.policy);
      this.store.configure(options.store || this.options.store);

      // Callback options.
      options.success || (options.success = this.options.success);
      options.error || (options.error = this.options.error);
      options.complete || (options.complete = this.options.complete);

      return options;
    },

    /**
     * Performs read operation, according to the caching policy.
     *
     * @private
     * @param {string} operation Operation. One of aggregation, query or
     *          queryWithQuery.
     * @param {*} arg Operation argument.
     * @param {Object} options Options.
     */
    _read: function(operation, arg, options) {
      // Extract primary and secondary store from cache policy.
      var networkFirst = this._shouldCallNetworkFirst(options.policy);
      var primaryStore = networkFirst ? this.store : this.db;
      var secondaryStore = networkFirst ? this.db : this.store;

      // Extend success handler to cache network response.
      var invoked = false;
      var fnSuccess = options.success;
      options.success = bind(this, function(response, info) {
        // Determine whether application-level handler should be triggered.
        var secondPass = invoked;
        if(!invoked || this._shouldCallBothCallbacks(options.policy)) {
          invoked = true;
          fnSuccess(response, info);
        }

        // Update cache in the background. This is only part of the complete
        // step.
        if(info.network && this._shouldUpdateCache(options.policy)) {
          var fn = function() { options.complete(); };
          this.db.put(operation, arg, response, merge(options, { success: fn, error: fn }));
        }

        // Trigger complete callback on final pass.
        else if(secondPass || !this._shouldCallBoth(options.policy)) {
          options.complete();
        }
      });

      // Handle according to policy.
      primaryStore[operation](arg, merge(options, {
        success: bind(this, function(response, info) {
          options.success(response, info);

          // Only call secondary store if the policy allows calling both.
          if(this._shouldCallBoth(options.policy)) {
            options.error = function() {// Reset error, we already succeeded.
              options.complete();
            };
            secondaryStore[operation](arg, options);
          }
        }),
        error: bind(this, function(error, info) {
          // Switch to secondary store if the caching policy allows a fallback.
          if(this._shouldCallFallback(options.policy)) {
            var fnError = options.error;
            options.error = function(error, info) {
              fnError(error, info);
              options.complete();
            };
            secondaryStore[operation](arg, options);
          }
          else {// no fallback, error out here.
            options.error(error, info);
            options.complete();
          }
        })
      }));
    },

    /**
     * Returns whether both the local and network store should be used.
     *
     * @private
     * @param {string} policy Cache policy.
     * @return {boolean}
     */
    _shouldCallBoth: function(policy) {
      var accepted = [Kinvey.Store.Cached.CACHE_FIRST, Kinvey.Store.Cached.BOTH];
      return -1 !== accepted.indexOf(policy);
    },

    /**
     * Returns whether both the local and network success handler should be invoked.
     *
     * @private
     * @param {string} policy Cache policy.
     * @return {boolean}
     */
    _shouldCallBothCallbacks: function(policy) {
      return Kinvey.Store.Cached.BOTH === policy;
    },

    /**
     * Returns whether another store should be tried on initial failure.
     *
     * @private
     * @param {string} policy Cache policy.
     * @return {boolean}
     */
    _shouldCallFallback: function(policy) {
      var accepted = [Kinvey.Store.Cached.CACHE_FIRST_NO_REFRESH, Kinvey.Store.Cached.NETWORK_FIRST];
      return this._shouldCallBoth(policy) || -1 !== accepted.indexOf(policy);
    },

    /**
     * Returns whether network store should be accessed first.
     *
     * @private
     * @param {string} policy Cache policy.
     * @return {boolean}
     */
    _shouldCallNetworkFirst: function(policy) {
      var accepted = [Kinvey.Store.Cached.NO_CACHE, Kinvey.Store.Cached.NETWORK_FIRST];
      return -1 !== accepted.indexOf(policy);
    },

    /**
     * Returns whether the cache should be updated.
     *
     * @private
     * @param {string} policy Cache policy.
     * @return {boolean}
     */
    _shouldUpdateCache: function(policy) {
      var accepted = [Kinvey.Store.Cached.CACHE_FIRST, Kinvey.Store.Cached.NETWORK_FIRST, Kinvey.Store.Cached.BOTH];
      return -1 !== accepted.indexOf(policy);
    },

    /**
     * Performs write operation, and handles the response according to the
     * caching policy.
     *
     * @private
     * @param {string} operation Operation. One of remove, removeWithquery or save.
     * @param {*} arg Operation argument.
     * @param {Object} options Options.
     */
    _write: function(operation, arg, options) {
      // Extend success handler to cache network response.
      var fnError = options.error;
      var fnSuccess = options.success;
      options.success = bind(this, function(response, info) {
        // Trigger application-level handler.
        fnSuccess(response, info);

        // Update cache in the background. This is the only part of the complete
        // step.
        if(this._shouldUpdateCache(options.policy)) {
          // The cache handle defines how the cache is updated. This differs
          // per operation.
          var cacheHandle = {
            remove: ['query', arg, null],
            removeWithQuery: ['queryWithQuery', arg, null]
          };

          // Upon save, store returns the document. Cache this, except for
          // when a user (with password!) is returned.
          if('user' !== this.collection && null != response) {
            cacheHandle.save = ['query', response._id, response];
          }

          // If a cache handle is defined, append the callbacks and trigger.
          if(cacheHandle[operation]) {
            cacheHandle[operation].push({
              success: function() { options.complete(); },
              error: function() { options.complete(); }
            });
            this.db.put.apply(this.db, cacheHandle[operation]);
            return;
          }
        }
        options.complete();
      });
      options.error = function(error, info) {
        // On error, there is nothing we can do except trigger both handlers.
        fnError(error, info);
        options.complete();
      };

      // Perform operation.
      this.store[operation](arg, options);
    }
  }, {
    /** @lends Kinvey.Store.Cached */

    // Cache policies.
    /**
     * No Cache policy. Ignore cache and only use the network.
     *
     * @constant
     */
    NO_CACHE: 'nocache',

    /**
     * Cache Only policy. Don't use the network.
     *
     * @constant
     */
    CACHE_ONLY: 'cacheonly',

    /**
     * Cache First policy. Pull from cache if available, otherwise network.
     *
     * @constant
     */
    CACHE_FIRST: 'cachefirst',

    /**
     * Cache First No Refresh policy. Pull from cache if available, otherwise
     * network. Does not update cache in the background.
     *
     * @constant
     */
    CACHE_FIRST_NO_REFRESH: 'cachefirst-norefresh',

    /**
     * Network first policy. Pull from network if available, otherwise cache.
     *
     * @constant
     */
    NETWORK_FIRST: 'networkfirst',

    /**
     * Both policy. Pull the cache copy (if it exists), then pull from network.
     *
     * @constant
     */
    BOTH: 'both',

    /**
     * Clears the entire cache.
     *
     * @param {Object} [options] Options.
     */
    clear: function(options) {
      new Database(null).clear(options);
    }
  });

  // Define the Kinvey.Store.Offline class.
  Kinvey.Store.Offline = Kinvey.Store.Cached.extend({
    // Store name.
    name: Kinvey.Store.OFFLINE,

    /**
     * Creates a new offline store.
     *
     * @name Kinvey.Store.Offline
     * @constructor
     * @extends Kinvey.Store.Cached
     * @param {string} collection Collection.
     * @param {Object} [options] Options.
     * @throws {Error} On usage with User API.
     */
    constructor: function(collection, options) {
      // The User API cannot be used offline for security issues.
      if(Kinvey.Store.AppData.USER_API === collection) {
        throw new Error('The User API cannot be used with OfflineStore');
      }

      // Call parent constructor.
      Kinvey.Store.Cached.prototype.constructor.call(this, collection, options);
    },

    /** @lends Kinvey.Store.Offline# */

    /**
     * Configures store.
     *
     * @override
     * @see Kinvey.Store.Cached#configure
     * @param {Object} options
     * @param {function(collection, cached, remote, options)} [options.conflict]
     *          Conflict resolution handler.
     */
    configure: function(options) {
      Kinvey.Store.Cached.prototype.configure.call(this, options);
      options.conflict && (this.options.conflict = options.conflict);
    },

    /**
     * Removes object from the store.
     *
     * @override
     * @see Kinvey.Store.Cached#remove
     */
    remove: function(object, options) {
      options = this._options(options);
      this.db.remove(object, this._wrap(object, options));
    },

    /**
     * Removes multiple objects from the store.
     *
     * @override
     * @see Kinvey.Store.Cached#removeWithQuery
     */
    removeWithQuery: function(query, options) {
      options = this._options(options);
      this.db.removeWithQuery(query, this._wrap(null, options));
    },

    /**
     * Saves object to the store.
     *
     * @override
     * @see Kinvey.Store.Cached#save
     */
    save: function(object, options) {
      options = this._options(options);
      this.db.save(object, this._wrap(object, options));
    },

    /**
     * Returns complete options object.
     *
     * @private
     * @override
     * @see Kinvey.Store.Cached#_options
     */
    _options: function(options) {
      options = Kinvey.Store.Cached.prototype._options.call(this, options);

      // Override the caching policy when offline.
      if(!Kinvey.Sync.isOnline) {
        options.policy = Kinvey.Store.Cached.CACHE_ONLY;
      }
      return options;
    },

    /**
     * Wraps success and error handlers to include synchronization.
     *
     * @private
     * @param {Object} scope Synchronization scope.
     * @param {Object} options Options.
     * @return {Object}
     */
    _wrap: function(scope, options) {
      // Wrap options for handling synchronization.
      return merge(options, {
        success: bind(this, function(response) {
          options.success(response, { offline: true });

          // If the scope parameter is defined, use the response to scope the
          // the synchronization to this object only.
          var opts = {
            conflict: options.conflict,
            success: options.complete,
            error: options.complete
          };
          if(scope) {
            // Fallback to scope itself if response is null.
            return Kinvey.Sync.object(this.collection, response || scope, opts);
          }

          // No scope, synchronize the whole collection.
          Kinvey.Sync.collection(this.collection, opts);
        }),
        error: function(error) {// Cannot perform synchronization, so terminate.
          options.error(error, { offline: true });
          options.complete();
        }
      });
    }
  });

  // User context used to perform synchronization with.
  var context = null;

  /**
   * Kinvey Sync namespace definition. This namespace manages the data
   * synchronization between local and remote backend.
   *
   * @namespace
   */
  Kinvey.Sync = {

    // Properties.

    /**
     * Environment status.
     *
     */
    isOnline: navigator.onLine,

    /**
     * Default options.
     *
     */
    options: {
      conflict: null,
      store: { },
      start: function() { },
      success: function() { },
      error: function() { }
    },

    // Methods.

    /**
     * Configures sync.
     *
     * @param {Object} options
     * @param {Object} options.store Store options.
     * @param {function(collection, cached, remote, options)} options.conflict
     *          Conflict resolution callback.
     * @param {function()} options.start Start callback.
     * @param {function(status)} options.success Success callback.
     * @param {function(error)} options.error Failure callback.
     */
    configure: function(options) {
      options.conflict && (Kinvey.Sync.options.conflict = options.conflict);
      options.store && (Kinvey.Sync.options.store = options.store);
      options.start && (Kinvey.Sync.options.start = options.start);
      options.success && (Kinvey.Sync.options.success = options.success);
      options.error && (Kinvey.Sync.options.error = options.error);
    },

    /**
     * Sets environment to offline mode.
     *
     */
    offline: function() {
      Kinvey.Sync.isOnline = false;
    },

    /**
     * Sets environment to online mode. This will trigger synchronization.
     *
     */
    online: function() {
      if(!Kinvey.Sync.isOnline) {
        // If a user context was specified, login prior to synchronization.
        if(null != context) {
          var user = new Kinvey.User();
          user.login(context.username, context.password, {
            success: function() {
              Kinvey.Sync.isOnline = true;
              Kinvey.Sync.syncWith(null);// Reset.
              Kinvey.Sync.application();
            },
            error: function(e, info) {
              // Failed to login the user. Do not trigger synchronization,
              // invoke the sychronization error handler instead.
              Kinvey.Sync.isOnline = true;
              Kinvey.Sync.syncWith(null);// Reset.
              Kinvey.Sync.options.error(e, info);
            }
          });
        }
        else {// No user context specified, continue with synchronization.
          Kinvey.Sync.isOnline = true;
          Kinvey.Sync.application();
        }
      }
    },

    /**
     * Synchronizes application.
     *
     * @param {Object} [options] Options.
     */
    application: function(options) {
      options = Kinvey.Sync._options(options);
      Kinvey.Sync.isOnline ? new Synchronizer(options).application({
        start: Kinvey.Sync.options.start || function() { }
      }) : options.error({
        error: Kinvey.Error.NO_NETWORK,
        description: 'There is no active network connection.',
        debug: 'Synchronization requires an active network connection.'
      });
    },

    /**
     * Synchronizes collection.
     *
     * @param {string} name Collection name.
     * @param {Object} [options] Options.
     */
    collection: function(name, options) {
      options = Kinvey.Sync._options(options);
      Kinvey.Sync.isOnline ? new Synchronizer(options).collection(name) : options.error({
        error: Kinvey.Error.NO_NETWORK,
        description: 'There is no active network connection.',
        debug: 'Synchronization requires an active network connection.'
      });
    },

    /**
     * Returns number of pending synchronization.
     *
     * @param {Object} [options] Options.
     * @param {function(count)} options.success Success callback.
     * @param {function(error)} options.error Failure callback.
     * @param {string} options.collection Collection to count.
     */
    count: function(options) {
      // Explicitly set handlers to avoid calling the Kinvey.Sync default ones.
      options || (options = {});
      options.success || (options.success = function() { });
      options.error || (options.error = function() { });

      // Invoke synchronizer count.
      new Synchronizer(options).count(options.collection || null);
    },

    /**
     * Synchronizes object.
     *
     * @param {string} collection Collection name.
     * @param {Object} object Object.
     * @param {Object} [options] Options.
     */
    object: function(collection, object, options) {
      options = Kinvey.Sync._options(options);
      Kinvey.Sync.isOnline ? new Synchronizer(options).object(collection, object) : options.error({
        error: Kinvey.Error.NO_NETWORK,
        description: 'There is no active network connection.',
        debug: 'Synchronization requires an active network connection.'
      });
    },

    /**
     * Sets user context to perform synchronization with.
     *
     * @param {string} username User name, or null to reset the context.
     * @param {string} [password] User password.
     */
    syncWith: function(username, password) {
      context = null != username ? { username: username, password: password } : null;
    },

    // Built-in conflict resolution handlers.

    /**
     * Client always wins conflict resolution. Prioritizes cached copy over
     * remote copy.
     *
     * @param {string} collection Collection name.
     * @param {Object} cached Cached copy.
     * @param {Object} remote Remote copy.
     * @param {Object} options
     * @param {function(copy)} options.success Success callback.
     * @param {function()} options.error Failure callback.
     */
    clientAlwaysWins: function(collection, cached, remote, options) {
      options.success(cached);
    },

    /**
     * Leaves conflicts as is.
     *
     * @param {string} collection Collection name.
     * @param {Object} cached Cached copy.
     * @param {Object} remote Remote copy.
     * @param {Object} options
     * @param {function(copy)} options.success Success callback.
     * @param {function()} options.error Failure callback.
     */
    ignore: function(collection, cached, remote, options) {
      options.error();
    },

    /**
     * Server always wins conflict resolution. Prioritizes remote copy over
     * cached copy.
     *
     * @param {string} collection Collection name.
     * @param {Object} cached Cached copy.
     * @param {Object} remote Remote copy.
     * @param {Object} options
     * @param {function(copy)} options.success Success callback.
     * @param {function()} options.error Failure callback.
     */
    serverAlwaysWins: function(collection, cached, remote, options) {
      options.success(remote);
    },

    // Helper methods.

    /**
     * Returns complete options object.
     *
     * @private
     * @param {Object} [options] Options.
     */
    _options: function(options) {
      options || (options = {});
      options.store || (options.store = Kinvey.Sync.options.store);
      options.conflict || (options.conflict = Kinvey.Sync.options.conflict || Kinvey.Sync.ignore);
      options.success || (options.success = Kinvey.Sync.options.success);
      options.error || (options.error = Kinvey.Sync.options.error);
      return options;
    }
  };

  // Listen to browser events to adapt the environment to.
  window.addEventListener('online', Kinvey.Sync.online, false);
  window.addEventListener('offline', Kinvey.Sync.offline, false);

  // Define the Synchronizer class.
  var Synchronizer = Base.extend({
    /**
     * Creates a new synchronizer.
     *
     * @name Synchronizer
     * @constructor
     * @private
     * @param {Object} options
     * @param {Object} options.store Store options.
     * @param {function(collection, cached, remote, options)} options.conflict
     *          Conflict resolution callback.
     * @param {function()} options.start Start callback.
     * @param {function(status)} options.success Success callback.
     * @param {function(error)} options.error Failure callback.
     */
    constructor: function(options) {
      // Configure.
      this.store = options.store;// AppData store options.
      this.conflict = options.conflict;
      this.success = options.success;
      this.error = options.error;
    },

    /** @lends Synchronizer# */

    /**
     * Synchronizes all application data.
     *
     * @param {Object} [options]
     * @param {function()} options.start Start callback.
     */
    application: function(options) {
      // Trigger start callback.
      options && options.start && options.start();

      // Retrieve pending transactions.
      new Database(Database.TRANSACTION_STORE).getTransactions({
        success: bind(this, function(transactions) {
          // Prepare response.
          var response = {};

          // If there are no pending transactions, return here.
          var collections = Object.keys(transactions);
          var pending = collections.length;
          if(0 === pending) {
            return this.success(response);
          }

          // There are pending transactions. Define a handler to aggregate the
          // responses per synchronized collection.
          var handler = bind(this, function(collection) {
            return bind(this, function(result) {
              // Add results to response.
              result && (response[collection] = result);

              // When all collections are synchronized, terminate the
              // algorithm.
              !--pending && this.success(response);
            });
          });

          // Synchronizing each collection (in parallel).
          collections.forEach(function(collection) {
            this._collection(collection, transactions[collection], handler(collection));
          }, this);
        }),
        error: this.error
      });
    },

    /**
     * Synchronizes a collection.
     *
     * @param {string} name Collection name.
     */
    collection: function(name) {
      // Retrieve pending transactions.
      new Database(name).getTransactions({
        success: bind(this, function(transactions) {
          // If there are no pending transactions, return here.
          if(null == transactions[name]) {
            return this.success({});
          }

          // There are pending transactions. Synchronize.
          this._collection(name, transactions[name], bind(this, function(result) {
            // Wrap result in collection property.
            var response = {};
            result && (response[name] = result);

            // Terminate the algorithm.
            this.success(response);
          }));
        }),
        error: this.error
      });
    },

    /**
     * Returns number of pending transactions.
     *
     * @param {string} collection Collection name, or null for all collections.
     */
    count: function(collection) {
      // Retrieve pending transactions.
      new Database(collection || Database.TRANSACTION_STORE).getTransactions({
        success: bind(this, function(transactions) {
          var count = 0;
          if(collection) {// Return count for a single collection?
            var partial = transactions[collection];
            count = partial ? Object.keys(partial).length : 0;
          }
          else {// Aggregate counts of all collections.
            Object.keys(transactions).forEach(function(collection) {
              count += Object.keys(transactions[collection]).length;
            });
          }

          // Terminate.
          this.success(count);
        }),
        error: this.error
      });
    },

    /**
     * Synchronizes an object.
     *
     * @param {string} collection Collection name.
     * @param {Object} object Object.
     */
    object: function(collection, object) {
      // Extract object id.
      var id = object._id;

      // Retrieve pending transactions for the collection.
      var db = new Database(collection);
      db.getTransactions({
        success: bind(this, function(transactions) {
          // If there is no pending transaction for this object, return here.
          if(null == transactions[collection] || !transactions[collection].hasOwnProperty(id)) {
            return this.success({});
          }

          // There is a pending transaction. Make sure this is the only
          // transaction we handle.
          var value = transactions[collection][id];
          transactions = {};
          transactions[id] = value;

          // Classify and commit.
          this._classifyAndCommit(collection, transactions, {
            db: db,
            objects: [id],
            store: Kinvey.Store.factory(Kinvey.Store.APPDATA, collection, this.store)
          }, bind(this, function(result) {
            // Wrap result in collection property.
            var response = {};
            response[collection] = result;

            // Terminate the algorithm.
            this.success(response);
          }));
        }),
        error: this.error
      });
    },

    /**
     * Classifies each transaction as committable, conflicted or canceled.
     *
     * @private
     * @param {string} collection Collection name.
     * @param {Object} transactions Pending transactions.
     * @param {Object} data
     * @param {Database} data.db Database.
     * @param {Array} data.objects Object ids under transaction.
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(committable, conflicted, canceled)} complete Complete callback.
     */
    _classify: function(collection, transactions, data, complete) {
      // Retrieve all objects under transaction.
      this._retrieve(data.objects, data, bind(this, function(cached, remote) {
        // Prepare response.
        var committable = {};
        var conflicted = [];

        // Define handler to handle the classification process below.
        var pending = data.objects.length;
        var handler = function(id) {
          return {
            success: function(copy) {
              // The user may have erroneously altered the id, which we
              // absolutely need to undo here.
              copy && (copy._id = id);

              // Add to set and continue.
              committable[id] = copy;
              !--pending && complete(committable, conflicted, []);
            },
            error: function(collection, cached, remote) {
              // Add to set and continue.
              conflicted.push(id);
              !--pending && complete(committable, conflicted, []);
            }
          };
        };

        // Classify each transaction (in parallel). First, handle objects
        // available both in the store and database.
        remote.forEach(function(object) {
          var id = object._id;
          this._object(collection, transactions[id], cached[id], object, handler(id));

          // Housekeeping, remove from cached to not loop it again below.
          delete cached[id];
        }, this);

        // Next, handle objects only available in the database.
        Object.keys(cached).forEach(function(id) {
          this._object(collection, transactions[id], cached[id], null, handler(id));
        }, this);
      }), function() {// An error occurred. Mark all transactions as cancelled.
        complete([], [], data.objects);
      });
    },

    /**
     * Classifies and commits all transactions for a collection.
     *
     * @private
     * @param {string} collection Collection name.
     * @param {Object} transactions Pending transactions.
     * @param {Object} data
     * @param {Database} data.db Database.
     * @param {Array} data.objects Object ids under transaction.
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(result)} complete Complete callback.
     */
    _classifyAndCommit: function(collection, transactions, data, complete) {
      this._classify(collection, transactions, data, bind(this, function(committable, conflicted, canceled) {
        this._commit(committable, data, function(committed, cCanceled) {
          // Merge sets and return.
          complete({
            committed: committed,
            conflicted: conflicted,
            canceled: canceled.concat(cCanceled)
          });
        });
      }));
    },

    /**
     * Processes synchronization for collection.
     *
     * @private
     * @param {string} name Collection name.
     * @param {Object} transactions List of pending transactions.
     * @param {function(result)} complete Complete callback.
     */
    _collection: function(name, transactions, complete) {
      // If there are no pending transactions, return here.
      var objects = Object.keys(transactions);
      if(0 === objects.length) {
        return complete();
      }

      // There are pending transactions. Classify and commit all.
      this._classifyAndCommit(name, transactions, {
        db: new Database(name),
        objects: objects,
        store: Kinvey.Store.factory(Kinvey.Store.APPDATA, name, this.store)
      }, complete);
    },

    /**
     * Commits a series of transactions.
     *
     * @private
     * @param {Object} objects Objects to commit.
     * @param {Object} data
     * @param {Database} data.db Database.
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(committed, canceled)} complete Complete callback.
     */
    _commit: function(objects, data, complete) {
      // If there are no transactions to be committed, return here.
      data.objects = Object.keys(objects);
      if(0 === data.objects.length) {
        return complete([ ], [ ]);
      }

      // There are transactions to be committed. Distinguish between updates
      // and removals.
      var updates = [ ];
      var removals = [ ];
      data.objects.forEach(function(id) {
        var object = objects[id];
        null != object ? updates.push(object) : removals.push(id);
      });

      // Prepare response.
      var committed = [];
      var canceled = [];
      var pending = 2;// Updates and removals.
      var handler = function(partialCommitted, partialCanceled) {
        committed = committed.concat(partialCommitted);
        canceled = canceled.concat(partialCanceled);

        // On complete, remove transactions from database. Failure at this
        // stage is non-fatal.
        if(!--pending) {
          var fn = function() {
            complete(committed, canceled);
          };
          data.db.removeTransactions(committed, {
            success: fn,
            error: fn
          });
        }
      };

      // Commit updates and removals (in parallel).
      this._commitUpdates(updates, data, handler);
      this._commitRemovals(removals, data, handler);
    },

    /**
     * Commits object.
     *
     * @private
     * @param {Object} object Object to commit.
     * @param {Object} data
     * @param {Database} data.db Database.
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(committed, canceled)} complete Complete callback.
     */
    _commitObject: function(object, data, complete) {
      // First, commit to the store.
      data.store.save(object, {
        success: function(response) {
          // Next, commit response to database. Failure is non-fatal.
          var fn = function() {
            complete([response._id], []);
          };
          data.db.put('query', response._id, response, {
            success: fn,
            error: fn
          });
        },
        error: function() {
          complete([], [object._id]);
        }
      });
    },

    /**
     * Commits a series of removal transactions.
     *
     * @private
     * @param {Array} objects Objects to commit.
     * @param {Object} data
     * @param {Database} data.db Database.
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(committed, canceled)} complete Complete callback.
     */
    _commitRemovals: function(objects, data, complete) {
      // If there are no transactions, return here.
      if(0 === objects.length) {
        return complete([], []);
      }

      // Define remote commit success handler.
      var success = function() {
        // Second step is to commit to the database. Failure is non-fatal.
        var fn = function() {
          complete(objects, []);
        };
        data.db.multiRemove(objects, {
          success: fn,
          error: fn
        });
      };

      // There are transactions to commit. First, commit to the store.
      var query = new Kinvey.Query().on('_id').in_(objects);
      data.store.removeWithQuery(query.toJSON(), {
        success: success,
        error: function() {
          // Mark all as canceled and return.
          complete([ ], objects);
        }
      });
    },

    /**
     * Commits a series of update transactions.
     *
     * @private
     * @param {Array} objects Objects to commit.
     * @param {Object} data
     * @param {Database} data.db Database.
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(committed, canceled)} complete Complete callback.
     */
    _commitUpdates: function(objects, data, complete) {
      // If there are no transactions, return here.
      if(0 === objects.length) {
        return complete([], []);
      }

      // Prepare response.
      var committed = [ ];
      var canceled = [ ];

      // Define progress handler.
      var pending = objects.length;
      var handler = function(uCommitted, uCanceled) {
        // Add to set and continue.
        committed = committed.concat(uCommitted);
        canceled = canceled.concat(uCanceled);
        !--pending && complete(committed, canceled);
      };

      // Commit each transaction (in parallel).
      objects.forEach(function(object) {
        this._commitObject(object, data, handler);
      }, this);
    },

    /**
     * Processes synchronization for object.
     *
     * @private
     * @param {string} collection Collection name.
     * @param {string} transaction Transaction timestamp.
     * @param {Object} cached Cached copy.
     * @param {Object} remote Remote copy.
     * @param {Object} options
     * @param {function(copy)} options.success Success handler.
     * @param {function(collection, cached, remote)} options.error Failure callback.
     */
    _object: function(collection, transaction, cached, remote, options) {
      // If remote copy does not exist, or timestamps match; cached copy wins.
      if(null === remote || transaction === remote._kmd.lmt) {
        return options.success(cached);
      }

      // At this point, cached and remote are in conflicting state. Invoke the
      // conflict resolution callback to resolve the conflict. Optionally, the
      // handler can maintain the conflicting state by triggering the error
      // handler.
      this.conflict(collection, cached, remote, {
        success: options.success,
        error: function() {
          options.error(collection, cached, remote);
        }
      });
    },

    /**
     * Retrieves objects from store and database.
     *
     * @param {Array} object List of object ids.
     * @param {Object} data
     * @param {Database} data.db Database
     * @param {Kinvey.Store.AppData} data.store Store.
     * @param {function(cached, remote)} success Success callback.
     * @param {function()} error Failure callback.
     */
    _retrieve: function(objects, data, success, error) {
      // Prepare response.
      var cached = [];
      var remote = [];

      // Define handler to handle store and database responses.
      var pending = 2;// store and database.
      var handler = function() {
        return {
          success: function(list, info) {
            // Add to set and continue.
            info.network ? remote = list : cached = list;
            !--pending && success(cached, remote);
          },
          error: function() {
            // Failed to retrieve objects. This is a fatal error.
            error();
            error = function() { };// Unset, to avoid invoking it twice.
          }
        };
      };

      // Retrieve objects (in parallel).
      var query = new Kinvey.Query().on('_id').in_(objects);
      data.store.queryWithQuery(query.toJSON(), handler());
      data.db.multiQuery(objects, handler());
    }
  });


  /**
   * Kinvey OAuth namespace.
   *
   * @namespace
   */
  Kinvey.OAuth = {
    // BL API uses the user collection.
    api: Kinvey.Store.AppData.USER_API,

    // Default options.
    options: {
      timeout: 10000,// Timeout in ms.

      success: function() { },
      error: function() { }
    },

    /**
     * Processes request token, and obtains access token for OAuth provider.
     *
     * @param {string} provider OAuth provider.
     * @param {Object} response Response attributes.
     * @param {Object} [options]
     * @param {string} options.oauth_token_secret OAuth1.0a token secret.
     * @param {function(tokens)} options.success Success callback.
     * @param {function(error)} options.error Failure callback.
     */
    accessToken: function(provider, response, options) {
      response || (response = {});
      options || (options = {});

      // Handle both OAuth1.0a and OAuth 2.0 protocols.
      if(response.access_token && response.expires_in) {// OAuth 2.0.
        options.success && options.success({
          access_token: response.access_token,
          expires_in: response.expires_in
        });
      }
      else if(response.oauth_token && response.oauth_verifier && options.oauth_token_secret) {
        // OAuth 1.0a requires a request to verify the tokens.
        this._send('POST', this._getUrl(provider, 'verifyToken'), JSON.stringify({
          oauth_token: response.oauth_token,
          oauth_token_secret: options.oauth_token_secret,
          oauth_verifier: response.oauth_verifier
        }), options);
      }
      else {// Error, most likely the user did not grant authorization.
        options.error && options.error({
          error: Kinvey.Error.RESPONSE_PROBLEM,
          description: 'User did not grant authorization to the OAuth provider.',
          debug: response.denied || response.error || response.oauth_problem
        });
      }
    },

    /**
     * Creates a new user given its OAuth access tokens. OAuth1.0a only.
     *
     * @param {string} provider OAuth provider.
     * @param {Object} attr User attributes.
     * @param {Object} [options]
     * @param {function(response, info)} options.success Success callback.
     * @param {function(error, info)} options.error Failure callback.
     */
    create: function(provider, attr, options) {
      this._send('POST', this._getUrl(provider, 'create'), JSON.stringify(attr), options);
    },

    /**
     * Logs in an existing user given its OAuth access tokens. OAuth1.0a only.
     *
     * @param {string} provider OAuth provider.
     * @param {Object} attr User attributes.
     * @param {Object} [options]
     * @param {function(response, info)} options.success Success callback.
     * @param {function(error, info)} options.error Failure callback.
     */
    login: function(provider, attr, options) {
      this._send('POST', this._getUrl(provider, 'login'), JSON.stringify(attr), options);
    },

    /**
     * Requests an OAuth token.
     *
     * @param {string} provider OAuth provider.
     * @param {Object} [options]
     * @param {string} options.redirect Redirect URL.
     * @param {function(tokens, info)} options.success Success callback.
     * @param {function(error, info)} options.error Failure callback.
     * @throws {Error} On invalid provider.
     */
    requestToken: function(provider, options) {
      options || (options = {});
      this._send('POST', this._getUrl(provider, 'requestToken'), JSON.stringify({
        redirect: options.redirect || '',
        state: options.state || null
      }), options);
    },

    /**
     * Constructs URL.
     *
     * @private
     * @param {string} provider OAuth provider.
     * @param {string} step OAuth step.
     * @return {string} URL.
     */
    _getUrl: function(provider, step) {
      return '/' + this.api + '/' + encodeURIComponent(Kinvey.appKey) + '/' +
       '?provider=' + encodeURIComponent(provider) +
       '&step=' + encodeURIComponent(step) +
       '&_=' + new Date().getTime();// Android < 4.0 cache bust.
    },

    /**
     * Tokenizes string.
     *
     * @private
     * @param {string} string Token string.
     * @example foo=bar&baz=qux => { foo: 'bar', baz: 'qux' }
     */
    _tokenize: function(string) {
      var tokens = {};
      string.split('&').forEach(function(pair) {
        var segments = pair.split('=', 2).map(decodeURIComponent);
        segments[0] && (tokens[segments[0]] = segments[1]);
      });
      return tokens;
    }
  };

  // Apply mixin.
  Xhr.call(Kinvey.OAuth);

  /**
   * UI helper function to perform the entire OAuth flow for a provider.
   *
   * @param {string} provider OAuth provider.
   * @param {Object} [options]
   * @param {string} options.redirect Redirect URL.
   * @param {function(tokens)} options.success Success callback.
   * @param {function(error)} options.error Failure callback.
   */
  Kinvey.OAuth.signIn = function(provider, options) {
    options || (options = {});
    options.popup || (options.popup = 'menubar=no,toolbar=no,location=no,personalbar=no');

    // Open pop-up here, as otherwise chances are they are blocked.
    var popup = window.open('about:blank', 'KinveyOAuth', options.popup);

    // Step 1: obtain a request token.
    var state = Math.random().toString(36).substr(2, 12);// CSRF protection.
    this.requestToken(provider, merge(options, {
      redirect: options.redirect || document.location.toString(),
      state: state,
      success: bind(this, function(tokens) {
        // Step 2: redirect pop-up to OAuth provider.
        popup.location.href = tokens.url;

        // Wait for pop-up to return to our domain.
        var interval = 500;// Half a second.
        var elapsed = 0;// Time elapsed.
        var timer = window.setInterval(bind(this, function() {
          if(null == popup.location) {// Pop-up closed unexpectedly.
            window.clearTimeout(timer);// Stop waiting.
            options.error && options.error({
              error: Kinvey.Error.RESPONSE_PROBLEM,
              description: 'The user closed the OAuth pop-up.',
              debug: ''
            });
          }
          else if(elapsed > options.timeout) {// Timeout.
            window.clearTimeout(timer);// Stop waiting.
            popup.close();// Close pop-up.
            options.error && options.error({
              error: Kinvey.Error.RESPONSE_PROBLEM,
              description: 'The OAuth pop-up timed out.',
              debug: 'The user waited too long to grant authorization to the OAuth provider.'
            });
          }
          else if(popup.location.host) {// Returned to our domain.
            window.clearTimeout(timer);// Stop waiting.

            // Save location.
            var response = this._tokenize(
              popup.location.search.substring(1) + '&' + popup.location.hash.substring(1)
            );
            popup.close();// Close pop-up.

            // Step 3: process token.
            if(response.state && response.state !== state) {// Validate state.
              options.error && options.error({
                error: Kinvey.Error.RESPONSE_PROBLEM,
                description: 'The state parameter did not match the expected state.',
                debug: 'This error could be the result of a cross-site-request-forgery attack.'
              });
            }
            else {
              this.accessToken(provider, response, merge(options, {
                oauth_token_secret: tokens.oauth_token_secret// OAuth1.0a.
              }));
            }
          }

          // Update elapsed time.
          elapsed += interval;
        }), interval);
      }),
      error: function(response, info) {
        popup.close();// Close pop-up.
        options.error && options.error(response, info);
      }
    }));
  };

}.call(this));
/*Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.*/
/*Version:1.11*/
/*! jQuery v@1.8.0 jquery.com | jquery.org/license */
(function(a,b){function cy(a){return f.isWindow(a)?a:a.nodeType===9?a.defaultView||a.parentWindow:!1}function cu(a){if(!cj[a]){var b=c.body,d=f("<"+a+">").appendTo(b),e=d.css("display");d.remove();if(e==="none"||e===""){ck||(ck=c.createElement("iframe"),ck.frameBorder=ck.width=ck.height=0),b.appendChild(ck);if(!cl||!ck.createElement)cl=(ck.contentWindow||ck.contentDocument).document,cl.write((f.support.boxModel?"<!doctype html>":"")+"<html><body>"),cl.close();d=cl.createElement(a),cl.body.appendChild(d),e=f.css(d,"display"),b.removeChild(ck)}cj[a]=e}return cj[a]}function ct(a,b){var c={};f.each(cp.concat.apply([],cp.slice(0,b)),function(){c[this]=a});return c}function cs(){cq=b}function cr(){setTimeout(cs,0);return cq=f.now()}function ci(){try{return new a.ActiveXObject("Microsoft.XMLHTTP")}catch(b){}}function ch(){try{return new a.XMLHttpRequest}catch(b){}}function cb(a,c){a.dataFilter&&(c=a.dataFilter(c,a.dataType));var d=a.dataTypes,e={},g,h,i=d.length,j,k=d[0],l,m,n,o,p;for(g=1;g<i;g++){if(g===1)for(h in a.converters)typeof h=="string"&&(e[h.toLowerCase()]=a.converters[h]);l=k,k=d[g];if(k==="*")k=l;else if(l!=="*"&&l!==k){m=l+" "+k,n=e[m]||e["* "+k];if(!n){p=b;for(o in e){j=o.split(" ");if(j[0]===l||j[0]==="*"){p=e[j[1]+" "+k];if(p){o=e[o],o===!0?n=p:p===!0&&(n=o);break}}}}!n&&!p&&f.error("No conversion from "+m.replace(" "," to ")),n!==!0&&(c=n?n(c):p(o(c)))}}return c}function ca(a,c,d){var e=a.contents,f=a.dataTypes,g=a.responseFields,h,i,j,k;for(i in g)i in d&&(c[g[i]]=d[i]);while(f[0]==="*")f.shift(),h===b&&(h=a.mimeType||c.getResponseHeader("content-type"));if(h)for(i in e)if(e[i]&&e[i].test(h)){f.unshift(i);break}if(f[0]in d)j=f[0];else{for(i in d){if(!f[0]||a.converters[i+" "+f[0]]){j=i;break}k||(k=i)}j=j||k}if(j){j!==f[0]&&f.unshift(j);return d[j]}}function b_(a,b,c,d){if(f.isArray(b))f.each(b,function(b,e){c||bD.test(a)?d(a,e):b_(a+"["+(typeof e=="object"?b:"")+"]",e,c,d)});else if(!c&&f.type(b)==="object")for(var e in b)b_(a+"["+e+"]",b[e],c,d);else d(a,b)}function b$(a,c){var d,e,g=f.ajaxSettings.flatOptions||{};for(d in c)c[d]!==b&&((g[d]?a:e||(e={}))[d]=c[d]);e&&f.extend(!0,a,e)}function bZ(a,c,d,e,f,g){f=f||c.dataTypes[0],g=g||{},g[f]=!0;var h=a[f],i=0,j=h?h.length:0,k=a===bS,l;for(;i<j&&(k||!l);i++)l=h[i](c,d,e),typeof l=="string"&&(!k||g[l]?l=b:(c.dataTypes.unshift(l),l=bZ(a,c,d,e,l,g)));(k||!l)&&!g["*"]&&(l=bZ(a,c,d,e,"*",g));return l}function bY(a){return function(b,c){typeof b!="string"&&(c=b,b="*");if(f.isFunction(c)){var d=b.toLowerCase().split(bO),e=0,g=d.length,h,i,j;for(;e<g;e++)h=d[e],j=/^\+/.test(h),j&&(h=h.substr(1)||"*"),i=a[h]=a[h]||[],i[j?"unshift":"push"](c)}}}function bB(a,b,c){var d=b==="width"?a.offsetWidth:a.offsetHeight,e=b==="width"?1:0,g=4;if(d>0){if(c!=="border")for(;e<g;e+=2)c||(d-=parseFloat(f.css(a,"padding"+bx[e]))||0),c==="margin"?d+=parseFloat(f.css(a,c+bx[e]))||0:d-=parseFloat(f.css(a,"border"+bx[e]+"Width"))||0;return d+"px"}d=by(a,b);if(d<0||d==null)d=a.style[b];if(bt.test(d))return d;d=parseFloat(d)||0;if(c)for(;e<g;e+=2)d+=parseFloat(f.css(a,"padding"+bx[e]))||0,c!=="padding"&&(d+=parseFloat(f.css(a,"border"+bx[e]+"Width"))||0),c==="margin"&&(d+=parseFloat(f.css(a,c+bx[e]))||0);return d+"px"}function bo(a){var b=c.createElement("div");bh.appendChild(b),b.innerHTML=a.outerHTML;return b.firstChild}function bn(a){var b=(a.nodeName||"").toLowerCase();b==="input"?bm(a):b!=="script"&&typeof a.getElementsByTagName!="undefined"&&f.grep(a.getElementsByTagName("input"),bm)}function bm(a){if(a.type==="checkbox"||a.type==="radio")a.defaultChecked=a.checked}function bl(a){return typeof a.getElementsByTagName!="undefined"?a.getElementsByTagName("*"):typeof a.querySelectorAll!="undefined"?a.querySelectorAll("*"):[]}function bk(a,b){var c;b.nodeType===1&&(b.clearAttributes&&b.clearAttributes(),b.mergeAttributes&&b.mergeAttributes(a),c=b.nodeName.toLowerCase(),c==="object"?b.outerHTML=a.outerHTML:c!=="input"||a.type!=="checkbox"&&a.type!=="radio"?c==="option"?b.selected=a.defaultSelected:c==="input"||c==="textarea"?b.defaultValue=a.defaultValue:c==="script"&&b.text!==a.text&&(b.text=a.text):(a.checked&&(b.defaultChecked=b.checked=a.checked),b.value!==a.value&&(b.value=a.value)),b.removeAttribute(f.expando),b.removeAttribute("_submit_attached"),b.removeAttribute("_change_attached"))}function bj(a,b){if(b.nodeType===1&&!!f.hasData(a)){var c,d,e,g=f._data(a),h=f._data(b,g),i=g.events;if(i){delete h.handle,h.events={};for(c in i)for(d=0,e=i[c].length;d<e;d++)f.event.add(b,c,i[c][d])}h.data&&(h.data=f.extend({},h.data))}}function bi(a,b){return f.nodeName(a,"table")?a.getElementsByTagName("tbody")[0]||a.appendChild(a.ownerDocument.createElement("tbody")):a}function U(a){var b=V.split("|"),c=a.createDocumentFragment();if(c.createElement)while(b.length)c.createElement(b.pop());return c}function T(a,b,c){b=b||0;if(f.isFunction(b))return f.grep(a,function(a,d){var e=!!b.call(a,d,a);return e===c});if(b.nodeType)return f.grep(a,function(a,d){return a===b===c});if(typeof b=="string"){var d=f.grep(a,function(a){return a.nodeType===1});if(O.test(b))return f.filter(b,d,!c);b=f.filter(b,d)}return f.grep(a,function(a,d){return f.inArray(a,b)>=0===c})}function S(a){return!a||!a.parentNode||a.parentNode.nodeType===11}function K(){return!0}function J(){return!1}function n(a,b,c){var d=b+"defer",e=b+"queue",g=b+"mark",h=f._data(a,d);h&&(c==="queue"||!f._data(a,e))&&(c==="mark"||!f._data(a,g))&&setTimeout(function(){!f._data(a,e)&&!f._data(a,g)&&(f.removeData(a,d,!0),h.fire())},0)}function m(a){for(var b in a){if(b==="data"&&f.isEmptyObject(a[b]))continue;if(b!=="toJSON")return!1}return!0}function l(a,c,d){if(d===b&&a.nodeType===1){var e="data-"+c.replace(k,"-$1").toLowerCase();d=a.getAttribute(e);if(typeof d=="string"){try{d=d==="true"?!0:d==="false"?!1:d==="null"?null:f.isNumeric(d)?+d:j.test(d)?f.parseJSON(d):d}catch(g){}f.data(a,c,d)}else d=b}return d}function h(a){var b=g[a]={},c,d;a=a.split(/\s+/);for(c=0,d=a.length;c<d;c++)b[a[c]]=!0;return b}var c=a.document,d=a.navigator,e=a.location,f=function(){function J(){if(!e.isReady){try{c.documentElement.doScroll("left")}catch(a){setTimeout(J,1);return}e.ready()}}var e=function(a,b){return new e.fn.init(a,b,h)},f=a.jQuery,g=a.$,h,i=/^(?:[^#<]*(<[\w\W]+>)[^>]*$|#([\w\-]*)$)/,j=/\S/,k=/^\s+/,l=/\s+$/,m=/^<(\w+)\s*\/?>(?:<\/\1>)?$/,n=/^[\],:{}\s]*$/,o=/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g,p=/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,q=/(?:^|:|,)(?:\s*\[)+/g,r=/(webkit)[ \/]([\w.]+)/,s=/(opera)(?:.*version)?[ \/]([\w.]+)/,t=/(msie) ([\w.]+)/,u=/(mozilla)(?:.*? rv:([\w.]+))?/,v=/-([a-z]|[0-9])/ig,w=/^-ms-/,x=function(a,b){return(b+"").toUpperCase()},y=d.userAgent,z,A,B,C=Object.prototype.toString,D=Object.prototype.hasOwnProperty,E=Array.prototype.push,F=Array.prototype.slice,G=String.prototype.trim,H=Array.prototype.indexOf,I={};e.fn=e.prototype={constructor:e,init:function(a,d,f){var g,h,j,k;if(!a)return this;if(a.nodeType){this.context=this[0]=a,this.length=1;return this}if(a==="body"&&!d&&c.body){this.context=c,this[0]=c.body,this.selector=a,this.length=1;return this}if(typeof a=="string"){a.charAt(0)!=="<"||a.charAt(a.length-1)!==">"||a.length<3?g=i.exec(a):g=[null,a,null];if(g&&(g[1]||!d)){if(g[1]){d=d instanceof e?d[0]:d,k=d?d.ownerDocument||d:c,j=m.exec(a),j?e.isPlainObject(d)?(a=[c.createElement(j[1])],e.fn.attr.call(a,d,!0)):a=[k.createElement(j[1])]:(j=e.buildFragment([g[1]],[k]),a=(j.cacheable?e.clone(j.fragment):j.fragment).childNodes);return e.merge(this,a)}h=c.getElementById(g[2]);if(h&&h.parentNode){if(h.id!==g[2])return f.find(a);this.length=1,this[0]=h}this.context=c,this.selector=a;return this}return!d||d.jquery?(d||f).find(a):this.constructor(d).find(a)}if(e.isFunction(a))return f.ready(a);a.selector!==b&&(this.selector=a.selector,this.context=a.context);return e.makeArray(a,this)},selector:"",jquery:"1.7.2",length:0,size:function(){return this.length},toArray:function(){return F.call(this,0)},get:function(a){return a==null?this.toArray():a<0?this[this.length+a]:this[a]},pushStack:function(a,b,c){var d=this.constructor();e.isArray(a)?E.apply(d,a):e.merge(d,a),d.prevObject=this,d.context=this.context,b==="find"?d.selector=this.selector+(this.selector?" ":"")+c:b&&(d.selector=this.selector+"."+b+"("+c+")");return d},each:function(a,b){return e.each(this,a,b)},ready:function(a){e.bindReady(),A.add(a);return this},eq:function(a){a=+a;return a===-1?this.slice(a):this.slice(a,a+1)},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},slice:function(){return this.pushStack(F.apply(this,arguments),"slice",F.call(arguments).join(","))},map:function(a){return this.pushStack(e.map(this,function(b,c){return a.call(b,c,b)}))},end:function(){return this.prevObject||this.constructor(null)},push:E,sort:[].sort,splice:[].splice},e.fn.init.prototype=e.fn,e.extend=e.fn.extend=function(){var a,c,d,f,g,h,i=arguments[0]||{},j=1,k=arguments.length,l=!1;typeof i=="boolean"&&(l=i,i=arguments[1]||{},j=2),typeof i!="object"&&!e.isFunction(i)&&(i={}),k===j&&(i=this,--j);for(;j<k;j++)if((a=arguments[j])!=null)for(c in a){d=i[c],f=a[c];if(i===f)continue;l&&f&&(e.isPlainObject(f)||(g=e.isArray(f)))?(g?(g=!1,h=d&&e.isArray(d)?d:[]):h=d&&e.isPlainObject(d)?d:{},i[c]=e.extend(l,h,f)):f!==b&&(i[c]=f)}return i},e.extend({noConflict:function(b){a.$===e&&(a.$=g),b&&a.jQuery===e&&(a.jQuery=f);return e},isReady:!1,readyWait:1,holdReady:function(a){a?e.readyWait++:e.ready(!0)},ready:function(a){if(a===!0&&!--e.readyWait||a!==!0&&!e.isReady){if(!c.body)return setTimeout(e.ready,1);e.isReady=!0;if(a!==!0&&--e.readyWait>0)return;A.fireWith(c,[e]),e.fn.trigger&&e(c).trigger("ready").off("ready")}},bindReady:function(){if(!A){A=e.Callbacks("once memory");if(c.readyState==="complete")return setTimeout(e.ready,1);if(c.addEventListener)c.addEventListener("DOMContentLoaded",B,!1),a.addEventListener("load",e.ready,!1);else if(c.attachEvent){c.attachEvent("onreadystatechange",B),a.attachEvent("onload",e.ready);var b=!1;try{b=a.frameElement==null}catch(d){}c.documentElement.doScroll&&b&&J()}}},isFunction:function(a){return e.type(a)==="function"},isArray:Array.isArray||function(a){return e.type(a)==="array"},isWindow:function(a){return a!=null&&a==a.window},isNumeric:function(a){return!isNaN(parseFloat(a))&&isFinite(a)},type:function(a){return a==null?String(a):I[C.call(a)]||"object"},isPlainObject:function(a){if(!a||e.type(a)!=="object"||a.nodeType||e.isWindow(a))return!1;try{if(a.constructor&&!D.call(a,"constructor")&&!D.call(a.constructor.prototype,"isPrototypeOf"))return!1}catch(c){return!1}var d;for(d in a);return d===b||D.call(a,d)},isEmptyObject:function(a){for(var b in a)return!1;return!0},error:function(a){throw new Error(a)},parseJSON:function(b){if(typeof b!="string"||!b)return null;b=e.trim(b);if(a.JSON&&a.JSON.parse)return a.JSON.parse(b);if(n.test(b.replace(o,"@").replace(p,"]").replace(q,"")))return(new Function("return "+b))();e.error("Invalid JSON: "+b)},parseXML:function(c){if(typeof c!="string"||!c)return null;var d,f;try{a.DOMParser?(f=new DOMParser,d=f.parseFromString(c,"text/xml")):(d=new ActiveXObject("Microsoft.XMLDOM"),d.async="false",d.loadXML(c))}catch(g){d=b}(!d||!d.documentElement||d.getElementsByTagName("parsererror").length)&&e.error("Invalid XML: "+c);return d},noop:function(){},globalEval:function(b){b&&j.test(b)&&(a.execScript||function(b){a.eval.call(a,b)})(b)},camelCase:function(a){return a.replace(w,"ms-").replace(v,x)},nodeName:function(a,b){return a.nodeName&&a.nodeName.toUpperCase()===b.toUpperCase()},each:function(a,c,d){var f,g=0,h=a.length,i=h===b||e.isFunction(a);if(d){if(i){for(f in a)if(c.apply(a[f],d)===!1)break}else for(;g<h;)if(c.apply(a[g++],d)===!1)break}else if(i){for(f in a)if(c.call(a[f],f,a[f])===!1)break}else for(;g<h;)if(c.call(a[g],g,a[g++])===!1)break;return a},trim:G?function(a){return a==null?"":G.call(a)}:function(a){return a==null?"":(a+"").replace(k,"").replace(l,"")},makeArray:function(a,b){var c=b||[];if(a!=null){var d=e.type(a);a.length==null||d==="string"||d==="function"||d==="regexp"||e.isWindow(a)?E.call(c,a):e.merge(c,a)}return c},inArray:function(a,b,c){var d;if(b){if(H)return H.call(b,a,c);d=b.length,c=c?c<0?Math.max(0,d+c):c:0;for(;c<d;c++)if(c in b&&b[c]===a)return c}return-1},merge:function(a,c){var d=a.length,e=0;if(typeof c.length=="number")for(var f=c.length;e<f;e++)a[d++]=c[e];else while(c[e]!==b)a[d++]=c[e++];a.length=d;return a},grep:function(a,b,c){var d=[],e;c=!!c;for(var f=0,g=a.length;f<g;f++)e=!!b(a[f],f),c!==e&&d.push(a[f]);return d},map:function(a,c,d){var f,g,h=[],i=0,j=a.length,k=a instanceof e||j!==b&&typeof j=="number"&&(j>0&&a[0]&&a[j-1]||j===0||e.isArray(a));if(k)for(;i<j;i++)f=c(a[i],i,d),f!=null&&(h[h.length]=f);else for(g in a)f=c(a[g],g,d),f!=null&&(h[h.length]=f);return h.concat.apply([],h)},guid:1,proxy:function(a,c){if(typeof c=="string"){var d=a[c];c=a,a=d}if(!e.isFunction(a))return b;var f=F.call(arguments,2),g=function(){return a.apply(c,f.concat(F.call(arguments)))};g.guid=a.guid=a.guid||g.guid||e.guid++;return g},access:function(a,c,d,f,g,h,i){var j,k=d==null,l=0,m=a.length;if(d&&typeof d=="object"){for(l in d)e.access(a,c,l,d[l],1,h,f);g=1}else if(f!==b){j=i===b&&e.isFunction(f),k&&(j?(j=c,c=function(a,b,c){return j.call(e(a),c)}):(c.call(a,f),c=null));if(c)for(;l<m;l++)c(a[l],d,j?f.call(a[l],l,c(a[l],d)):f,i);g=1}return g?a:k?c.call(a):m?c(a[0],d):h},now:function(){return(new Date).getTime()},uaMatch:function(a){a=a.toLowerCase();var b=r.exec(a)||s.exec(a)||t.exec(a)||a.indexOf("compatible")<0&&u.exec(a)||[];return{browser:b[1]||"",version:b[2]||"0"}},sub:function(){function a(b,c){return new a.fn.init(b,c)}e.extend(!0,a,this),a.superclass=this,a.fn=a.prototype=this(),a.fn.constructor=a,a.sub=this.sub,a.fn.init=function(d,f){f&&f instanceof e&&!(f instanceof a)&&(f=a(f));return e.fn.init.call(this,d,f,b)},a.fn.init.prototype=a.fn;var b=a(c);return a},browser:{}}),e.each("Boolean Number String Function Array Date RegExp Object".split(" "),function(a,b){I["[object "+b+"]"]=b.toLowerCase()}),z=e.uaMatch(y),z.browser&&(e.browser[z.browser]=!0,e.browser.version=z.version),e.browser.webkit&&(e.browser.safari=!0),j.test(" ")&&(k=/^[\s\xA0]+/,l=/[\s\xA0]+$/),h=e(c),c.addEventListener?B=function(){c.removeEventListener("DOMContentLoaded",B,!1),e.ready()}:c.attachEvent&&(B=function(){c.readyState==="complete"&&(c.detachEvent("onreadystatechange",B),e.ready())});return e}(),g={};f.Callbacks=function(a){a=a?g[a]||h(a):{};var c=[],d=[],e,i,j,k,l,m,n=function(b){var d,e,g,h,i;for(d=0,e=b.length;d<e;d++)g=b[d],h=f.type(g),h==="array"?n(g):h==="function"&&(!a.unique||!p.has(g))&&c.push(g)},o=function(b,f){f=f||[],e=!a.memory||[b,f],i=!0,j=!0,m=k||0,k=0,l=c.length;for(;c&&m<l;m++)if(c[m].apply(b,f)===!1&&a.stopOnFalse){e=!0;break}j=!1,c&&(a.once?e===!0?p.disable():c=[]:d&&d.length&&(e=d.shift(),p.fireWith(e[0],e[1])))},p={add:function(){if(c){var a=c.length;n(arguments),j?l=c.length:e&&e!==!0&&(k=a,o(e[0],e[1]))}return this},remove:function(){if(c){var b=arguments,d=0,e=b.length;for(;d<e;d++)for(var f=0;f<c.length;f++)if(b[d]===c[f]){j&&f<=l&&(l--,f<=m&&m--),c.splice(f--,1);if(a.unique)break}}return this},has:function(a){if(c){var b=0,d=c.length;for(;b<d;b++)if(a===c[b])return!0}return!1},empty:function(){c=[];return this},disable:function(){c=d=e=b;return this},disabled:function(){return!c},lock:function(){d=b,(!e||e===!0)&&p.disable();return this},locked:function(){return!d},fireWith:function(b,c){d&&(j?a.once||d.push([b,c]):(!a.once||!e)&&o(b,c));return this},fire:function(){p.fireWith(this,arguments);return this},fired:function(){return!!i}};return p};var i=[].slice;f.extend({Deferred:function(a){var b=f.Callbacks("once memory"),c=f.Callbacks("once memory"),d=f.Callbacks("memory"),e="pending",g={resolve:b,reject:c,notify:d},h={done:b.add,fail:c.add,progress:d.add,state:function(){return e},isResolved:b.fired,isRejected:c.fired,then:function(a,b,c){i.done(a).fail(b).progress(c);return this},always:function(){i.done.apply(i,arguments).fail.apply(i,arguments);return this},pipe:function(a,b,c){return f.Deferred(function(d){f.each({done:[a,"resolve"],fail:[b,"reject"],progress:[c,"notify"]},function(a,b){var c=b[0],e=b[1],g;f.isFunction(c)?i[a](function(){g=c.apply(this,arguments),g&&f.isFunction(g.promise)?g.promise().then(d.resolve,d.reject,d.notify):d[e+"With"](this===i?d:this,[g])}):i[a](d[e])})}).promise()},promise:function(a){if(a==null)a=h;else for(var b in h)a[b]=h[b];return a}},i=h.promise({}),j;for(j in g)i[j]=g[j].fire,i[j+"With"]=g[j].fireWith;i.done(function(){e="resolved"},c.disable,d.lock).fail(function(){e="rejected"},b.disable,d.lock),a&&a.call(i,i);return i},when:function(a){function m(a){return function(b){e[a]=arguments.length>1?i.call(arguments,0):b,j.notifyWith(k,e)}}function l(a){return function(c){b[a]=arguments.length>1?i.call(arguments,0):c,--g||j.resolveWith(j,b)}}var b=i.call(arguments,0),c=0,d=b.length,e=Array(d),g=d,h=d,j=d<=1&&a&&f.isFunction(a.promise)?a:f.Deferred(),k=j.promise();if(d>1){for(;c<d;c++)b[c]&&b[c].promise&&f.isFunction(b[c].promise)?b[c].promise().then(l(c),j.reject,m(c)):--g;g||j.resolveWith(j,b)}else j!==a&&j.resolveWith(j,d?[a]:[]);return k}}),f.support=function(){var b,d,e,g,h,i,j,k,l,m,n,o,p=c.createElement("div"),q=c.documentElement;p.setAttribute("className","t"),p.innerHTML="   <link/><table></table><a href='/a' style='top:1px;float:left;opacity:.55;'>a</a><input type='checkbox'/>",d=p.getElementsByTagName("*"),e=p.getElementsByTagName("a")[0];if(!d||!d.length||!e)return{};g=c.createElement("select"),h=g.appendChild(c.createElement("option")),i=p.getElementsByTagName("input")[0],b={leadingWhitespace:p.firstChild.nodeType===3,tbody:!p.getElementsByTagName("tbody").length,htmlSerialize:!!p.getElementsByTagName("link").length,style:/top/.test(e.getAttribute("style")),hrefNormalized:e.getAttribute("href")==="/a",opacity:/^0.55/.test(e.style.opacity),cssFloat:!!e.style.cssFloat,checkOn:i.value==="on",optSelected:h.selected,getSetAttribute:p.className!=="t",enctype:!!c.createElement("form").enctype,html5Clone:c.createElement("nav").cloneNode(!0).outerHTML!=="<:nav></:nav>",submitBubbles:!0,changeBubbles:!0,focusinBubbles:!1,deleteExpando:!0,noCloneEvent:!0,inlineBlockNeedsLayout:!1,shrinkWrapBlocks:!1,reliableMarginRight:!0,pixelMargin:!0},f.boxModel=b.boxModel=c.compatMode==="CSS1Compat",i.checked=!0,b.noCloneChecked=i.cloneNode(!0).checked,g.disabled=!0,b.optDisabled=!h.disabled;try{delete p.test}catch(r){b.deleteExpando=!1}!p.addEventListener&&p.attachEvent&&p.fireEvent&&(p.attachEvent("onclick",function(){b.noCloneEvent=!1}),p.cloneNode(!0).fireEvent("onclick")),i=c.createElement("input"),i.value="t",i.setAttribute("type","radio"),b.radioValue=i.value==="t",i.setAttribute("checked","checked"),i.setAttribute("name","t"),p.appendChild(i),j=c.createDocumentFragment(),j.appendChild(p.lastChild),b.checkClone=j.cloneNode(!0).cloneNode(!0).lastChild.checked,b.appendChecked=i.checked,j.removeChild(i),j.appendChild(p);if(p.attachEvent)for(n in{submit:1,change:1,focusin:1})m="on"+n,o=m in p,o||(p.setAttribute(m,"return;"),o=typeof p[m]=="function"),b[n+"Bubbles"]=o;j.removeChild(p),j=g=h=p=i=null,f(function(){var d,e,g,h,i,j,l,m,n,q,r,s,t,u=c.getElementsByTagName("body")[0];!u||(m=1,t="padding:0;margin:0;border:",r="position:absolute;top:0;left:0;width:1px;height:1px;",s=t+"0;visibility:hidden;",n="style='"+r+t+"5px solid #000;",q="<div "+n+"display:block;'><div style='"+t+"0;display:block;overflow:hidden;'></div></div>"+"<table "+n+"' cellpadding='0' cellspacing='0'>"+"<tr><td></td></tr></table>",d=c.createElement("div"),d.style.cssText=s+"width:0;height:0;position:static;top:0;margin-top:"+m+"px",u.insertBefore(d,u.firstChild),p=c.createElement("div"),d.appendChild(p),p.innerHTML="<table><tr><td style='"+t+"0;display:none'></td><td>t</td></tr></table>",k=p.getElementsByTagName("td"),o=k[0].offsetHeight===0,k[0].style.display="",k[1].style.display="none",b.reliableHiddenOffsets=o&&k[0].offsetHeight===0,a.getComputedStyle&&(p.innerHTML="",l=c.createElement("div"),l.style.width="0",l.style.marginRight="0",p.style.width="2px",p.appendChild(l),b.reliableMarginRight=(parseInt((a.getComputedStyle(l,null)||{marginRight:0}).marginRight,10)||0)===0),typeof p.style.zoom!="undefined"&&(p.innerHTML="",p.style.width=p.style.padding="1px",p.style.border=0,p.style.overflow="hidden",p.style.display="inline",p.style.zoom=1,b.inlineBlockNeedsLayout=p.offsetWidth===3,p.style.display="block",p.style.overflow="visible",p.innerHTML="<div style='width:5px;'></div>",b.shrinkWrapBlocks=p.offsetWidth!==3),p.style.cssText=r+s,p.innerHTML=q,e=p.firstChild,g=e.firstChild,i=e.nextSibling.firstChild.firstChild,j={doesNotAddBorder:g.offsetTop!==5,doesAddBorderForTableAndCells:i.offsetTop===5},g.style.position="fixed",g.style.top="20px",j.fixedPosition=g.offsetTop===20||g.offsetTop===15,g.style.position=g.style.top="",e.style.overflow="hidden",e.style.position="relative",j.subtractsBorderForOverflowNotVisible=g.offsetTop===-5,j.doesNotIncludeMarginInBodyOffset=u.offsetTop!==m,a.getComputedStyle&&(p.style.marginTop="1%",b.pixelMargin=(a.getComputedStyle(p,null)||{marginTop:0}).marginTop!=="1%"),typeof d.style.zoom!="undefined"&&(d.style.zoom=1),u.removeChild(d),l=p=d=null,f.extend(b,j))});return b}();var j=/^(?:\{.*\}|\[.*\])$/,k=/([A-Z])/g;f.extend({cache:{},uuid:0,expando:"jQuery"+(f.fn.jquery+Math.random()).replace(/\D/g,""),noData:{embed:!0,object:"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000",applet:!0},hasData:function(a){a=a.nodeType?f.cache[a[f.expando]]:a[f.expando];return!!a&&!m(a)},data:function(a,c,d,e){if(!!f.acceptData(a)){var g,h,i,j=f.expando,k=typeof c=="string",l=a.nodeType,m=l?f.cache:a,n=l?a[j]:a[j]&&j,o=c==="events";if((!n||!m[n]||!o&&!e&&!m[n].data)&&k&&d===b)return;n||(l?a[j]=n=++f.uuid:n=j),m[n]||(m[n]={},l||(m[n].toJSON=f.noop));if(typeof c=="object"||typeof c=="function")e?m[n]=f.extend(m[n],c):m[n].data=f.extend(m[n].data,c);g=h=m[n],e||(h.data||(h.data={}),h=h.data),d!==b&&(h[f.camelCase(c)]=d);if(o&&!h[c])return g.events;k?(i=h[c],i==null&&(i=h[f.camelCase(c)])):i=h;return i}},removeData:function(a,b,c){if(!!f.acceptData(a)){var d,e,g,h=f.expando,i=a.nodeType,j=i?f.cache:a,k=i?a[h]:h;if(!j[k])return;if(b){d=c?j[k]:j[k].data;if(d){f.isArray(b)||(b in d?b=[b]:(b=f.camelCase(b),b in d?b=[b]:b=b.split(" ")));for(e=0,g=b.length;e<g;e++)delete d[b[e]];if(!(c?m:f.isEmptyObject)(d))return}}if(!c){delete j[k].data;if(!m(j[k]))return}f.support.deleteExpando||!j.setInterval?delete j[k]:j[k]=null,i&&(f.support.deleteExpando?delete a[h]:a.removeAttribute?a.removeAttribute(h):a[h]=null)}},_data:function(a,b,c){return f.data(a,b,c,!0)},acceptData:function(a){if(a.nodeName){var b=f.noData[a.nodeName.toLowerCase()];if(b)return b!==!0&&a.getAttribute("classid")===b}return!0}}),f.fn.extend({data:function(a,c){var d,e,g,h,i,j=this[0],k=0,m=null;if(a===b){if(this.length){m=f.data(j);if(j.nodeType===1&&!f._data(j,"parsedAttrs")){g=j.attributes;for(i=g.length;k<i;k++)h=g[k].name,h.indexOf("data-")===0&&(h=f.camelCase(h.substring(5)),l(j,h,m[h]));f._data(j,"parsedAttrs",!0)}}return m}if(typeof a=="object")return this.each(function(){f.data(this,a)});d=a.split(".",2),d[1]=d[1]?"."+d[1]:"",e=d[1]+"!";return f.access(this,function(c){if(c===b){m=this.triggerHandler("getData"+e,[d[0]]),m===b&&j&&(m=f.data(j,a),m=l(j,a,m));return m===b&&d[1]?this.data(d[0]):m}d[1]=c,this.each(function(){var b=f(this);b.triggerHandler("setData"+e,d),f.data(this,a,c),b.triggerHandler("changeData"+e,d)})},null,c,arguments.length>1,null,!1)},removeData:function(a){return this.each(function(){f.removeData(this,a)})}}),f.extend({_mark:function(a,b){a&&(b=(b||"fx")+"mark",f._data(a,b,(f._data(a,b)||0)+1))},_unmark:function(a,b,c){a!==!0&&(c=b,b=a,a=!1);if(b){c=c||"fx";var d=c+"mark",e=a?0:(f._data(b,d)||1)-1;e?f._data(b,d,e):(f.removeData(b,d,!0),n(b,c,"mark"))}},queue:function(a,b,c){var d;if(a){b=(b||"fx")+"queue",d=f._data(a,b),c&&(!d||f.isArray(c)?d=f._data(a,b,f.makeArray(c)):d.push(c));return d||[]}},dequeue:function(a,b){b=b||"fx";var c=f.queue(a,b),d=c.shift(),e={};d==="inprogress"&&(d=c.shift()),d&&(b==="fx"&&c.unshift("inprogress"),f._data(a,b+".run",e),d.call(a,function(){f.dequeue(a,b)},e)),c.length||(f.removeData(a,b+"queue "+b+".run",!0),n(a,b,"queue"))}}),f.fn.extend({queue:function(a,c){var d=2;typeof a!="string"&&(c=a,a="fx",d--);if(arguments.length<d)return f.queue(this[0],a);return c===b?this:this.each(function(){var b=f.queue(this,a,c);a==="fx"&&b[0]!=="inprogress"&&f.dequeue(this,a)})},dequeue:function(a){return this.each(function(){f.dequeue(this,a)})},delay:function(a,b){a=f.fx?f.fx.speeds[a]||a:a,b=b||"fx";return this.queue(b,function(b,c){var d=setTimeout(b,a);c.stop=function(){clearTimeout(d)}})},clearQueue:function(a){return this.queue(a||"fx",[])},promise:function(a,c){function m(){--h||d.resolveWith(e,[e])}typeof a!="string"&&(c=a,a=b),a=a||"fx";var d=f.Deferred(),e=this,g=e.length,h=1,i=a+"defer",j=a+"queue",k=a+"mark",l;while(g--)if(l=f.data(e[g],i,b,!0)||(f.data(e[g],j,b,!0)||f.data(e[g],k,b,!0))&&f.data(e[g],i,f.Callbacks("once memory"),!0))h++,l.add(m);m();return d.promise(c)}});var o=/[\n\t\r]/g,p=/\s+/,q=/\r/g,r=/^(?:button|input)$/i,s=/^(?:button|input|object|select|textarea)$/i,t=/^a(?:rea)?$/i,u=/^(?:autofocus|autoplay|async|checked|controls|defer|disabled|hidden|loop|multiple|open|readonly|required|scoped|selected)$/i,v=f.support.getSetAttribute,w,x,y;f.fn.extend({attr:function(a,b){return f.access(this,f.attr,a,b,arguments.length>1)},removeAttr:function(a){return this.each(function(){f.removeAttr(this,a)})},prop:function(a,b){return f.access(this,f.prop,a,b,arguments.length>1)},removeProp:function(a){a=f.propFix[a]||a;return this.each(function(){try{this[a]=b,delete this[a]}catch(c){}})},addClass:function(a){var b,c,d,e,g,h,i;if(f.isFunction(a))return this.each(function(b){f(this).addClass(a.call(this,b,this.className))});if(a&&typeof a=="string"){b=a.split(p);for(c=0,d=this.length;c<d;c++){e=this[c];if(e.nodeType===1)if(!e.className&&b.length===1)e.className=a;else{g=" "+e.className+" ";for(h=0,i=b.length;h<i;h++)~g.indexOf(" "+b[h]+" ")||(g+=b[h]+" ");e.className=f.trim(g)}}}return this},removeClass:function(a){var c,d,e,g,h,i,j;if(f.isFunction(a))return this.each(function(b){f(this).removeClass(a.call(this,b,this.className))});if(a&&typeof a=="string"||a===b){c=(a||"").split(p);for(d=0,e=this.length;d<e;d++){g=this[d];if(g.nodeType===1&&g.className)if(a){h=(" "+g.className+" ").replace(o," ");for(i=0,j=c.length;i<j;i++)h=h.replace(" "+c[i]+" "," ");g.className=f.trim(h)}else g.className=""}}return this},toggleClass:function(a,b){var c=typeof a,d=typeof b=="boolean";if(f.isFunction(a))return this.each(function(c){f(this).toggleClass(a.call(this,c,this.className,b),b)});return this.each(function(){if(c==="string"){var e,g=0,h=f(this),i=b,j=a.split(p);while(e=j[g++])i=d?i:!h.hasClass(e),h[i?"addClass":"removeClass"](e)}else if(c==="undefined"||c==="boolean")this.className&&f._data(this,"__className__",this.className),this.className=this.className||a===!1?"":f._data(this,"__className__")||""})},hasClass:function(a){var b=" "+a+" ",c=0,d=this.length;for(;c<d;c++)if(this[c].nodeType===1&&(" "+this[c].className+" ").replace(o," ").indexOf(b)>-1)return!0;return!1},val:function(a){var c,d,e,g=this[0];{if(!!arguments.length){e=f.isFunction(a);return this.each(function(d){var g=f(this),h;if(this.nodeType===1){e?h=a.call(this,d,g.val()):h=a,h==null?h="":typeof h=="number"?h+="":f.isArray(h)&&(h=f.map(h,function(a){return a==null?"":a+""})),c=f.valHooks[this.type]||f.valHooks[this.nodeName.toLowerCase()];if(!c||!("set"in c)||c.set(this,h,"value")===b)this.value=h}})}if(g){c=f.valHooks[g.type]||f.valHooks[g.nodeName.toLowerCase()];if(c&&"get"in c&&(d=c.get(g,"value"))!==b)return d;d=g.value;return typeof d=="string"?d.replace(q,""):d==null?"":d}}}}),f.extend({valHooks:{option:{get:function(a){var b=a.attributes.value;return!b||b.specified?a.value:a.text}},select:{get:function(a){var b,c,d,e,g=a.selectedIndex,h=[],i=a.options,j=a.type==="select-one";if(g<0)return null;c=j?g:0,d=j?g+1:i.length;for(;c<d;c++){e=i[c];if(e.selected&&(f.support.optDisabled?!e.disabled:e.getAttribute("disabled")===null)&&(!e.parentNode.disabled||!f.nodeName(e.parentNode,"optgroup"))){b=f(e).val();if(j)return b;h.push(b)}}if(j&&!h.length&&i.length)return f(i[g]).val();return h},set:function(a,b){var c=f.makeArray(b);f(a).find("option").each(function(){this.selected=f.inArray(f(this).val(),c)>=0}),c.length||(a.selectedIndex=-1);return c}}},attrFn:{val:!0,css:!0,html:!0,text:!0,data:!0,width:!0,height:!0,offset:!0},attr:function(a,c,d,e){var g,h,i,j=a.nodeType;if(!!a&&j!==3&&j!==8&&j!==2){if(e&&c in f.attrFn)return f(a)[c](d);if(typeof a.getAttribute=="undefined")return f.prop(a,c,d);i=j!==1||!f.isXMLDoc(a),i&&(c=c.toLowerCase(),h=f.attrHooks[c]||(u.test(c)?x:w));if(d!==b){if(d===null){f.removeAttr(a,c);return}if(h&&"set"in h&&i&&(g=h.set(a,d,c))!==b)return g;a.setAttribute(c,""+d);return d}if(h&&"get"in h&&i&&(g=h.get(a,c))!==null)return g;g=a.getAttribute(c);return g===null?b:g}},removeAttr:function(a,b){var c,d,e,g,h,i=0;if(b&&a.nodeType===1){d=b.toLowerCase().split(p),g=d.length;for(;i<g;i++)e=d[i],e&&(c=f.propFix[e]||e,h=u.test(e),h||f.attr(a,e,""),a.removeAttribute(v?e:c),h&&c in a&&(a[c]=!1))}},attrHooks:{type:{set:function(a,b){if(r.test(a.nodeName)&&a.parentNode)f.error("type property can't be changed");else if(!f.support.radioValue&&b==="radio"&&f.nodeName(a,"input")){var c=a.value;a.setAttribute("type",b),c&&(a.value=c);return b}}},value:{get:function(a,b){if(w&&f.nodeName(a,"button"))return w.get(a,b);return b in a?a.value:null},set:function(a,b,c){if(w&&f.nodeName(a,"button"))return w.set(a,b,c);a.value=b}}},propFix:{tabindex:"tabIndex",readonly:"readOnly","for":"htmlFor","class":"className",maxlength:"maxLength",cellspacing:"cellSpacing",cellpadding:"cellPadding",rowspan:"rowSpan",colspan:"colSpan",usemap:"useMap",frameborder:"frameBorder",contenteditable:"contentEditable"},prop:function(a,c,d){var e,g,h,i=a.nodeType;if(!!a&&i!==3&&i!==8&&i!==2){h=i!==1||!f.isXMLDoc(a),h&&(c=f.propFix[c]||c,g=f.propHooks[c]);return d!==b?g&&"set"in g&&(e=g.set(a,d,c))!==b?e:a[c]=d:g&&"get"in g&&(e=g.get(a,c))!==null?e:a[c]}},propHooks:{tabIndex:{get:function(a){var c=a.getAttributeNode("tabindex");return c&&c.specified?parseInt(c.value,10):s.test(a.nodeName)||t.test(a.nodeName)&&a.href?0:b}}}}),f.attrHooks.tabindex=f.propHooks.tabIndex,x={get:function(a,c){var d,e=f.prop(a,c);return e===!0||typeof e!="boolean"&&(d=a.getAttributeNode(c))&&d.nodeValue!==!1?c.toLowerCase():b},set:function(a,b,c){var d;b===!1?f.removeAttr(a,c):(d=f.propFix[c]||c,d in a&&(a[d]=!0),a.setAttribute(c,c.toLowerCase()));return c}},v||(y={name:!0,id:!0,coords:!0},w=f.valHooks.button={get:function(a,c){var d;d=a.getAttributeNode(c);return d&&(y[c]?d.nodeValue!=="":d.specified)?d.nodeValue:b},set:function(a,b,d){var e=a.getAttributeNode(d);e||(e=c.createAttribute(d),a.setAttributeNode(e));return e.nodeValue=b+""}},f.attrHooks.tabindex.set=w.set,f.each(["width","height"],function(a,b){f.attrHooks[b]=f.extend(f.attrHooks[b],{set:function(a,c){if(c===""){a.setAttribute(b,"auto");return c}}})}),f.attrHooks.contenteditable={get:w.get,set:function(a,b,c){b===""&&(b="false"),w.set(a,b,c)}}),f.support.hrefNormalized||f.each(["href","src","width","height"],function(a,c){f.attrHooks[c]=f.extend(f.attrHooks[c],{get:function(a){var d=a.getAttribute(c,2);return d===null?b:d}})}),f.support.style||(f.attrHooks.style={get:function(a){return a.style.cssText.toLowerCase()||b},set:function(a,b){return a.style.cssText=""+b}}),f.support.optSelected||(f.propHooks.selected=f.extend(f.propHooks.selected,{get:function(a){var b=a.parentNode;b&&(b.selectedIndex,b.parentNode&&b.parentNode.selectedIndex);return null}})),f.support.enctype||(f.propFix.enctype="encoding"),f.support.checkOn||f.each(["radio","checkbox"],function(){f.valHooks[this]={get:function(a){return a.getAttribute("value")===null?"on":a.value}}}),f.each(["radio","checkbox"],function(){f.valHooks[this]=f.extend(f.valHooks[this],{set:function(a,b){if(f.isArray(b))return a.checked=f.inArray(f(a).val(),b)>=0}})});var z=/^(?:textarea|input|select)$/i,A=/^([^\.]*)?(?:\.(.+))?$/,B=/(?:^|\s)hover(\.\S+)?\b/,C=/^key/,D=/^(?:mouse|contextmenu)|click/,E=/^(?:focusinfocus|focusoutblur)$/,F=/^(\w*)(?:#([\w\-]+))?(?:\.([\w\-]+))?$/,G=function(
a){var b=F.exec(a);b&&(b[1]=(b[1]||"").toLowerCase(),b[3]=b[3]&&new RegExp("(?:^|\\s)"+b[3]+"(?:\\s|$)"));return b},H=function(a,b){var c=a.attributes||{};return(!b[1]||a.nodeName.toLowerCase()===b[1])&&(!b[2]||(c.id||{}).value===b[2])&&(!b[3]||b[3].test((c["class"]||{}).value))},I=function(a){return f.event.special.hover?a:a.replace(B,"mouseenter$1 mouseleave$1")};f.event={add:function(a,c,d,e,g){var h,i,j,k,l,m,n,o,p,q,r,s;if(!(a.nodeType===3||a.nodeType===8||!c||!d||!(h=f._data(a)))){d.handler&&(p=d,d=p.handler,g=p.selector),d.guid||(d.guid=f.guid++),j=h.events,j||(h.events=j={}),i=h.handle,i||(h.handle=i=function(a){return typeof f!="undefined"&&(!a||f.event.triggered!==a.type)?f.event.dispatch.apply(i.elem,arguments):b},i.elem=a),c=f.trim(I(c)).split(" ");for(k=0;k<c.length;k++){l=A.exec(c[k])||[],m=l[1],n=(l[2]||"").split(".").sort(),s=f.event.special[m]||{},m=(g?s.delegateType:s.bindType)||m,s=f.event.special[m]||{},o=f.extend({type:m,origType:l[1],data:e,handler:d,guid:d.guid,selector:g,quick:g&&G(g),namespace:n.join(".")},p),r=j[m];if(!r){r=j[m]=[],r.delegateCount=0;if(!s.setup||s.setup.call(a,e,n,i)===!1)a.addEventListener?a.addEventListener(m,i,!1):a.attachEvent&&a.attachEvent("on"+m,i)}s.add&&(s.add.call(a,o),o.handler.guid||(o.handler.guid=d.guid)),g?r.splice(r.delegateCount++,0,o):r.push(o),f.event.global[m]=!0}a=null}},global:{},remove:function(a,b,c,d,e){var g=f.hasData(a)&&f._data(a),h,i,j,k,l,m,n,o,p,q,r,s;if(!!g&&!!(o=g.events)){b=f.trim(I(b||"")).split(" ");for(h=0;h<b.length;h++){i=A.exec(b[h])||[],j=k=i[1],l=i[2];if(!j){for(j in o)f.event.remove(a,j+b[h],c,d,!0);continue}p=f.event.special[j]||{},j=(d?p.delegateType:p.bindType)||j,r=o[j]||[],m=r.length,l=l?new RegExp("(^|\\.)"+l.split(".").sort().join("\\.(?:.*\\.)?")+"(\\.|$)"):null;for(n=0;n<r.length;n++)s=r[n],(e||k===s.origType)&&(!c||c.guid===s.guid)&&(!l||l.test(s.namespace))&&(!d||d===s.selector||d==="**"&&s.selector)&&(r.splice(n--,1),s.selector&&r.delegateCount--,p.remove&&p.remove.call(a,s));r.length===0&&m!==r.length&&((!p.teardown||p.teardown.call(a,l)===!1)&&f.removeEvent(a,j,g.handle),delete o[j])}f.isEmptyObject(o)&&(q=g.handle,q&&(q.elem=null),f.removeData(a,["events","handle"],!0))}},customEvent:{getData:!0,setData:!0,changeData:!0},trigger:function(c,d,e,g){if(!e||e.nodeType!==3&&e.nodeType!==8){var h=c.type||c,i=[],j,k,l,m,n,o,p,q,r,s;if(E.test(h+f.event.triggered))return;h.indexOf("!")>=0&&(h=h.slice(0,-1),k=!0),h.indexOf(".")>=0&&(i=h.split("."),h=i.shift(),i.sort());if((!e||f.event.customEvent[h])&&!f.event.global[h])return;c=typeof c=="object"?c[f.expando]?c:new f.Event(h,c):new f.Event(h),c.type=h,c.isTrigger=!0,c.exclusive=k,c.namespace=i.join("."),c.namespace_re=c.namespace?new RegExp("(^|\\.)"+i.join("\\.(?:.*\\.)?")+"(\\.|$)"):null,o=h.indexOf(":")<0?"on"+h:"";if(!e){j=f.cache;for(l in j)j[l].events&&j[l].events[h]&&f.event.trigger(c,d,j[l].handle.elem,!0);return}c.result=b,c.target||(c.target=e),d=d!=null?f.makeArray(d):[],d.unshift(c),p=f.event.special[h]||{};if(p.trigger&&p.trigger.apply(e,d)===!1)return;r=[[e,p.bindType||h]];if(!g&&!p.noBubble&&!f.isWindow(e)){s=p.delegateType||h,m=E.test(s+h)?e:e.parentNode,n=null;for(;m;m=m.parentNode)r.push([m,s]),n=m;n&&n===e.ownerDocument&&r.push([n.defaultView||n.parentWindow||a,s])}for(l=0;l<r.length&&!c.isPropagationStopped();l++)m=r[l][0],c.type=r[l][1],q=(f._data(m,"events")||{})[c.type]&&f._data(m,"handle"),q&&q.apply(m,d),q=o&&m[o],q&&f.acceptData(m)&&q.apply(m,d)===!1&&c.preventDefault();c.type=h,!g&&!c.isDefaultPrevented()&&(!p._default||p._default.apply(e.ownerDocument,d)===!1)&&(h!=="click"||!f.nodeName(e,"a"))&&f.acceptData(e)&&o&&e[h]&&(h!=="focus"&&h!=="blur"||c.target.offsetWidth!==0)&&!f.isWindow(e)&&(n=e[o],n&&(e[o]=null),f.event.triggered=h,e[h](),f.event.triggered=b,n&&(e[o]=n));return c.result}},dispatch:function(c){c=f.event.fix(c||a.event);var d=(f._data(this,"events")||{})[c.type]||[],e=d.delegateCount,g=[].slice.call(arguments,0),h=!c.exclusive&&!c.namespace,i=f.event.special[c.type]||{},j=[],k,l,m,n,o,p,q,r,s,t,u;g[0]=c,c.delegateTarget=this;if(!i.preDispatch||i.preDispatch.call(this,c)!==!1){if(e&&(!c.button||c.type!=="click")){n=f(this),n.context=this.ownerDocument||this;for(m=c.target;m!=this;m=m.parentNode||this)if(m.disabled!==!0){p={},r=[],n[0]=m;for(k=0;k<e;k++)s=d[k],t=s.selector,p[t]===b&&(p[t]=s.quick?H(m,s.quick):n.is(t)),p[t]&&r.push(s);r.length&&j.push({elem:m,matches:r})}}d.length>e&&j.push({elem:this,matches:d.slice(e)});for(k=0;k<j.length&&!c.isPropagationStopped();k++){q=j[k],c.currentTarget=q.elem;for(l=0;l<q.matches.length&&!c.isImmediatePropagationStopped();l++){s=q.matches[l];if(h||!c.namespace&&!s.namespace||c.namespace_re&&c.namespace_re.test(s.namespace))c.data=s.data,c.handleObj=s,o=((f.event.special[s.origType]||{}).handle||s.handler).apply(q.elem,g),o!==b&&(c.result=o,o===!1&&(c.preventDefault(),c.stopPropagation()))}}i.postDispatch&&i.postDispatch.call(this,c);return c.result}},props:"attrChange attrName relatedNode srcElement altKey bubbles cancelable ctrlKey currentTarget eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(" "),fixHooks:{},keyHooks:{props:"char charCode key keyCode".split(" "),filter:function(a,b){a.which==null&&(a.which=b.charCode!=null?b.charCode:b.keyCode);return a}},mouseHooks:{props:"button buttons clientX clientY fromElement offsetX offsetY pageX pageY screenX screenY toElement".split(" "),filter:function(a,d){var e,f,g,h=d.button,i=d.fromElement;a.pageX==null&&d.clientX!=null&&(e=a.target.ownerDocument||c,f=e.documentElement,g=e.body,a.pageX=d.clientX+(f&&f.scrollLeft||g&&g.scrollLeft||0)-(f&&f.clientLeft||g&&g.clientLeft||0),a.pageY=d.clientY+(f&&f.scrollTop||g&&g.scrollTop||0)-(f&&f.clientTop||g&&g.clientTop||0)),!a.relatedTarget&&i&&(a.relatedTarget=i===a.target?d.toElement:i),!a.which&&h!==b&&(a.which=h&1?1:h&2?3:h&4?2:0);return a}},fix:function(a){if(a[f.expando])return a;var d,e,g=a,h=f.event.fixHooks[a.type]||{},i=h.props?this.props.concat(h.props):this.props;a=f.Event(g);for(d=i.length;d;)e=i[--d],a[e]=g[e];a.target||(a.target=g.srcElement||c),a.target.nodeType===3&&(a.target=a.target.parentNode),a.metaKey===b&&(a.metaKey=a.ctrlKey);return h.filter?h.filter(a,g):a},special:{ready:{setup:f.bindReady},load:{noBubble:!0},focus:{delegateType:"focusin"},blur:{delegateType:"focusout"},beforeunload:{setup:function(a,b,c){f.isWindow(this)&&(this.onbeforeunload=c)},teardown:function(a,b){this.onbeforeunload===b&&(this.onbeforeunload=null)}}},simulate:function(a,b,c,d){var e=f.extend(new f.Event,c,{type:a,isSimulated:!0,originalEvent:{}});d?f.event.trigger(e,null,b):f.event.dispatch.call(b,e),e.isDefaultPrevented()&&c.preventDefault()}},f.event.handle=f.event.dispatch,f.removeEvent=c.removeEventListener?function(a,b,c){a.removeEventListener&&a.removeEventListener(b,c,!1)}:function(a,b,c){a.detachEvent&&a.detachEvent("on"+b,c)},f.Event=function(a,b){if(!(this instanceof f.Event))return new f.Event(a,b);a&&a.type?(this.originalEvent=a,this.type=a.type,this.isDefaultPrevented=a.defaultPrevented||a.returnValue===!1||a.getPreventDefault&&a.getPreventDefault()?K:J):this.type=a,b&&f.extend(this,b),this.timeStamp=a&&a.timeStamp||f.now(),this[f.expando]=!0},f.Event.prototype={preventDefault:function(){this.isDefaultPrevented=K;var a=this.originalEvent;!a||(a.preventDefault?a.preventDefault():a.returnValue=!1)},stopPropagation:function(){this.isPropagationStopped=K;var a=this.originalEvent;!a||(a.stopPropagation&&a.stopPropagation(),a.cancelBubble=!0)},stopImmediatePropagation:function(){this.isImmediatePropagationStopped=K,this.stopPropagation()},isDefaultPrevented:J,isPropagationStopped:J,isImmediatePropagationStopped:J},f.each({mouseenter:"mouseover",mouseleave:"mouseout"},function(a,b){f.event.special[a]={delegateType:b,bindType:b,handle:function(a){var c=this,d=a.relatedTarget,e=a.handleObj,g=e.selector,h;if(!d||d!==c&&!f.contains(c,d))a.type=e.origType,h=e.handler.apply(this,arguments),a.type=b;return h}}}),f.support.submitBubbles||(f.event.special.submit={setup:function(){if(f.nodeName(this,"form"))return!1;f.event.add(this,"click._submit keypress._submit",function(a){var c=a.target,d=f.nodeName(c,"input")||f.nodeName(c,"button")?c.form:b;d&&!d._submit_attached&&(f.event.add(d,"submit._submit",function(a){a._submit_bubble=!0}),d._submit_attached=!0)})},postDispatch:function(a){a._submit_bubble&&(delete a._submit_bubble,this.parentNode&&!a.isTrigger&&f.event.simulate("submit",this.parentNode,a,!0))},teardown:function(){if(f.nodeName(this,"form"))return!1;f.event.remove(this,"._submit")}}),f.support.changeBubbles||(f.event.special.change={setup:function(){if(z.test(this.nodeName)){if(this.type==="checkbox"||this.type==="radio")f.event.add(this,"propertychange._change",function(a){a.originalEvent.propertyName==="checked"&&(this._just_changed=!0)}),f.event.add(this,"click._change",function(a){this._just_changed&&!a.isTrigger&&(this._just_changed=!1,f.event.simulate("change",this,a,!0))});return!1}f.event.add(this,"beforeactivate._change",function(a){var b=a.target;z.test(b.nodeName)&&!b._change_attached&&(f.event.add(b,"change._change",function(a){this.parentNode&&!a.isSimulated&&!a.isTrigger&&f.event.simulate("change",this.parentNode,a,!0)}),b._change_attached=!0)})},handle:function(a){var b=a.target;if(this!==b||a.isSimulated||a.isTrigger||b.type!=="radio"&&b.type!=="checkbox")return a.handleObj.handler.apply(this,arguments)},teardown:function(){f.event.remove(this,"._change");return z.test(this.nodeName)}}),f.support.focusinBubbles||f.each({focus:"focusin",blur:"focusout"},function(a,b){var d=0,e=function(a){f.event.simulate(b,a.target,f.event.fix(a),!0)};f.event.special[b]={setup:function(){d++===0&&c.addEventListener(a,e,!0)},teardown:function(){--d===0&&c.removeEventListener(a,e,!0)}}}),f.fn.extend({on:function(a,c,d,e,g){var h,i;if(typeof a=="object"){typeof c!="string"&&(d=d||c,c=b);for(i in a)this.on(i,c,d,a[i],g);return this}d==null&&e==null?(e=c,d=c=b):e==null&&(typeof c=="string"?(e=d,d=b):(e=d,d=c,c=b));if(e===!1)e=J;else if(!e)return this;g===1&&(h=e,e=function(a){f().off(a);return h.apply(this,arguments)},e.guid=h.guid||(h.guid=f.guid++));return this.each(function(){f.event.add(this,a,e,d,c)})},one:function(a,b,c,d){return this.on(a,b,c,d,1)},off:function(a,c,d){if(a&&a.preventDefault&&a.handleObj){var e=a.handleObj;f(a.delegateTarget).off(e.namespace?e.origType+"."+e.namespace:e.origType,e.selector,e.handler);return this}if(typeof a=="object"){for(var g in a)this.off(g,c,a[g]);return this}if(c===!1||typeof c=="function")d=c,c=b;d===!1&&(d=J);return this.each(function(){f.event.remove(this,a,d,c)})},bind:function(a,b,c){return this.on(a,null,b,c)},unbind:function(a,b){return this.off(a,null,b)},live:function(a,b,c){f(this.context).on(a,this.selector,b,c);return this},die:function(a,b){f(this.context).off(a,this.selector||"**",b);return this},delegate:function(a,b,c,d){return this.on(b,a,c,d)},undelegate:function(a,b,c){return arguments.length==1?this.off(a,"**"):this.off(b,a,c)},trigger:function(a,b){return this.each(function(){f.event.trigger(a,b,this)})},triggerHandler:function(a,b){if(this[0])return f.event.trigger(a,b,this[0],!0)},toggle:function(a){var b=arguments,c=a.guid||f.guid++,d=0,e=function(c){var e=(f._data(this,"lastToggle"+a.guid)||0)%d;f._data(this,"lastToggle"+a.guid,e+1),c.preventDefault();return b[e].apply(this,arguments)||!1};e.guid=c;while(d<b.length)b[d++].guid=c;return this.click(e)},hover:function(a,b){return this.mouseenter(a).mouseleave(b||a)}}),f.each("blur focus focusin focusout load resize scroll unload click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup error contextmenu".split(" "),function(a,b){f.fn[b]=function(a,c){c==null&&(c=a,a=null);return arguments.length>0?this.on(b,null,a,c):this.trigger(b)},f.attrFn&&(f.attrFn[b]=!0),C.test(b)&&(f.event.fixHooks[b]=f.event.keyHooks),D.test(b)&&(f.event.fixHooks[b]=f.event.mouseHooks)}),function(){function x(a,b,c,e,f,g){for(var h=0,i=e.length;h<i;h++){var j=e[h];if(j){var k=!1;j=j[a];while(j){if(j[d]===c){k=e[j.sizset];break}if(j.nodeType===1){g||(j[d]=c,j.sizset=h);if(typeof b!="string"){if(j===b){k=!0;break}}else if(m.filter(b,[j]).length>0){k=j;break}}j=j[a]}e[h]=k}}}function w(a,b,c,e,f,g){for(var h=0,i=e.length;h<i;h++){var j=e[h];if(j){var k=!1;j=j[a];while(j){if(j[d]===c){k=e[j.sizset];break}j.nodeType===1&&!g&&(j[d]=c,j.sizset=h);if(j.nodeName.toLowerCase()===b){k=j;break}j=j[a]}e[h]=k}}}var a=/((?:\((?:\([^()]+\)|[^()]+)+\)|\[(?:\[[^\[\]]*\]|['"][^'"]*['"]|[^\[\]'"]+)+\]|\\.|[^ >+~,(\[\\]+)+|[>+~])(\s*,\s*)?((?:.|\r|\n)*)/g,d="sizcache"+(Math.random()+"").replace(".",""),e=0,g=Object.prototype.toString,h=!1,i=!0,j=/\\/g,k=/\r\n/g,l=/\W/;[0,0].sort(function(){i=!1;return 0});var m=function(b,d,e,f){e=e||[],d=d||c;var h=d;if(d.nodeType!==1&&d.nodeType!==9)return[];if(!b||typeof b!="string")return e;var i,j,k,l,n,q,r,t,u=!0,v=m.isXML(d),w=[],x=b;do{a.exec(""),i=a.exec(x);if(i){x=i[3],w.push(i[1]);if(i[2]){l=i[3];break}}}while(i);if(w.length>1&&p.exec(b))if(w.length===2&&o.relative[w[0]])j=y(w[0]+w[1],d,f);else{j=o.relative[w[0]]?[d]:m(w.shift(),d);while(w.length)b=w.shift(),o.relative[b]&&(b+=w.shift()),j=y(b,j,f)}else{!f&&w.length>1&&d.nodeType===9&&!v&&o.match.ID.test(w[0])&&!o.match.ID.test(w[w.length-1])&&(n=m.find(w.shift(),d,v),d=n.expr?m.filter(n.expr,n.set)[0]:n.set[0]);if(d){n=f?{expr:w.pop(),set:s(f)}:m.find(w.pop(),w.length===1&&(w[0]==="~"||w[0]==="+")&&d.parentNode?d.parentNode:d,v),j=n.expr?m.filter(n.expr,n.set):n.set,w.length>0?k=s(j):u=!1;while(w.length)q=w.pop(),r=q,o.relative[q]?r=w.pop():q="",r==null&&(r=d),o.relative[q](k,r,v)}else k=w=[]}k||(k=j),k||m.error(q||b);if(g.call(k)==="[object Array]")if(!u)e.push.apply(e,k);else if(d&&d.nodeType===1)for(t=0;k[t]!=null;t++)k[t]&&(k[t]===!0||k[t].nodeType===1&&m.contains(d,k[t]))&&e.push(j[t]);else for(t=0;k[t]!=null;t++)k[t]&&k[t].nodeType===1&&e.push(j[t]);else s(k,e);l&&(m(l,h,e,f),m.uniqueSort(e));return e};m.uniqueSort=function(a){if(u){h=i,a.sort(u);if(h)for(var b=1;b<a.length;b++)a[b]===a[b-1]&&a.splice(b--,1)}return a},m.matches=function(a,b){return m(a,null,null,b)},m.matchesSelector=function(a,b){return m(b,null,null,[a]).length>0},m.find=function(a,b,c){var d,e,f,g,h,i;if(!a)return[];for(e=0,f=o.order.length;e<f;e++){h=o.order[e];if(g=o.leftMatch[h].exec(a)){i=g[1],g.splice(1,1);if(i.substr(i.length-1)!=="\\"){g[1]=(g[1]||"").replace(j,""),d=o.find[h](g,b,c);if(d!=null){a=a.replace(o.match[h],"");break}}}}d||(d=typeof b.getElementsByTagName!="undefined"?b.getElementsByTagName("*"):[]);return{set:d,expr:a}},m.filter=function(a,c,d,e){var f,g,h,i,j,k,l,n,p,q=a,r=[],s=c,t=c&&c[0]&&m.isXML(c[0]);while(a&&c.length){for(h in o.filter)if((f=o.leftMatch[h].exec(a))!=null&&f[2]){k=o.filter[h],l=f[1],g=!1,f.splice(1,1);if(l.substr(l.length-1)==="\\")continue;s===r&&(r=[]);if(o.preFilter[h]){f=o.preFilter[h](f,s,d,r,e,t);if(!f)g=i=!0;else if(f===!0)continue}if(f)for(n=0;(j=s[n])!=null;n++)j&&(i=k(j,f,n,s),p=e^i,d&&i!=null?p?g=!0:s[n]=!1:p&&(r.push(j),g=!0));if(i!==b){d||(s=r),a=a.replace(o.match[h],"");if(!g)return[];break}}if(a===q)if(g==null)m.error(a);else break;q=a}return s},m.error=function(a){throw new Error("Syntax error, unrecognized expression: "+a)};var n=m.getText=function(a){var b,c,d=a.nodeType,e="";if(d){if(d===1||d===9||d===11){if(typeof a.textContent=="string")return a.textContent;if(typeof a.innerText=="string")return a.innerText.replace(k,"");for(a=a.firstChild;a;a=a.nextSibling)e+=n(a)}else if(d===3||d===4)return a.nodeValue}else for(b=0;c=a[b];b++)c.nodeType!==8&&(e+=n(c));return e},o=m.selectors={order:["ID","NAME","TAG"],match:{ID:/#((?:[\w\u00c0-\uFFFF\-]|\\.)+)/,CLASS:/\.((?:[\w\u00c0-\uFFFF\-]|\\.)+)/,NAME:/\[name=['"]*((?:[\w\u00c0-\uFFFF\-]|\\.)+)['"]*\]/,ATTR:/\[\s*((?:[\w\u00c0-\uFFFF\-]|\\.)+)\s*(?:(\S?=)\s*(?:(['"])(.*?)\3|(#?(?:[\w\u00c0-\uFFFF\-]|\\.)*)|)|)\s*\]/,TAG:/^((?:[\w\u00c0-\uFFFF\*\-]|\\.)+)/,CHILD:/:(only|nth|last|first)-child(?:\(\s*(even|odd|(?:[+\-]?\d+|(?:[+\-]?\d*)?n\s*(?:[+\-]\s*\d+)?))\s*\))?/,POS:/:(nth|eq|gt|lt|first|last|even|odd)(?:\((\d*)\))?(?=[^\-]|$)/,PSEUDO:/:((?:[\w\u00c0-\uFFFF\-]|\\.)+)(?:\((['"]?)((?:\([^\)]+\)|[^\(\)]*)+)\2\))?/},leftMatch:{},attrMap:{"class":"className","for":"htmlFor"},attrHandle:{href:function(a){return a.getAttribute("href")},type:function(a){return a.getAttribute("type")}},relative:{"+":function(a,b){var c=typeof b=="string",d=c&&!l.test(b),e=c&&!d;d&&(b=b.toLowerCase());for(var f=0,g=a.length,h;f<g;f++)if(h=a[f]){while((h=h.previousSibling)&&h.nodeType!==1);a[f]=e||h&&h.nodeName.toLowerCase()===b?h||!1:h===b}e&&m.filter(b,a,!0)},">":function(a,b){var c,d=typeof b=="string",e=0,f=a.length;if(d&&!l.test(b)){b=b.toLowerCase();for(;e<f;e++){c=a[e];if(c){var g=c.parentNode;a[e]=g.nodeName.toLowerCase()===b?g:!1}}}else{for(;e<f;e++)c=a[e],c&&(a[e]=d?c.parentNode:c.parentNode===b);d&&m.filter(b,a,!0)}},"":function(a,b,c){var d,f=e++,g=x;typeof b=="string"&&!l.test(b)&&(b=b.toLowerCase(),d=b,g=w),g("parentNode",b,f,a,d,c)},"~":function(a,b,c){var d,f=e++,g=x;typeof b=="string"&&!l.test(b)&&(b=b.toLowerCase(),d=b,g=w),g("previousSibling",b,f,a,d,c)}},find:{ID:function(a,b,c){if(typeof b.getElementById!="undefined"&&!c){var d=b.getElementById(a[1]);return d&&d.parentNode?[d]:[]}},NAME:function(a,b){if(typeof b.getElementsByName!="undefined"){var c=[],d=b.getElementsByName(a[1]);for(var e=0,f=d.length;e<f;e++)d[e].getAttribute("name")===a[1]&&c.push(d[e]);return c.length===0?null:c}},TAG:function(a,b){if(typeof b.getElementsByTagName!="undefined")return b.getElementsByTagName(a[1])}},preFilter:{CLASS:function(a,b,c,d,e,f){a=" "+a[1].replace(j,"")+" ";if(f)return a;for(var g=0,h;(h=b[g])!=null;g++)h&&(e^(h.className&&(" "+h.className+" ").replace(/[\t\n\r]/g," ").indexOf(a)>=0)?c||d.push(h):c&&(b[g]=!1));return!1},ID:function(a){return a[1].replace(j,"")},TAG:function(a,b){return a[1].replace(j,"").toLowerCase()},CHILD:function(a){if(a[1]==="nth"){a[2]||m.error(a[0]),a[2]=a[2].replace(/^\+|\s*/g,"");var b=/(-?)(\d*)(?:n([+\-]?\d*))?/.exec(a[2]==="even"&&"2n"||a[2]==="odd"&&"2n+1"||!/\D/.test(a[2])&&"0n+"+a[2]||a[2]);a[2]=b[1]+(b[2]||1)-0,a[3]=b[3]-0}else a[2]&&m.error(a[0]);a[0]=e++;return a},ATTR:function(a,b,c,d,e,f){var g=a[1]=a[1].replace(j,"");!f&&o.attrMap[g]&&(a[1]=o.attrMap[g]),a[4]=(a[4]||a[5]||"").replace(j,""),a[2]==="~="&&(a[4]=" "+a[4]+" ");return a},PSEUDO:function(b,c,d,e,f){if(b[1]==="not")if((a.exec(b[3])||"").length>1||/^\w/.test(b[3]))b[3]=m(b[3],null,null,c);else{var g=m.filter(b[3],c,d,!0^f);d||e.push.apply(e,g);return!1}else if(o.match.POS.test(b[0])||o.match.CHILD.test(b[0]))return!0;return b},POS:function(a){a.unshift(!0);return a}},filters:{enabled:function(a){return a.disabled===!1&&a.type!=="hidden"},disabled:function(a){return a.disabled===!0},checked:function(a){return a.checked===!0},selected:function(a){a.parentNode&&a.parentNode.selectedIndex;return a.selected===!0},parent:function(a){return!!a.firstChild},empty:function(a){return!a.firstChild},has:function(a,b,c){return!!m(c[3],a).length},header:function(a){return/h\d/i.test(a.nodeName)},text:function(a){var b=a.getAttribute("type"),c=a.type;return a.nodeName.toLowerCase()==="input"&&"text"===c&&(b===c||b===null)},radio:function(a){return a.nodeName.toLowerCase()==="input"&&"radio"===a.type},checkbox:function(a){return a.nodeName.toLowerCase()==="input"&&"checkbox"===a.type},file:function(a){return a.nodeName.toLowerCase()==="input"&&"file"===a.type},password:function(a){return a.nodeName.toLowerCase()==="input"&&"password"===a.type},submit:function(a){var b=a.nodeName.toLowerCase();return(b==="input"||b==="button")&&"submit"===a.type},image:function(a){return a.nodeName.toLowerCase()==="input"&&"image"===a.type},reset:function(a){var b=a.nodeName.toLowerCase();return(b==="input"||b==="button")&&"reset"===a.type},button:function(a){var b=a.nodeName.toLowerCase();return b==="input"&&"button"===a.type||b==="button"},input:function(a){return/input|select|textarea|button/i.test(a.nodeName)},focus:function(a){return a===a.ownerDocument.activeElement}},setFilters:{first:function(a,b){return b===0},last:function(a,b,c,d){return b===d.length-1},even:function(a,b){return b%2===0},odd:function(a,b){return b%2===1},lt:function(a,b,c){return b<c[3]-0},gt:function(a,b,c){return b>c[3]-0},nth:function(a,b,c){return c[3]-0===b},eq:function(a,b,c){return c[3]-0===b}},filter:{PSEUDO:function(a,b,c,d){var e=b[1],f=o.filters[e];if(f)return f(a,c,b,d);if(e==="contains")return(a.textContent||a.innerText||n([a])||"").indexOf(b[3])>=0;if(e==="not"){var g=b[3];for(var h=0,i=g.length;h<i;h++)if(g[h]===a)return!1;return!0}m.error(e)},CHILD:function(a,b){var c,e,f,g,h,i,j,k=b[1],l=a;switch(k){case"only":case"first":while(l=l.previousSibling)if(l.nodeType===1)return!1;if(k==="first")return!0;l=a;case"last":while(l=l.nextSibling)if(l.nodeType===1)return!1;return!0;case"nth":c=b[2],e=b[3];if(c===1&&e===0)return!0;f=b[0],g=a.parentNode;if(g&&(g[d]!==f||!a.nodeIndex)){i=0;for(l=g.firstChild;l;l=l.nextSibling)l.nodeType===1&&(l.nodeIndex=++i);g[d]=f}j=a.nodeIndex-e;return c===0?j===0:j%c===0&&j/c>=0}},ID:function(a,b){return a.nodeType===1&&a.getAttribute("id")===b},TAG:function(a,b){return b==="*"&&a.nodeType===1||!!a.nodeName&&a.nodeName.toLowerCase()===b},CLASS:function(a,b){return(" "+(a.className||a.getAttribute("class"))+" ").indexOf(b)>-1},ATTR:function(a,b){var c=b[1],d=m.attr?m.attr(a,c):o.attrHandle[c]?o.attrHandle[c](a):a[c]!=null?a[c]:a.getAttribute(c),e=d+"",f=b[2],g=b[4];return d==null?f==="!=":!f&&m.attr?d!=null:f==="="?e===g:f==="*="?e.indexOf(g)>=0:f==="~="?(" "+e+" ").indexOf(g)>=0:g?f==="!="?e!==g:f==="^="?e.indexOf(g)===0:f==="$="?e.substr(e.length-g.length)===g:f==="|="?e===g||e.substr(0,g.length+1)===g+"-":!1:e&&d!==!1},POS:function(a,b,c,d){var e=b[2],f=o.setFilters[e];if(f)return f(a,c,b,d)}}},p=o.match.POS,q=function(a,b){return"\\"+(b-0+1)};for(var r in o.match)o.match[r]=new RegExp(o.match[r].source+/(?![^\[]*\])(?![^\(]*\))/.source),o.leftMatch[r]=new RegExp(/(^(?:.|\r|\n)*?)/.source+o.match[r].source.replace(/\\(\d+)/g,q));o.match.globalPOS=p;var s=function(a,b){a=Array.prototype.slice.call(a,0);if(b){b.push.apply(b,a);return b}return a};try{Array.prototype.slice.call(c.documentElement.childNodes,0)[0].nodeType}catch(t){s=function(a,b){var c=0,d=b||[];if(g.call(a)==="[object Array]")Array.prototype.push.apply(d,a);else if(typeof a.length=="number")for(var e=a.length;c<e;c++)d.push(a[c]);else for(;a[c];c++)d.push(a[c]);return d}}var u,v;c.documentElement.compareDocumentPosition?u=function(a,b){if(a===b){h=!0;return 0}if(!a.compareDocumentPosition||!b.compareDocumentPosition)return a.compareDocumentPosition?-1:1;return a.compareDocumentPosition(b)&4?-1:1}:(u=function(a,b){if(a===b){h=!0;return 0}if(a.sourceIndex&&b.sourceIndex)return a.sourceIndex-b.sourceIndex;var c,d,e=[],f=[],g=a.parentNode,i=b.parentNode,j=g;if(g===i)return v(a,b);if(!g)return-1;if(!i)return 1;while(j)e.unshift(j),j=j.parentNode;j=i;while(j)f.unshift(j),j=j.parentNode;c=e.length,d=f.length;for(var k=0;k<c&&k<d;k++)if(e[k]!==f[k])return v(e[k],f[k]);return k===c?v(a,f[k],-1):v(e[k],b,1)},v=function(a,b,c){if(a===b)return c;var d=a.nextSibling;while(d){if(d===b)return-1;d=d.nextSibling}return 1}),function(){var a=c.createElement("div"),d="script"+(new Date).getTime(),e=c.documentElement;a.innerHTML="<a name='"+d+"'/>",e.insertBefore(a,e.firstChild),c.getElementById(d)&&(o.find.ID=function(a,c,d){if(typeof c.getElementById!="undefined"&&!d){var e=c.getElementById(a[1]);return e?e.id===a[1]||typeof e.getAttributeNode!="undefined"&&e.getAttributeNode("id").nodeValue===a[1]?[e]:b:[]}},o.filter.ID=function(a,b){var c=typeof a.getAttributeNode!="undefined"&&a.getAttributeNode("id");return a.nodeType===1&&c&&c.nodeValue===b}),e.removeChild(a),e=a=null}(),function(){var a=c.createElement("div");a.appendChild(c.createComment("")),a.getElementsByTagName("*").length>0&&(o.find.TAG=function(a,b){var c=b.getElementsByTagName(a[1]);if(a[1]==="*"){var d=[];for(var e=0;c[e];e++)c[e].nodeType===1&&d.push(c[e]);c=d}return c}),a.innerHTML="<a href='#'></a>",a.firstChild&&typeof a.firstChild.getAttribute!="undefined"&&a.firstChild.getAttribute("href")!=="#"&&(o.attrHandle.href=function(a){return a.getAttribute("href",2)}),a=null}(),c.querySelectorAll&&function(){var a=m,b=c.createElement("div"),d="__sizzle__";b.innerHTML="<p class='TEST'></p>";if(!b.querySelectorAll||b.querySelectorAll(".TEST").length!==0){m=function(b,e,f,g){e=e||c;if(!g&&!m.isXML(e)){var h=/^(\w+$)|^\.([\w\-]+$)|^#([\w\-]+$)/.exec(b);if(h&&(e.nodeType===1||e.nodeType===9)){if(h[1])return s(e.getElementsByTagName(b),f);if(h[2]&&o.find.CLASS&&e.getElementsByClassName)return s(e.getElementsByClassName(h[2]),f)}if(e.nodeType===9){if(b==="body"&&e.body)return s([e.body],f);if(h&&h[3]){var i=e.getElementById(h[3]);if(!i||!i.parentNode)return s([],f);if(i.id===h[3])return s([i],f)}try{return s(e.querySelectorAll(b),f)}catch(j){}}else if(e.nodeType===1&&e.nodeName.toLowerCase()!=="object"){var k=e,l=e.getAttribute("id"),n=l||d,p=e.parentNode,q=/^\s*[+~]/.test(b);l?n=n.replace(/'/g,"\\$&"):e.setAttribute("id",n),q&&p&&(e=e.parentNode);try{if(!q||p)return s(e.querySelectorAll("[id='"+n+"'] "+b),f)}catch(r){}finally{l||k.removeAttribute("id")}}}return a(b,e,f,g)};for(var e in a)m[e]=a[e];b=null}}(),function(){var a=c.documentElement,b=a.matchesSelector||a.mozMatchesSelector||a.webkitMatchesSelector||a.msMatchesSelector;if(b){var d=!b.call(c.createElement("div"),"div"),e=!1;try{b.call(c.documentElement,"[test!='']:sizzle")}catch(f){e=!0}m.matchesSelector=function(a,c){c=c.replace(/\=\s*([^'"\]]*)\s*\]/g,"='$1']");if(!m.isXML(a))try{if(e||!o.match.PSEUDO.test(c)&&!/!=/.test(c)){var f=b.call(a,c);if(f||!d||a.document&&a.document.nodeType!==11)return f}}catch(g){}return m(c,null,null,[a]).length>0}}}(),function(){var a=c.createElement("div");a.innerHTML="<div class='test e'></div><div class='test'></div>";if(!!a.getElementsByClassName&&a.getElementsByClassName("e").length!==0){a.lastChild.className="e";if(a.getElementsByClassName("e").length===1)return;o.order.splice(1,0,"CLASS"),o.find.CLASS=function(a,b,c){if(typeof b.getElementsByClassName!="undefined"&&!c)return b.getElementsByClassName(a[1])},a=null}}(),c.documentElement.contains?m.contains=function(a,b){return a!==b&&(a.contains?a.contains(b):!0)}:c.documentElement.compareDocumentPosition?m.contains=function(a,b){return!!(a.compareDocumentPosition(b)&16)}:m.contains=function(){return!1},m.isXML=function(a){var b=(a?a.ownerDocument||a:0).documentElement;return b?b.nodeName!=="HTML":!1};var y=function(a,b,c){var d,e=[],f="",g=b.nodeType?[b]:b;while(d=o.match.PSEUDO.exec(a))f+=d[0],a=a.replace(o.match.PSEUDO,"");a=o.relative[a]?a+"*":a;for(var h=0,i=g.length;h<i;h++)m(a,g[h],e,c);return m.filter(f,e)};m.attr=f.attr,m.selectors.attrMap={},f.find=m,f.expr=m.selectors,f.expr[":"]=f.expr.filters,f.unique=m.uniqueSort,f.text=m.getText,f.isXMLDoc=m.isXML,f.contains=m.contains}();var L=/Until$/,M=/^(?:parents|prevUntil|prevAll)/,N=/,/,O=/^.[^:#\[\.,]*$/,P=Array.prototype.slice,Q=f.expr.match.globalPOS,R={children:!0,contents:!0,next:!0,prev:!0};f.fn.extend({find:function(a){var b=this,c,d;if(typeof a!="string")return f(a).filter(function(){for(c=0,d=b.length;c<d;c++)if(f.contains(b[c],this))return!0});var e=this.pushStack("","find",a),g,h,i;for(c=0,d=this.length;c<d;c++){g=e.length,f.find(a,this[c],e);if(c>0)for(h=g;h<e.length;h++)for(i=0;i<g;i++)if(e[i]===e[h]){e.splice(h--,1);break}}return e},has:function(a){var b=f(a);return this.filter(function(){for(var a=0,c=b.length;a<c;a++)if(f.contains(this,b[a]))return!0})},not:function(a){return this.pushStack(T(this,a,!1),"not",a)},filter:function(a){return this.pushStack(T(this,a,!0),"filter",a)},is:function(a){return!!a&&(typeof a=="string"?Q.test(a)?f(a,this.context).index(this[0])>=0:f.filter(a,this).length>0:this.filter(a).length>0)},closest:function(a,b){var c=[],d,e,g=this[0];if(f.isArray(a)){var h=1;while(g&&g.ownerDocument&&g!==b){for(d=0;d<a.length;d++)f(g).is(a[d])&&c.push({selector:a[d],elem:g,level:h});g=g.parentNode,h++}return c}var i=Q.test(a)||typeof a!="string"?f(a,b||this.context):0;for(d=0,e=this.length;d<e;d++){g=this[d];while(g){if(i?i.index(g)>-1:f.find.matchesSelector(g,a)){c.push(g);break}g=g.parentNode;if(!g||!g.ownerDocument||g===b||g.nodeType===11)break}}c=c.length>1?f.unique(c):c;return this.pushStack(c,"closest",a)},index:function(a){if(!a)return this[0]&&this[0].parentNode?this.prevAll().length:-1;if(typeof a=="string")return f.inArray(this[0],f(a));return f.inArray(a.jquery?a[0]:a,this)},add:function(a,b){var c=typeof a=="string"?f(a,b):f.makeArray(a&&a.nodeType?[a]:a),d=f.merge(this.get(),c);return this.pushStack(S(c[0])||S(d[0])?d:f.unique(d))},andSelf:function(){return this.add(this.prevObject)}}),f.each({parent:function(a){var b=a.parentNode;return b&&b.nodeType!==11?b:null},parents:function(a){return f.dir(a,"parentNode")},parentsUntil:function(a,b,c){return f.dir(a,"parentNode",c)},next:function(a){return f.nth(a,2,"nextSibling")},prev:function(a){return f.nth(a,2,"previousSibling")},nextAll:function(a){return f.dir(a,"nextSibling")},prevAll:function(a){return f.dir(a,"previousSibling")},nextUntil:function(a,b,c){return f.dir(a,"nextSibling",c)},prevUntil:function(a,b,c){return f.dir(a,"previousSibling",c)},siblings:function(a){return f.sibling((a.parentNode||{}).firstChild,a)},children:function(a){return f.sibling(a.firstChild)},contents:function(a){return f.nodeName(a,"iframe")?a.contentDocument||a.contentWindow.document:f.makeArray(a.childNodes)}},function(a,b){f.fn[a]=function(c,d){var e=f.map(this,b,c);L.test(a)||(d=c),d&&typeof d=="string"&&(e=f.filter(d,e)),e=this.length>1&&!R[a]?f.unique(e):e,(this.length>1||N.test(d))&&M.test(a)&&(e=e.reverse());return this.pushStack(e,a,P.call(arguments).join(","))}}),f.extend({filter:function(a,b,c){c&&(a=":not("+a+")");return b.length===1?f.find.matchesSelector(b[0],a)?[b[0]]:[]:f.find.matches(a,b)},dir:function(a,c,d){var e=[],g=a[c];while(g&&g.nodeType!==9&&(d===b||g.nodeType!==1||!f(g).is(d)))g.nodeType===1&&e.push(g),g=g[c];return e},nth:function(a,b,c,d){b=b||1;var e=0;for(;a;a=a[c])if(a.nodeType===1&&++e===b)break;return a},sibling:function(a,b){var c=[];for(;a;a=a.nextSibling)a.nodeType===1&&a!==b&&c.push(a);return c}});var V="abbr|article|aside|audio|bdi|canvas|data|datalist|details|figcaption|figure|footer|header|hgroup|mark|meter|nav|output|progress|section|summary|time|video",W=/ jQuery\d+="(?:\d+|null)"/g,X=/^\s+/,Y=/<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:]+)[^>]*)\/>/ig,Z=/<([\w:]+)/,$=/<tbody/i,_=/<|&#?\w+;/,ba=/<(?:script|style)/i,bb=/<(?:script|object|embed|option|style)/i,bc=new RegExp("<(?:"+V+")[\\s/>]","i"),bd=/checked\s*(?:[^=]|=\s*.checked.)/i,be=/\/(java|ecma)script/i,bf=/^\s*<!(?:\[CDATA\[|\-\-)/,bg={option:[1,"<select multiple='multiple'>","</select>"],legend:[1,"<fieldset>","</fieldset>"],thead:[1,"<table>","</table>"],tr:[2,"<table><tbody>","</tbody></table>"],td:[3,"<table><tbody><tr>","</tr></tbody></table>"],col:[2,"<table><tbody></tbody><colgroup>","</colgroup></table>"],area:[1,"<map>","</map>"],_default:[0,"",""]},bh=U(c);bg.optgroup=bg.option,bg.tbody=bg.tfoot=bg.colgroup=bg.caption=bg.thead,bg.th=bg.td,f.support.htmlSerialize||(bg._default=[1,"div<div>","</div>"]),f.fn.extend({text:function(a){return f.access(this,function(a){return a===b?f.text(this):this.empty().append((this[0]&&this[0].ownerDocument||c).createTextNode(a))},null,a,arguments.length)},wrapAll:function(a){if(f.isFunction(a))return this.each(function(b){f(this).wrapAll(a.call(this,b))});if(this[0]){var b=f(a,this[0].ownerDocument).eq(0).clone(!0);this[0].parentNode&&b.insertBefore(this[0]),b.map(function(){var a=this;while(a.firstChild&&a.firstChild.nodeType===1)a=a.firstChild;return a}).append(this)}return this},wrapInner:function(a){if(f.isFunction(a))return this.each(function(b){f(this).wrapInner(a.call(this,b))});return this.each(function(){var b=f(this),c=b.contents();c.length?c.wrapAll(a):b.append(a)})},wrap:function(a){var b=f.isFunction(a);return this.each(function(c){f(this).wrapAll(b?a.call(this,c):a)})},unwrap:function(){return this.parent().each(function(){f.nodeName(this,"body")||f(this).replaceWith(this.childNodes)}).end()},append:function(){return this.domManip(arguments,!0,function(a){this.nodeType===1&&this.appendChild(a)})},prepend:function(){return this.domManip(arguments,!0,function(a){this.nodeType===1&&this.insertBefore(a,this.firstChild)})},before:function(){if(this[0]&&this[0].parentNode)return this.domManip(arguments,!1,function(a){this.parentNode.insertBefore(a,this)});if(arguments.length){var a=f
.clean(arguments);a.push.apply(a,this.toArray());return this.pushStack(a,"before",arguments)}},after:function(){if(this[0]&&this[0].parentNode)return this.domManip(arguments,!1,function(a){this.parentNode.insertBefore(a,this.nextSibling)});if(arguments.length){var a=this.pushStack(this,"after",arguments);a.push.apply(a,f.clean(arguments));return a}},remove:function(a,b){for(var c=0,d;(d=this[c])!=null;c++)if(!a||f.filter(a,[d]).length)!b&&d.nodeType===1&&(f.cleanData(d.getElementsByTagName("*")),f.cleanData([d])),d.parentNode&&d.parentNode.removeChild(d);return this},empty:function(){for(var a=0,b;(b=this[a])!=null;a++){b.nodeType===1&&f.cleanData(b.getElementsByTagName("*"));while(b.firstChild)b.removeChild(b.firstChild)}return this},clone:function(a,b){a=a==null?!1:a,b=b==null?a:b;return this.map(function(){return f.clone(this,a,b)})},html:function(a){return f.access(this,function(a){var c=this[0]||{},d=0,e=this.length;if(a===b)return c.nodeType===1?c.innerHTML.replace(W,""):null;if(typeof a=="string"&&!ba.test(a)&&(f.support.leadingWhitespace||!X.test(a))&&!bg[(Z.exec(a)||["",""])[1].toLowerCase()]){a=a.replace(Y,"<$1></$2>");try{for(;d<e;d++)c=this[d]||{},c.nodeType===1&&(f.cleanData(c.getElementsByTagName("*")),c.innerHTML=a);c=0}catch(g){}}c&&this.empty().append(a)},null,a,arguments.length)},replaceWith:function(a){if(this[0]&&this[0].parentNode){if(f.isFunction(a))return this.each(function(b){var c=f(this),d=c.html();c.replaceWith(a.call(this,b,d))});typeof a!="string"&&(a=f(a).detach());return this.each(function(){var b=this.nextSibling,c=this.parentNode;f(this).remove(),b?f(b).before(a):f(c).append(a)})}return this.length?this.pushStack(f(f.isFunction(a)?a():a),"replaceWith",a):this},detach:function(a){return this.remove(a,!0)},domManip:function(a,c,d){var e,g,h,i,j=a[0],k=[];if(!f.support.checkClone&&arguments.length===3&&typeof j=="string"&&bd.test(j))return this.each(function(){f(this).domManip(a,c,d,!0)});if(f.isFunction(j))return this.each(function(e){var g=f(this);a[0]=j.call(this,e,c?g.html():b),g.domManip(a,c,d)});if(this[0]){i=j&&j.parentNode,f.support.parentNode&&i&&i.nodeType===11&&i.childNodes.length===this.length?e={fragment:i}:e=f.buildFragment(a,this,k),h=e.fragment,h.childNodes.length===1?g=h=h.firstChild:g=h.firstChild;if(g){c=c&&f.nodeName(g,"tr");for(var l=0,m=this.length,n=m-1;l<m;l++)d.call(c?bi(this[l],g):this[l],e.cacheable||m>1&&l<n?f.clone(h,!0,!0):h)}k.length&&f.each(k,function(a,b){b.src?f.ajax({type:"GET",global:!1,url:b.src,async:!1,dataType:"script"}):f.globalEval((b.text||b.textContent||b.innerHTML||"").replace(bf,"/*$0*/")),b.parentNode&&b.parentNode.removeChild(b)})}return this}}),f.buildFragment=function(a,b,d){var e,g,h,i,j=a[0];b&&b[0]&&(i=b[0].ownerDocument||b[0]),i.createDocumentFragment||(i=c),a.length===1&&typeof j=="string"&&j.length<512&&i===c&&j.charAt(0)==="<"&&!bb.test(j)&&(f.support.checkClone||!bd.test(j))&&(f.support.html5Clone||!bc.test(j))&&(g=!0,h=f.fragments[j],h&&h!==1&&(e=h)),e||(e=i.createDocumentFragment(),f.clean(a,i,e,d)),g&&(f.fragments[j]=h?e:1);return{fragment:e,cacheable:g}},f.fragments={},f.each({appendTo:"append",prependTo:"prepend",insertBefore:"before",insertAfter:"after",replaceAll:"replaceWith"},function(a,b){f.fn[a]=function(c){var d=[],e=f(c),g=this.length===1&&this[0].parentNode;if(g&&g.nodeType===11&&g.childNodes.length===1&&e.length===1){e[b](this[0]);return this}for(var h=0,i=e.length;h<i;h++){var j=(h>0?this.clone(!0):this).get();f(e[h])[b](j),d=d.concat(j)}return this.pushStack(d,a,e.selector)}}),f.extend({clone:function(a,b,c){var d,e,g,h=f.support.html5Clone||f.isXMLDoc(a)||!bc.test("<"+a.nodeName+">")?a.cloneNode(!0):bo(a);if((!f.support.noCloneEvent||!f.support.noCloneChecked)&&(a.nodeType===1||a.nodeType===11)&&!f.isXMLDoc(a)){bk(a,h),d=bl(a),e=bl(h);for(g=0;d[g];++g)e[g]&&bk(d[g],e[g])}if(b){bj(a,h);if(c){d=bl(a),e=bl(h);for(g=0;d[g];++g)bj(d[g],e[g])}}d=e=null;return h},clean:function(a,b,d,e){var g,h,i,j=[];b=b||c,typeof b.createElement=="undefined"&&(b=b.ownerDocument||b[0]&&b[0].ownerDocument||c);for(var k=0,l;(l=a[k])!=null;k++){typeof l=="number"&&(l+="");if(!l)continue;if(typeof l=="string")if(!_.test(l))l=b.createTextNode(l);else{l=l.replace(Y,"<$1></$2>");var m=(Z.exec(l)||["",""])[1].toLowerCase(),n=bg[m]||bg._default,o=n[0],p=b.createElement("div"),q=bh.childNodes,r;b===c?bh.appendChild(p):U(b).appendChild(p),p.innerHTML=n[1]+l+n[2];while(o--)p=p.lastChild;if(!f.support.tbody){var s=$.test(l),t=m==="table"&&!s?p.firstChild&&p.firstChild.childNodes:n[1]==="<table>"&&!s?p.childNodes:[];for(i=t.length-1;i>=0;--i)f.nodeName(t[i],"tbody")&&!t[i].childNodes.length&&t[i].parentNode.removeChild(t[i])}!f.support.leadingWhitespace&&X.test(l)&&p.insertBefore(b.createTextNode(X.exec(l)[0]),p.firstChild),l=p.childNodes,p&&(p.parentNode.removeChild(p),q.length>0&&(r=q[q.length-1],r&&r.parentNode&&r.parentNode.removeChild(r)))}var u;if(!f.support.appendChecked)if(l[0]&&typeof (u=l.length)=="number")for(i=0;i<u;i++)bn(l[i]);else bn(l);l.nodeType?j.push(l):j=f.merge(j,l)}if(d){g=function(a){return!a.type||be.test(a.type)};for(k=0;j[k];k++){h=j[k];if(e&&f.nodeName(h,"script")&&(!h.type||be.test(h.type)))e.push(h.parentNode?h.parentNode.removeChild(h):h);else{if(h.nodeType===1){var v=f.grep(h.getElementsByTagName("script"),g);j.splice.apply(j,[k+1,0].concat(v))}d.appendChild(h)}}}return j},cleanData:function(a){var b,c,d=f.cache,e=f.event.special,g=f.support.deleteExpando;for(var h=0,i;(i=a[h])!=null;h++){if(i.nodeName&&f.noData[i.nodeName.toLowerCase()])continue;c=i[f.expando];if(c){b=d[c];if(b&&b.events){for(var j in b.events)e[j]?f.event.remove(i,j):f.removeEvent(i,j,b.handle);b.handle&&(b.handle.elem=null)}g?delete i[f.expando]:i.removeAttribute&&i.removeAttribute(f.expando),delete d[c]}}}});var bp=/alpha\([^)]*\)/i,bq=/opacity=([^)]*)/,br=/([A-Z]|^ms)/g,bs=/^[\-+]?(?:\d*\.)?\d+$/i,bt=/^-?(?:\d*\.)?\d+(?!px)[^\d\s]+$/i,bu=/^([\-+])=([\-+.\de]+)/,bv=/^margin/,bw={position:"absolute",visibility:"hidden",display:"block"},bx=["Top","Right","Bottom","Left"],by,bz,bA;f.fn.css=function(a,c){return f.access(this,function(a,c,d){return d!==b?f.style(a,c,d):f.css(a,c)},a,c,arguments.length>1)},f.extend({cssHooks:{opacity:{get:function(a,b){if(b){var c=by(a,"opacity");return c===""?"1":c}return a.style.opacity}}},cssNumber:{fillOpacity:!0,fontWeight:!0,lineHeight:!0,opacity:!0,orphans:!0,widows:!0,zIndex:!0,zoom:!0},cssProps:{"float":f.support.cssFloat?"cssFloat":"styleFloat"},style:function(a,c,d,e){if(!!a&&a.nodeType!==3&&a.nodeType!==8&&!!a.style){var g,h,i=f.camelCase(c),j=a.style,k=f.cssHooks[i];c=f.cssProps[i]||i;if(d===b){if(k&&"get"in k&&(g=k.get(a,!1,e))!==b)return g;return j[c]}h=typeof d,h==="string"&&(g=bu.exec(d))&&(d=+(g[1]+1)*+g[2]+parseFloat(f.css(a,c)),h="number");if(d==null||h==="number"&&isNaN(d))return;h==="number"&&!f.cssNumber[i]&&(d+="px");if(!k||!("set"in k)||(d=k.set(a,d))!==b)try{j[c]=d}catch(l){}}},css:function(a,c,d){var e,g;c=f.camelCase(c),g=f.cssHooks[c],c=f.cssProps[c]||c,c==="cssFloat"&&(c="float");if(g&&"get"in g&&(e=g.get(a,!0,d))!==b)return e;if(by)return by(a,c)},swap:function(a,b,c){var d={},e,f;for(f in b)d[f]=a.style[f],a.style[f]=b[f];e=c.call(a);for(f in b)a.style[f]=d[f];return e}}),f.curCSS=f.css,c.defaultView&&c.defaultView.getComputedStyle&&(bz=function(a,b){var c,d,e,g,h=a.style;b=b.replace(br,"-$1").toLowerCase(),(d=a.ownerDocument.defaultView)&&(e=d.getComputedStyle(a,null))&&(c=e.getPropertyValue(b),c===""&&!f.contains(a.ownerDocument.documentElement,a)&&(c=f.style(a,b))),!f.support.pixelMargin&&e&&bv.test(b)&&bt.test(c)&&(g=h.width,h.width=c,c=e.width,h.width=g);return c}),c.documentElement.currentStyle&&(bA=function(a,b){var c,d,e,f=a.currentStyle&&a.currentStyle[b],g=a.style;f==null&&g&&(e=g[b])&&(f=e),bt.test(f)&&(c=g.left,d=a.runtimeStyle&&a.runtimeStyle.left,d&&(a.runtimeStyle.left=a.currentStyle.left),g.left=b==="fontSize"?"1em":f,f=g.pixelLeft+"px",g.left=c,d&&(a.runtimeStyle.left=d));return f===""?"auto":f}),by=bz||bA,f.each(["height","width"],function(a,b){f.cssHooks[b]={get:function(a,c,d){if(c)return a.offsetWidth!==0?bB(a,b,d):f.swap(a,bw,function(){return bB(a,b,d)})},set:function(a,b){return bs.test(b)?b+"px":b}}}),f.support.opacity||(f.cssHooks.opacity={get:function(a,b){return bq.test((b&&a.currentStyle?a.currentStyle.filter:a.style.filter)||"")?parseFloat(RegExp.$1)/100+"":b?"1":""},set:function(a,b){var c=a.style,d=a.currentStyle,e=f.isNumeric(b)?"alpha(opacity="+b*100+")":"",g=d&&d.filter||c.filter||"";c.zoom=1;if(b>=1&&f.trim(g.replace(bp,""))===""){c.removeAttribute("filter");if(d&&!d.filter)return}c.filter=bp.test(g)?g.replace(bp,e):g+" "+e}}),f(function(){f.support.reliableMarginRight||(f.cssHooks.marginRight={get:function(a,b){return f.swap(a,{display:"inline-block"},function(){return b?by(a,"margin-right"):a.style.marginRight})}})}),f.expr&&f.expr.filters&&(f.expr.filters.hidden=function(a){var b=a.offsetWidth,c=a.offsetHeight;return b===0&&c===0||!f.support.reliableHiddenOffsets&&(a.style&&a.style.display||f.css(a,"display"))==="none"},f.expr.filters.visible=function(a){return!f.expr.filters.hidden(a)}),f.each({margin:"",padding:"",border:"Width"},function(a,b){f.cssHooks[a+b]={expand:function(c){var d,e=typeof c=="string"?c.split(" "):[c],f={};for(d=0;d<4;d++)f[a+bx[d]+b]=e[d]||e[d-2]||e[0];return f}}});var bC=/%20/g,bD=/\[\]$/,bE=/\r?\n/g,bF=/#.*$/,bG=/^(.*?):[ \t]*([^\r\n]*)\r?$/mg,bH=/^(?:color|date|datetime|datetime-local|email|hidden|month|number|password|range|search|tel|text|time|url|week)$/i,bI=/^(?:about|app|app\-storage|.+\-extension|file|res|widget):$/,bJ=/^(?:GET|HEAD)$/,bK=/^\/\//,bL=/\?/,bM=/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,bN=/^(?:select|textarea)/i,bO=/\s+/,bP=/([?&])_=[^&]*/,bQ=/^([\w\+\.\-]+:)(?:\/\/([^\/?#:]*)(?::(\d+))?)?/,bR=f.fn.load,bS={},bT={},bU,bV,bW=["*/"]+["*"];try{bU=e.href}catch(bX){bU=c.createElement("a"),bU.href="",bU=bU.href}bV=bQ.exec(bU.toLowerCase())||[],f.fn.extend({load:function(a,c,d){if(typeof a!="string"&&bR)return bR.apply(this,arguments);if(!this.length)return this;var e=a.indexOf(" ");if(e>=0){var g=a.slice(e,a.length);a=a.slice(0,e)}var h="GET";c&&(f.isFunction(c)?(d=c,c=b):typeof c=="object"&&(c=f.param(c,f.ajaxSettings.traditional),h="POST"));var i=this;f.ajax({url:a,type:h,dataType:"html",data:c,complete:function(a,b,c){c=a.responseText,a.isResolved()&&(a.done(function(a){c=a}),i.html(g?f("<div>").append(c.replace(bM,"")).find(g):c)),d&&i.each(d,[c,b,a])}});return this},serialize:function(){return f.param(this.serializeArray())},serializeArray:function(){return this.map(function(){return this.elements?f.makeArray(this.elements):this}).filter(function(){return this.name&&!this.disabled&&(this.checked||bN.test(this.nodeName)||bH.test(this.type))}).map(function(a,b){var c=f(this).val();return c==null?null:f.isArray(c)?f.map(c,function(a,c){return{name:b.name,value:a.replace(bE,"\r\n")}}):{name:b.name,value:c.replace(bE,"\r\n")}}).get()}}),f.each("ajaxStart ajaxStop ajaxComplete ajaxError ajaxSuccess ajaxSend".split(" "),function(a,b){f.fn[b]=function(a){return this.on(b,a)}}),f.each(["get","post"],function(a,c){f[c]=function(a,d,e,g){f.isFunction(d)&&(g=g||e,e=d,d=b);return f.ajax({type:c,url:a,data:d,success:e,dataType:g})}}),f.extend({getScript:function(a,c){return f.get(a,b,c,"script")},getJSON:function(a,b,c){return f.get(a,b,c,"json")},ajaxSetup:function(a,b){b?b$(a,f.ajaxSettings):(b=a,a=f.ajaxSettings),b$(a,b);return a},ajaxSettings:{url:bU,isLocal:bI.test(bV[1]),global:!0,type:"GET",contentType:"application/x-www-form-urlencoded; charset=UTF-8",processData:!0,async:!0,accepts:{xml:"application/xml, text/xml",html:"text/html",text:"text/plain",json:"application/json, text/javascript","*":bW},contents:{xml:/xml/,html:/html/,json:/json/},responseFields:{xml:"responseXML",text:"responseText"},converters:{"* text":a.String,"text html":!0,"text json":f.parseJSON,"text xml":f.parseXML},flatOptions:{context:!0,url:!0}},ajaxPrefilter:bY(bS),ajaxTransport:bY(bT),ajax:function(a,c){function w(a,c,l,m){if(s!==2){s=2,q&&clearTimeout(q),p=b,n=m||"",v.readyState=a>0?4:0;var o,r,u,w=c,x=l?ca(d,v,l):b,y,z;if(a>=200&&a<300||a===304){if(d.ifModified){if(y=v.getResponseHeader("Last-Modified"))f.lastModified[k]=y;if(z=v.getResponseHeader("Etag"))f.etag[k]=z}if(a===304)w="notmodified",o=!0;else try{r=cb(d,x),w="success",o=!0}catch(A){w="parsererror",u=A}}else{u=w;if(!w||a)w="error",a<0&&(a=0)}v.status=a,v.statusText=""+(c||w),o?h.resolveWith(e,[r,w,v]):h.rejectWith(e,[v,w,u]),v.statusCode(j),j=b,t&&g.trigger("ajax"+(o?"Success":"Error"),[v,d,o?r:u]),i.fireWith(e,[v,w]),t&&(g.trigger("ajaxComplete",[v,d]),--f.active||f.event.trigger("ajaxStop"))}}typeof a=="object"&&(c=a,a=b),c=c||{};var d=f.ajaxSetup({},c),e=d.context||d,g=e!==d&&(e.nodeType||e instanceof f)?f(e):f.event,h=f.Deferred(),i=f.Callbacks("once memory"),j=d.statusCode||{},k,l={},m={},n,o,p,q,r,s=0,t,u,v={readyState:0,setRequestHeader:function(a,b){if(!s){var c=a.toLowerCase();a=m[c]=m[c]||a,l[a]=b}return this},getAllResponseHeaders:function(){return s===2?n:null},getResponseHeader:function(a){var c;if(s===2){if(!o){o={};while(c=bG.exec(n))o[c[1].toLowerCase()]=c[2]}c=o[a.toLowerCase()]}return c===b?null:c},overrideMimeType:function(a){s||(d.mimeType=a);return this},abort:function(a){a=a||"abort",p&&p.abort(a),w(0,a);return this}};h.promise(v),v.success=v.done,v.error=v.fail,v.complete=i.add,v.statusCode=function(a){if(a){var b;if(s<2)for(b in a)j[b]=[j[b],a[b]];else b=a[v.status],v.then(b,b)}return this},d.url=((a||d.url)+"").replace(bF,"").replace(bK,bV[1]+"//"),d.dataTypes=f.trim(d.dataType||"*").toLowerCase().split(bO),d.crossDomain==null&&(r=bQ.exec(d.url.toLowerCase()),d.crossDomain=!(!r||r[1]==bV[1]&&r[2]==bV[2]&&(r[3]||(r[1]==="http:"?80:443))==(bV[3]||(bV[1]==="http:"?80:443)))),d.data&&d.processData&&typeof d.data!="string"&&(d.data=f.param(d.data,d.traditional)),bZ(bS,d,c,v);if(s===2)return!1;t=d.global,d.type=d.type.toUpperCase(),d.hasContent=!bJ.test(d.type),t&&f.active++===0&&f.event.trigger("ajaxStart");if(!d.hasContent){d.data&&(d.url+=(bL.test(d.url)?"&":"?")+d.data,delete d.data),k=d.url;if(d.cache===!1){var x=f.now(),y=d.url.replace(bP,"$1_="+x);d.url=y+(y===d.url?(bL.test(d.url)?"&":"?")+"_="+x:"")}}(d.data&&d.hasContent&&d.contentType!==!1||c.contentType)&&v.setRequestHeader("Content-Type",d.contentType),d.ifModified&&(k=k||d.url,f.lastModified[k]&&v.setRequestHeader("If-Modified-Since",f.lastModified[k]),f.etag[k]&&v.setRequestHeader("If-None-Match",f.etag[k])),v.setRequestHeader("Accept",d.dataTypes[0]&&d.accepts[d.dataTypes[0]]?d.accepts[d.dataTypes[0]]+(d.dataTypes[0]!=="*"?", "+bW+"; q=0.01":""):d.accepts["*"]);for(u in d.headers)v.setRequestHeader(u,d.headers[u]);if(d.beforeSend&&(d.beforeSend.call(e,v,d)===!1||s===2)){v.abort();return!1}for(u in{success:1,error:1,complete:1})v[u](d[u]);p=bZ(bT,d,c,v);if(!p)w(-1,"No Transport");else{v.readyState=1,t&&g.trigger("ajaxSend",[v,d]),d.async&&d.timeout>0&&(q=setTimeout(function(){v.abort("timeout")},d.timeout));try{s=1,p.send(l,w)}catch(z){if(s<2)w(-1,z);else throw z}}return v},param:function(a,c){var d=[],e=function(a,b){b=f.isFunction(b)?b():b,d[d.length]=encodeURIComponent(a)+"="+encodeURIComponent(b)};c===b&&(c=f.ajaxSettings.traditional);if(f.isArray(a)||a.jquery&&!f.isPlainObject(a))f.each(a,function(){e(this.name,this.value)});else for(var g in a)b_(g,a[g],c,e);return d.join("&").replace(bC,"+")}}),f.extend({active:0,lastModified:{},etag:{}});var cc=f.now(),cd=/(\=)\?(&|$)|\?\?/i;f.ajaxSetup({jsonp:"callback",jsonpCallback:function(){return f.expando+"_"+cc++}}),f.ajaxPrefilter("json jsonp",function(b,c,d){var e=typeof b.data=="string"&&/^application\/x\-www\-form\-urlencoded/.test(b.contentType);if(b.dataTypes[0]==="jsonp"||b.jsonp!==!1&&(cd.test(b.url)||e&&cd.test(b.data))){var g,h=b.jsonpCallback=f.isFunction(b.jsonpCallback)?b.jsonpCallback():b.jsonpCallback,i=a[h],j=b.url,k=b.data,l="$1"+h+"$2";b.jsonp!==!1&&(j=j.replace(cd,l),b.url===j&&(e&&(k=k.replace(cd,l)),b.data===k&&(j+=(/\?/.test(j)?"&":"?")+b.jsonp+"="+h))),b.url=j,b.data=k,a[h]=function(a){g=[a]},d.always(function(){a[h]=i,g&&f.isFunction(i)&&a[h](g[0])}),b.converters["script json"]=function(){g||f.error(h+" was not called");return g[0]},b.dataTypes[0]="json";return"script"}}),f.ajaxSetup({accepts:{script:"text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"},contents:{script:/javascript|ecmascript/},converters:{"text script":function(a){f.globalEval(a);return a}}}),f.ajaxPrefilter("script",function(a){a.cache===b&&(a.cache=!1),a.crossDomain&&(a.type="GET",a.global=!1)}),f.ajaxTransport("script",function(a){if(a.crossDomain){var d,e=c.head||c.getElementsByTagName("head")[0]||c.documentElement;return{send:function(f,g){d=c.createElement("script"),d.async="async",a.scriptCharset&&(d.charset=a.scriptCharset),d.src=a.url,d.onload=d.onreadystatechange=function(a,c){if(c||!d.readyState||/loaded|complete/.test(d.readyState))d.onload=d.onreadystatechange=null,e&&d.parentNode&&e.removeChild(d),d=b,c||g(200,"success")},e.insertBefore(d,e.firstChild)},abort:function(){d&&d.onload(0,1)}}}});var ce=a.ActiveXObject?function(){for(var a in cg)cg[a](0,1)}:!1,cf=0,cg;f.ajaxSettings.xhr=a.ActiveXObject?function(){return!this.isLocal&&ch()||ci()}:ch,function(a){f.extend(f.support,{ajax:!!a,cors:!!a&&"withCredentials"in a})}(f.ajaxSettings.xhr()),f.support.ajax&&f.ajaxTransport(function(c){if(!c.crossDomain||f.support.cors){var d;return{send:function(e,g){var h=c.xhr(),i,j;c.username?h.open(c.type,c.url,c.async,c.username,c.password):h.open(c.type,c.url,c.async);if(c.xhrFields)for(j in c.xhrFields)h[j]=c.xhrFields[j];c.mimeType&&h.overrideMimeType&&h.overrideMimeType(c.mimeType),!c.crossDomain&&!e["X-Requested-With"]&&(e["X-Requested-With"]="XMLHttpRequest");try{for(j in e)h.setRequestHeader(j,e[j])}catch(k){}h.send(c.hasContent&&c.data||null),d=function(a,e){var j,k,l,m,n;try{if(d&&(e||h.readyState===4)){d=b,i&&(h.onreadystatechange=f.noop,ce&&delete cg[i]);if(e)h.readyState!==4&&h.abort();else{j=h.status,l=h.getAllResponseHeaders(),m={},n=h.responseXML,n&&n.documentElement&&(m.xml=n);try{m.text=h.responseText}catch(a){}try{k=h.statusText}catch(o){k=""}!j&&c.isLocal&&!c.crossDomain?j=m.text?200:404:j===1223&&(j=204)}}}catch(p){e||g(-1,p)}m&&g(j,k,m,l)},!c.async||h.readyState===4?d():(i=++cf,ce&&(cg||(cg={},f(a).unload(ce)),cg[i]=d),h.onreadystatechange=d)},abort:function(){d&&d(0,1)}}}});var cj={},ck,cl,cm=/^(?:toggle|show|hide)$/,cn=/^([+\-]=)?([\d+.\-]+)([a-z%]*)$/i,co,cp=[["height","marginTop","marginBottom","paddingTop","paddingBottom"],["width","marginLeft","marginRight","paddingLeft","paddingRight"],["opacity"]],cq;f.fn.extend({show:function(a,b,c){var d,e;if(a||a===0)return this.animate(ct("show",3),a,b,c);for(var g=0,h=this.length;g<h;g++)d=this[g],d.style&&(e=d.style.display,!f._data(d,"olddisplay")&&e==="none"&&(e=d.style.display=""),(e===""&&f.css(d,"display")==="none"||!f.contains(d.ownerDocument.documentElement,d))&&f._data(d,"olddisplay",cu(d.nodeName)));for(g=0;g<h;g++){d=this[g];if(d.style){e=d.style.display;if(e===""||e==="none")d.style.display=f._data(d,"olddisplay")||""}}return this},hide:function(a,b,c){if(a||a===0)return this.animate(ct("hide",3),a,b,c);var d,e,g=0,h=this.length;for(;g<h;g++)d=this[g],d.style&&(e=f.css(d,"display"),e!=="none"&&!f._data(d,"olddisplay")&&f._data(d,"olddisplay",e));for(g=0;g<h;g++)this[g].style&&(this[g].style.display="none");return this},_toggle:f.fn.toggle,toggle:function(a,b,c){var d=typeof a=="boolean";f.isFunction(a)&&f.isFunction(b)?this._toggle.apply(this,arguments):a==null||d?this.each(function(){var b=d?a:f(this).is(":hidden");f(this)[b?"show":"hide"]()}):this.animate(ct("toggle",3),a,b,c);return this},fadeTo:function(a,b,c,d){return this.filter(":hidden").css("opacity",0).show().end().animate({opacity:b},a,c,d)},animate:function(a,b,c,d){function g(){e.queue===!1&&f._mark(this);var b=f.extend({},e),c=this.nodeType===1,d=c&&f(this).is(":hidden"),g,h,i,j,k,l,m,n,o,p,q;b.animatedProperties={};for(i in a){g=f.camelCase(i),i!==g&&(a[g]=a[i],delete a[i]);if((k=f.cssHooks[g])&&"expand"in k){l=k.expand(a[g]),delete a[g];for(i in l)i in a||(a[i]=l[i])}}for(g in a){h=a[g],f.isArray(h)?(b.animatedProperties[g]=h[1],h=a[g]=h[0]):b.animatedProperties[g]=b.specialEasing&&b.specialEasing[g]||b.easing||"swing";if(h==="hide"&&d||h==="show"&&!d)return b.complete.call(this);c&&(g==="height"||g==="width")&&(b.overflow=[this.style.overflow,this.style.overflowX,this.style.overflowY],f.css(this,"display")==="inline"&&f.css(this,"float")==="none"&&(!f.support.inlineBlockNeedsLayout||cu(this.nodeName)==="inline"?this.style.display="inline-block":this.style.zoom=1))}b.overflow!=null&&(this.style.overflow="hidden");for(i in a)j=new f.fx(this,b,i),h=a[i],cm.test(h)?(q=f._data(this,"toggle"+i)||(h==="toggle"?d?"show":"hide":0),q?(f._data(this,"toggle"+i,q==="show"?"hide":"show"),j[q]()):j[h]()):(m=cn.exec(h),n=j.cur(),m?(o=parseFloat(m[2]),p=m[3]||(f.cssNumber[i]?"":"px"),p!=="px"&&(f.style(this,i,(o||1)+p),n=(o||1)/j.cur()*n,f.style(this,i,n+p)),m[1]&&(o=(m[1]==="-="?-1:1)*o+n),j.custom(n,o,p)):j.custom(n,h,""));return!0}var e=f.speed(b,c,d);if(f.isEmptyObject(a))return this.each(e.complete,[!1]);a=f.extend({},a);return e.queue===!1?this.each(g):this.queue(e.queue,g)},stop:function(a,c,d){typeof a!="string"&&(d=c,c=a,a=b),c&&a!==!1&&this.queue(a||"fx",[]);return this.each(function(){function h(a,b,c){var e=b[c];f.removeData(a,c,!0),e.stop(d)}var b,c=!1,e=f.timers,g=f._data(this);d||f._unmark(!0,this);if(a==null)for(b in g)g[b]&&g[b].stop&&b.indexOf(".run")===b.length-4&&h(this,g,b);else g[b=a+".run"]&&g[b].stop&&h(this,g,b);for(b=e.length;b--;)e[b].elem===this&&(a==null||e[b].queue===a)&&(d?e[b](!0):e[b].saveState(),c=!0,e.splice(b,1));(!d||!c)&&f.dequeue(this,a)})}}),f.each({slideDown:ct("show",1),slideUp:ct("hide",1),slideToggle:ct("toggle",1),fadeIn:{opacity:"show"},fadeOut:{opacity:"hide"},fadeToggle:{opacity:"toggle"}},function(a,b){f.fn[a]=function(a,c,d){return this.animate(b,a,c,d)}}),f.extend({speed:function(a,b,c){var d=a&&typeof a=="object"?f.extend({},a):{complete:c||!c&&b||f.isFunction(a)&&a,duration:a,easing:c&&b||b&&!f.isFunction(b)&&b};d.duration=f.fx.off?0:typeof d.duration=="number"?d.duration:d.duration in f.fx.speeds?f.fx.speeds[d.duration]:f.fx.speeds._default;if(d.queue==null||d.queue===!0)d.queue="fx";d.old=d.complete,d.complete=function(a){f.isFunction(d.old)&&d.old.call(this),d.queue?f.dequeue(this,d.queue):a!==!1&&f._unmark(this)};return d},easing:{linear:function(a){return a},swing:function(a){return-Math.cos(a*Math.PI)/2+.5}},timers:[],fx:function(a,b,c){this.options=b,this.elem=a,this.prop=c,b.orig=b.orig||{}}}),f.fx.prototype={update:function(){this.options.step&&this.options.step.call(this.elem,this.now,this),(f.fx.step[this.prop]||f.fx.step._default)(this)},cur:function(){if(this.elem[this.prop]!=null&&(!this.elem.style||this.elem.style[this.prop]==null))return this.elem[this.prop];var a,b=f.css(this.elem,this.prop);return isNaN(a=parseFloat(b))?!b||b==="auto"?0:b:a},custom:function(a,c,d){function h(a){return e.step(a)}var e=this,g=f.fx;this.startTime=cq||cr(),this.end=c,this.now=this.start=a,this.pos=this.state=0,this.unit=d||this.unit||(f.cssNumber[this.prop]?"":"px"),h.queue=this.options.queue,h.elem=this.elem,h.saveState=function(){f._data(e.elem,"fxshow"+e.prop)===b&&(e.options.hide?f._data(e.elem,"fxshow"+e.prop,e.start):e.options.show&&f._data(e.elem,"fxshow"+e.prop,e.end))},h()&&f.timers.push(h)&&!co&&(co=setInterval(g.tick,g.interval))},show:function(){var a=f._data(this.elem,"fxshow"+this.prop);this.options.orig[this.prop]=a||f.style(this.elem,this.prop),this.options.show=!0,a!==b?this.custom(this.cur(),a):this.custom(this.prop==="width"||this.prop==="height"?1:0,this.cur()),f(this.elem).show()},hide:function(){this.options.orig[this.prop]=f._data(this.elem,"fxshow"+this.prop)||f.style(this.elem,this.prop),this.options.hide=!0,this.custom(this.cur(),0)},step:function(a){var b,c,d,e=cq||cr(),g=!0,h=this.elem,i=this.options;if(a||e>=i.duration+this.startTime){this.now=this.end,this.pos=this.state=1,this.update(),i.animatedProperties[this.prop]=!0;for(b in i.animatedProperties)i.animatedProperties[b]!==!0&&(g=!1);if(g){i.overflow!=null&&!f.support.shrinkWrapBlocks&&f.each(["","X","Y"],function(a,b){h.style["overflow"+b]=i.overflow[a]}),i.hide&&f(h).hide();if(i.hide||i.show)for(b in i.animatedProperties)f.style(h,b,i.orig[b]),f.removeData(h,"fxshow"+b,!0),f.removeData(h,"toggle"+b,!0);d=i.complete,d&&(i.complete=!1,d.call(h))}return!1}i.duration==Infinity?this.now=e:(c=e-this.startTime,this.state=c/i.duration,this.pos=f.easing[i.animatedProperties[this.prop]](this.state,c,0,1,i.duration),this.now=this.start+(this.end-this.start)*this.pos),this.update();return!0}},f.extend(f.fx,{tick:function(){var a,b=f.timers,c=0;for(;c<b.length;c++)a=b[c],!a()&&b[c]===a&&b.splice(c--,1);b.length||f.fx.stop()},interval:13,stop:function(){clearInterval(co),co=null},speeds:{slow:600,fast:200,_default:400},step:{opacity:function(a){f.style(a.elem,"opacity",a.now)},_default:function(a){a.elem.style&&a.elem.style[a.prop]!=null?a.elem.style[a.prop]=a.now+a.unit:a.elem[a.prop]=a.now}}}),f.each(cp.concat.apply([],cp),function(a,b){b.indexOf("margin")&&(f.fx.step[b]=function(a){f.style(a.elem,b,Math.max(0,a.now)+a.unit)})}),f.expr&&f.expr.filters&&(f.expr.filters.animated=function(a){return f.grep(f.timers,function(b){return a===b.elem}).length});var cv,cw=/^t(?:able|d|h)$/i,cx=/^(?:body|html)$/i;"getBoundingClientRect"in c.documentElement?cv=function(a,b,c,d){try{d=a.getBoundingClientRect()}catch(e){}if(!d||!f.contains(c,a))return d?{top:d.top,left:d.left}:{top:0,left:0};var g=b.body,h=cy(b),i=c.clientTop||g.clientTop||0,j=c.clientLeft||g.clientLeft||0,k=h.pageYOffset||f.support.boxModel&&c.scrollTop||g.scrollTop,l=h.pageXOffset||f.support.boxModel&&c.scrollLeft||g.scrollLeft,m=d.top+k-i,n=d.left+l-j;return{top:m,left:n}}:cv=function(a,b,c){var d,e=a.offsetParent,g=a,h=b.body,i=b.defaultView,j=i?i.getComputedStyle(a,null):a.currentStyle,k=a.offsetTop,l=a.offsetLeft;while((a=a.parentNode)&&a!==h&&a!==c){if(f.support.fixedPosition&&j.position==="fixed")break;d=i?i.getComputedStyle(a,null):a.currentStyle,k-=a.scrollTop,l-=a.scrollLeft,a===e&&(k+=a.offsetTop,l+=a.offsetLeft,f.support.doesNotAddBorder&&(!f.support.doesAddBorderForTableAndCells||!cw.test(a.nodeName))&&(k+=parseFloat(d.borderTopWidth)||0,l+=parseFloat(d.borderLeftWidth)||0),g=e,e=a.offsetParent),f.support.subtractsBorderForOverflowNotVisible&&d.overflow!=="visible"&&(k+=parseFloat(d.borderTopWidth)||0,l+=parseFloat(d.borderLeftWidth)||0),j=d}if(j.position==="relative"||j.position==="static")k+=h.offsetTop,l+=h.offsetLeft;f.support.fixedPosition&&j.position==="fixed"&&(k+=Math.max(c.scrollTop,h.scrollTop),l+=Math.max(c.scrollLeft,h.scrollLeft));return{top:k,left:l}},f.fn.offset=function(a){if(arguments.length)return a===b?this:this.each(function(b){f.offset.setOffset(this,a,b)});var c=this[0],d=c&&c.ownerDocument;if(!d)return null;if(c===d.body)return f.offset.bodyOffset(c);return cv(c,d,d.documentElement)},f.offset={bodyOffset:function(a){var b=a.offsetTop,c=a.offsetLeft;f.support.doesNotIncludeMarginInBodyOffset&&(b+=parseFloat(f.css(a,"marginTop"))||0,c+=parseFloat(f.css(a,"marginLeft"))||0);return{top:b,left:c}},setOffset:function(a,b,c){var d=f.css(a,"position");d==="static"&&(a.style.position="relative");var e=f(a),g=e.offset(),h=f.css(a,"top"),i=f.css(a,"left"),j=(d==="absolute"||d==="fixed")&&f.inArray("auto",[h,i])>-1,k={},l={},m,n;j?(l=e.position(),m=l.top,n=l.left):(m=parseFloat(h)||0,n=parseFloat(i)||0),f.isFunction(b)&&(b=b.call(a,c,g)),b.top!=null&&(k.top=b.top-g.top+m),b.left!=null&&(k.left=b.left-g.left+n),"using"in b?b.using.call(a,k):e.css(k)}},f.fn.extend({position:function(){if(!this[0])return null;var a=this[0],b=this.offsetParent(),c=this.offset(),d=cx.test(b[0].nodeName)?{top:0,left:0}:b.offset();c.top-=parseFloat(f.css(a,"marginTop"))||0,c.left-=parseFloat(f.css(a,"marginLeft"))||0,d.top+=parseFloat(f.css(b[0],"borderTopWidth"))||0,d.left+=parseFloat(f.css(b[0],"borderLeftWidth"))||0;return{top:c.top-d.top,left:c.left-d.left}},offsetParent:function(){return this.map(function(){var a=this.offsetParent||c.body;while(a&&!cx.test(a.nodeName)&&f.css(a,"position")==="static")a=a.offsetParent;return a})}}),f.each({scrollLeft:"pageXOffset",scrollTop:"pageYOffset"},function(a,c){var d=/Y/.test(c);f.fn[a]=function(e){return f.access(this,function(a,e,g){var h=cy(a);if(g===b)return h?c in h?h[c]:f.support.boxModel&&h.document.documentElement[e]||h.document.body[e]:a[e];h?h.scrollTo(d?f(h).scrollLeft():g,d?g:f(h).scrollTop()):a[e]=g},a,e,arguments.length,null)}}),f.each({Height:"height",Width:"width"},function(a,c){var d="client"+a,e="scroll"+a,g="offset"+a;f.fn["inner"+a]=function(){var a=this[0];return a?a.style?parseFloat(f.css(a,c,"padding")):this[c]():null},f.fn["outer"+a]=function(a){var b=this[0];return b?b.style?parseFloat(f.css(b,c,a?"margin":"border")):this[c]():null},f.fn[c]=function(a){return f.access(this,function(a,c,h){var i,j,k,l;if(f.isWindow(a)){i=a.document,j=i.documentElement[d];return f.support.boxModel&&j||i.body&&i.body[d]||j}if(a.nodeType===9){i=a.documentElement;if(i[d]>=i[e])return i[d];return Math.max(a.body[e],i[e],a.body[g],i[g])}if(h===b){k=f.css(a,c),l=parseFloat(k);return f.isNumeric(l)?l:k}f(a).css(c,h)},c,a,arguments.length,null)}}),a.jQuery=a.$=f,typeof define=="function"&&define.amd&&define.amd.jQuery&&define("jquery",[],function(){return f})})(window);

// WARNING: Removed iScroll

/*
 * Scrollbox turns a given element into a scrollable area. The scrollbox
 * element should have class="scrollbox"; it will grow to the height of
 * its parent element minus the combined height of all siblings.
 */
function Scrollbox(elem, options) {
  var self = this;
  var point1;
  var point2;
  var y0 = 0;
  var y1 = 0;
  var deltaY = 0;
  var tensionY = 0;
  var tensionX = 0;
  var elementHeight = 0;
  var childHeight = 0;
  var x0 = 0;
  var x1 = 0;
  var deltaX = 0;
  var elementWidth = 0;
  var childWidth = 0;
  var child;
  var tension = 2.5;
  var mousing = false;
  var settings;
  var enabled = true;
  var defaults = {
    scrollDirection: "vertical"
  };

  var freeImages = function (elem) {
      var imgs = elem.querySelectorAll("img");
      for (var i = 0; i < imgs.length; i++) {
          imgs[i].src = "../img/blank.png";
      }
  };

  var boundY = function (y) {
    if( elementHeight === 0 || childHeight === 0 ) {
      elementHeight = elem.offsetHeight;
      childHeight = child.offsetHeight;
    }

    return Math.round(Math.min(0, Math.max(y, elementHeight - childHeight)));
  };

  var boundX = function (x) {
    if( elementWidth === 0 || childWidth === 0 ) {
      elementWidth = elem.offsetWidth;
      childWidth = child.offsetWidth;
    }
    return Math.round(Math.min(0, Math.max(x, elementWidth - childWidth)));
  };

  var init = function () {
    settings = $.extend( {}, defaults, options );
    ScrollUtil.init();

    elem.innerHTML = "<div class=\"flow\">" + elem.innerHTML + "</div>";

    child = elem.firstChild;

    elem.style.setProperty("height", ScrollUtil.getAvailableHeight(elem) + "px");

    var touchstart = function (touch) {
      if( !enabled ) {
        return;
      }

      ScrollUtil.transition(child, "0s linear");

      if(settings.scrollDirection === "vertical" ) {
        y0 = elem.getBoundingClientRect().top;
        deltaY = 0;
        elementHeight = elem.offsetHeight;
        childHeight = child.offsetHeight;
        point1 = new Point(touch.pageX, touch.pageY);
        y1 = child.getBoundingClientRect().top - y0;
        ScrollUtil.transform(child, "0", y1 + "px");
      } else {
        x0 = 0;
        dX = 0;
        elementWidth = elem.offsetWidth;
        ec = elem.offsetWidth;
        point1 = new Point(touch.pageX, touch.pageY);
        x1 = child.getBoundingClientRect().left;
        ScrollUtil.transform(child, x1, "0");
      }

      $( elem ).trigger( "scrollstart" );
    };

    var touchmove = function (touch) {
      if( !enabled ) {
        return;
      }
      point2 = new Point(touch.pageX, touch.pageY);

      if( settings.scrollDirection === "vertical" ) {
        deltaY = point2.distanceY(point1);
        tensionY = y1;

        if (Math.abs(deltaY) > 5) {
          tensionY += deltaY;
        }

        // tension up or down.
        if (tensionY > 0) {
          tensionY = tensionY / tension;
        } else if (tensionY < elementHeight - childHeight) {
          tensionY += (elementHeight - (Math.max(elementHeight, childHeight) + tensionY)) / tension;
        }

        ScrollUtil.transform(child, "0", tensionY + "px");
        y1 = Math.round(y1 + deltaY);
      } else {
        deltaX = point2.distanceX(point1);
        tensionX = x1;

        if (Math.abs(deltaX) > 5) {
          tensionX += deltaX;
        }

        // tension left or right
        if (tensionX > 0) {
          tensionX = tensionX  / tension;
        } else if (tensionX < elementWidth - childWidth) {
          tensionX += (elementWidth - (Math.max(elementWidth, childWidth) + tensionX)) / tension;
        }

        ScrollUtil.transform(child, tensionX + "px", "0");
          x1 = Math.round(x1 + deltaX);
      }
      point1 = point2;
    };

    var touchend = function () {
      if( !enabled ) {
        return;
      }

      if(settings.scrollDirection === "vertical" ) {
        self.scrollToY(y1 + (deltaY * Math.abs(deltaY) * 0.75));
      } else {
        self.scrollToX(x1 + (deltaX * Math.abs(deltaX) * 0.75));
      }
      $( elem ).trigger( "scrollend" );
    };

    if ( bc.utils.hasTouchSupport() ) {
      elem.addEventListener("touchstart", function (evt) {
        if (evt.touches) {
          touchstart(evt.touches[0]);
        }
      });

      elem.addEventListener("touchmove", function (evt) {
        if (evt.touches) {
          touchmove(evt.touches[0]);
        }
      });

      elem.addEventListener("touchend", function (evt) {
        touchend();
      });
    } else {
      elem.addEventListener("mousedown", function (evt) {
        mousing = true;
        touchstart(evt);
      });

      elem.addEventListener("mousemove", function (evt) {
        if (mousing) {
          touchmove(evt);
        }
      });

      elem.addEventListener("mouseup", function (evt) {
        if (mousing) {
          mousing = false;
          touchend();
        }
      });
    }

    if (elem.id) {
      Scrollbox.all[elem.id] = self;
    }

    if( !bc.utils.hasTouchSupport() ) {
      $( document ).on( "mousedown", "img", function( evt ) {
        evt.preventDefault();
        evt.stopPropagation();
      });
    }

    // corrects a rendering bug in android 2.x. (9/6/2012)
    self.scrollToY(0, 0);
  };

  this.scrollToY = function (y, timing ) {
    timing = timing || "500ms cubic-bezier(0.250, 0.460, 0.450, 0.940)";
    y1 = boundY(y);
    ScrollUtil.transform(child, "0", y1 + "px");
    ScrollUtil.transition(child, timing );
    $( child ).one( "webkitTransitionEnd", function() {
      $( elem ).trigger( "scrollend" );
    });
  };

  this.scrollToX = function (x, timing) {
    timing = timing || "500ms cubic-bezier(0.250, 0.460, 0.450, 0.940)";
    x1 = boundX(x);
    ScrollUtil.transform(child, x1 + "px", "0");
    ScrollUtil.transition(child, timing );
    $( child ).one( "webkitTransitionEnd", function() {
      $( elem ).trigger( "scrollend" );
    });
  };

  this.setScrollingDirection = function (direction) {
    //TODO - set jQuery child as a global object
    var $child = $( child );
    $child.width( $child.children().width() );
    elementWidth = elem.offsetWidth;
    childWidth = child.offsetWidth;
    settings.scrollDirection = direction;
  };

  this.disable = function() {
    enabled = false;
  };

  this.enable = function() {
    enabled = true;
  };

  // resize to fit available height. do not call directly
  this.resize = function () {
    height = ScrollUtil.getAvailableHeight(elem);
    elem.style.setProperty("height", height + "px");

    //TODO - handle resize for landscape
    elementHeight = elem.offsetHeight;
    childHeight = child.offsetHeight;
    y1 = boundY(y1);

    ScrollUtil.transform(child, "0", y1 + "px");
    ScrollUtil.transition(child, "0ms linear");
  };

  // get the HTML content of this scrollbox
  this.getContent = function () {
    return child.innerHTML;
  };

  // update the HTML content of this scrollbox
  this.setContent = function (html) {
    freeImages(elem);

    child.innerHTML = html;
  };

  // snap to the top
  this.top = function () {
    y1 = 0;
    ScrollUtil.transform(child, "0", "0");
    ScrollUtil.transition(child, "0s linear");
  };

  this.clear = function () {
    freeImages(elem);

    this.setContent("");
    this.top();
  };

  init();
}

Scrollbox.all = {};

Scrollbox.get = function (elemId) {
  return Scrollbox.all[elemId];
};

// Point holds an arbitrary location measured from top left
function Point(x, y) {
  this.x = x;
  this.y = y;
}

Point.prototype.distanceX = function (point) {
  return this.x - point.x;
};

Point.prototype.distanceY = function (point) {
  return this.y - point.y;
};

/*
 * Static helper and init functions used by Scrollbox
 */
var ScrollUtil = {};

// add listeners, add css rules
ScrollUtil.init = function () {
  // do just once
  if (ScrollUtil.inited) {
    return;
  }

  var orientation = bc.context.viewOrientation;

  // WARNING: Commented out, since this breaks native scrolling
  //document.body.addEventListener("touchmove", function (evt) {
  //  evt.preventDefault();
  //});

  //window.addEventListener("resize", function (evt) {
  $( bc ).bind( "vieworientationchange", function() {
    //var o =window.innerWidth > window.innerHeight ? "L" : "P";
    if ( bc.context.viewOrientation === orientation) {
      return;
    }
    orientation = bc.context.viewOrientation;
    // resize scrollboxes

    for (var s in Scrollbox.all) {
      Scrollbox.all[s].resize();
    }
  });

  var css = {
    "html": [
      "width: 100%"
    ],
    ".scrollbox": [
      "overflow: hidden"
    ],
    ".scrollbox > .flow": [
      "-webkit-transform: translate3d(0, 0, 0)"
    ]
  };

  var sheet = document.styleSheets[0];

  for (var c in css) {
    sheet.addRule(c, css[c].join(";"));
  }

  ScrollUtil.inited = true;
};

// apply a 3D transform to an element
ScrollUtil.transform = function (elem, x, y) {
  elem.style.setProperty("-webkit-transform", "translate3d(" + x + ", " + y + ", 0)");
};

// apply a CSS transition to an element's transform
// value is expressed as "time curve", e.g. "500ms linear"
ScrollUtil.transition = function (elem, value) {
  elem.style.setProperty("-webkit-transition", "-webkit-transform " + value);
};

// get the available height for an element
ScrollUtil.getAvailableHeight = function (elem) {
  var parent = elem.parentElement;
  var sibs = parent.childNodes;
  var h = 0;

  var isStatic = function (style) {
    return ["static", "relative"].indexOf(style.position) > -1;
  };

  var isBlock = function (style) {
    return style.display !== "inline-block" && style.float === "none";
  };

  for (var i in sibs) {
    if (sibs[i] !== elem) {
      var style = window.getComputedStyle(sibs[i]);
      if (style && isStatic(style) && isBlock(style)) {
        h += sibs[i].offsetHeight || 0;
      }
    }
  }

  return parent.getBoundingClientRect().height - h;
};

// Get the available width for an element
ScrollUtil.getAvailableWidth = function (elem) {
  return elem.parentElement.offsetWidth;
};
/*
  Markup.js v1.5.12: http://github.com/adammark/Markup.js
  MIT License
  (c) 2011 Adam Mark
*/
var Mark={includes:{},globals:{},delimiter:">",compact:false,_copy:function(d,c){c=c||[];for(var e in d){c[e]=d[e]}return c},_size:function(b){return b instanceof Array?b.length:(b||0)},_iter:function(a,b){this.idx=a;this.size=b;this.length=b;this.sign="#";this.toString=function(){return this.idx+this.sign.length-1}},_pipe:function(h,d){var c=d.shift(),g,b,a;if(c){g=c.split(this.delimiter);b=g[0].trim();a=g.splice(1);try{h=this._pipe(Mark.pipes[b].apply(null,[h].concat(a)),d)}catch(f){}}return h},_eval:function(e,g,h){var a=this._pipe(e,g),b=a,d=-1,c,f;if(a instanceof Array){a="";c=b.length;while(++d<c){f={iter:new this._iter(d,c)};a+=h?Mark.up(h,b[d],f):b[d]}}else{if(a instanceof Object){a=Mark.up(h,b)}}return a},_test:function(a,f,d,b){var e=Mark.up(f,d,b).split(/\{\{\s*else\s*\}\}/),c=(a===false?e[1]:e[0]);return Mark.up(c||"",d,b)},_bridge:function(g,e){var f="{{\\s*"+e+"([^/}]+\\w*)?}}|{{/"+e+"\\s*}}",l=new RegExp(f,"g"),n=g.match(l),m,k=0,j=0,i=-1,h=0;for(m in n){i=g.indexOf(n[m],i+1);if(n[m].match("{{/")){j++}else{k++}if(k===j){break}}k=g.indexOf(n[0]);j=k+n[0].length;h=i+n[m].length;return[g.substring(k,h),g.substring(j,i)]}};Mark.up=function(s,b,e){b=b||{};e=e||{};var m=/\{\{\w*[^}]+\w*\}\}/g,l=s.match(m)||[],t,d,g,h=[],r,c,f,n,k,o,a,q=0,p=0;if(e.pipes){this._copy(e.pipes,this.pipes)}if(e.includes){this._copy(e.includes,this.includes)}if(e.globals){this._copy(e.globals,this.globals)}if(e.delimiter){this.delimiter=e.delimiter}if(e.compact!==undefined){this.compact=e.compact}while((t=l[q++])){k=undefined;f="";r=t.indexOf("/}}")>-1;d=t.substr(2,t.length-(r?5:4));d=d.replace(/`([^`]+)`/g,function(i,j){return Mark.up("{{"+j+"}}",b)});c=d.trim().indexOf("if ")===0;h=d.split("|").splice(1);d=d.replace(/^\s*if/,"").split("|").shift().trim();g=c?"if":d.split("|")[0];n=b[d];if(c&&!h.length){h=["notempty"]}if(!r&&s.indexOf("{{/"+g)>-1){k=this._bridge(s,g);t=k[0];f=k[1];q+=t.match(m).length-1}if(/^\{\{\s*else\s*\}\}$/.test(t)){continue}else{if((o=this.globals[d])!==undefined){k=this._eval(o,h,f)}else{if((a=this.includes[d])){if(a instanceof Function){a=a()}k=this._pipe(Mark.up(a,b),h)}else{if(d.match(/#{1,2}/)){e.iter.sign=d;k=this._pipe(e.iter,h)}else{if(d==="."){k=this._pipe(b,h)}else{if(d.match(/\./)){d=d.split(".");n=Mark.globals[d[0]];if(n){p=1}else{p=0;n=b}while(n&&p<d.length){n=n[d[p++]]}k=this._eval(n,h,f)}else{if(c){k=this._pipe(n,h)}else{if(n instanceof Array){k=this._eval(n,h,f)}else{if(f){k=n?Mark.up(f,n):undefined}else{if(b.hasOwnProperty(d)){k=this._pipe(n,h)}}}}}}}}}}if(c){k=this._test(k,f,b,e)}s=s.replace(t,k===undefined?"???":k)}return this.compact?s.replace(/>\s+</g,"><"):s};Mark.pipes={empty:function(a){return !a||(a+"").trim().length===0?a:false},notempty:function(a){return a&&(a+"").trim().length?a:false},blank:function(b,a){return !!b||b===0?b:a},more:function(d,c){return Mark._size(d)>c?d:false},less:function(d,c){return Mark._size(d)<c?d:false},ormore:function(d,c){return Mark._size(d)>=c?d:false},orless:function(d,c){return Mark._size(d)<=c?d:false},between:function(e,d,f){e=Mark._size(e);return e>=d&&e<=f?e:false},equals:function(d,c){return d==c?d:false},notequals:function(d,c){return d!=c?d:false},like:function(b,a){return new RegExp(a,"i").test(b)?b:false},notlike:function(b,a){return !Mark.pipes.like(b,a)?b:false},upcase:function(a){return String(a).toUpperCase()},downcase:function(a){return String(a).toLowerCase()},capcase:function(a){return a.replace(/\b\w/g,function(b){return b.toUpperCase()})},chop:function(a,b){return a.length>b?a.substr(0,b)+"...":a},tease:function(c,d){var b=c.split(/\s+/);return b.slice(0,d).join(" ")+(b.length>d?"...":"")},trim:function(a){return a.trim()},pack:function(a){return a.trim().replace(/\s{2,}/g," ")},round:function(a){return Math.round(+a)},clean:function(a){return String(a).replace(/<\/?[^>]+>/gi,"")},size:function(a){return a.length},length:function(a){return a.length},reverse:function(a){return Mark._copy(a).reverse()},join:function(a,b){return a.join(b)},limit:function(b,c,a){return b.slice(+a||0,+c+(+a||0))},split:function(b,a){return b.split(a||",")},choose:function(b,c,a){return !!b?c:(a||"")},toggle:function(c,b,a,d){return a.split(",")[b.match(/\w+/g).indexOf(c+"")]||d},sort:function(a,c){var b=function(e,d){return e[c]>d[c]?1:-1};return Mark._copy(a).sort(c?b:undefined)},fix:function(a,b){return(+a).toFixed(b)},mod:function(a,b){return(+a)%(+b)},divisible:function(a,b){return a&&(+a%b)===0?a:false},even:function(a){return a&&(+a&1)===0?a:false},odd:function(a){return a&&(+a&1)===1?a:false},number:function(a){return parseFloat(a.replace(/[^\-\d\.]/g,""))},url:function(a){return encodeURI(a)},bool:function(a){return !!a},falsy:function(a){return !a},first:function(a){return a.idx===0},last:function(a){return a.idx===a.size-1},call:function(b,a){return b[a].apply(b,[].slice.call(arguments,2))},set:function(b,a){Mark.globals[a]=b;return""},log:function(a){console.log(a);return a}}; /*global bc:true, atob:false*/
/*jshint indent:2, browser: true, white: false devel:true undef:false*/


/**
 * bc is the namespace for all functions, properties, and events available through the Brightcove App Cloud SDK.
 * @namespace
 */
var bc = {};

/**
 * Brightcove core is responsible for communicating with the Brightcove App Cloud server, storing the responses from the server,
 * and messaging the appropriate events.
 * @namespace
 */
bc.core = {};

/**
 * Import required 3rd party libraries and namespace so as not to conflict with other versions
 */
bc.lib = {};

// namespace our version of jQuery and reset the global vars of $,jQuery back to what they were
( function() {
  bc.lib.jQuery = jQuery.noConflict(true);
  if ( jQuery === undefined ) {
    jQuery = bc.lib.jQuery;
    $ = jQuery;
  }
})();

( function( $, undefined ) {
  //tracks whether or not we have set ads yet.
  var _adsSet,
      _globalDataRequestPollCount = {},
      _markupLoaded = false,
      _localeResourceFileLoaded = false;

  /** @private The URL of the App Cloud Studio. */
  bc.SERVER_URL = ( "%SERVER_URL%".indexOf( "%" ) > -1 ) ? "http://read.appcloud.brightcove.com" : "%SERVER_URL%";

  /** @private The URL of the server we will send metrics to. */
  bc.METRICS_SERVER_URL = ( "%METRICS_SERVER_URL%".indexOf( "%" ) > -1 ) ? "http://metrics.brightcove.com" : "%METRICS_SERVER_URL%";

  /** This is a unique ID that is generated when the application is created in the Brightcove App Cloud Studio.  During development this will be undefined, since the application has not been created by the Studio yet. */
  bc.appID = null;

  /** This is a unique ID that generated for this specific "view" when the application is created in the App Cloud Studio.  During development this will be the URL of the view, since the URL is a unique string. */
  bc.viewID = null;

  /** This the unique ID that represents the App Cloud account that this application is part of.  During development this will be undefined. */
  bc.accountID = null;

  /** @private The SQLite database that we use to track our localStorage usage.  See bc.core.cache and pruneCache to see how this is used. */
  bc.db = null;

  /**
   * Context object that exposes information related to the current state of the application.  The following properties exist
   * on the context object:
   * <ul>
   *   <li>viewOrientation: A string that will match either <code>portrait</code> or <code>landscape</code>.  Represents the orientation of the view on the phone.  NOTE:
   *       this is different from device orientation.  For example, the phone might actually be held in landscape mode but the view does not autorotate,
   *       in which case the view would still be in <code>portrait</code> mode.</li>
   *   <li>os: A string that will match either <code>ios</code> or <code>android</code>. </li>
   *   <li>isNative: A boolean value indicating whether or not we are running inside a native container on a device.</li>
   *   <li>moreNavigationView: A boolean value indicating whether or not the current view falls under the "more" section.  (Specific to iOS)</li>
   *   <li>version: The version of the SDK.</li>
   * </ul>
   * @namespace
   */
  bc.context = { version: "1.11" };

  /**
   * If a developer uses the <a href="http://support.brightcove.com/en/docs/using-markup-templates">markup templating</a> system included in the SDK
   * then any layouts specified in the .txt file will be populated onto the bc.templates object.  For example if your markup.txt file has the following
   * layout: <br>
   <pre>===== example-tmpl
&lt;h1&gt;My Example&lt;/h1&gt;
&lt;p&gt;Example paragraph.  Really any HTML can go here&lt;/p&gt;
   </pre>
   <br>
   Then after the bc.init event is fired the bc.templates object will now have a property of "example-tmpl".  This can be referenced as bc.templates["example-tmpl"] and
   passed into the Mark.up function. For example:
   <pre>var html = Mark.up( bc.templates["example-tmpl"] );
$( "body" ).html( html );</pre>
   Would set the body of the page to <pre>
&lt;h1&gt;My Example&lt;/h1&gt;
&lt;p&gt;Example paragraph.  Really any HTML can go here&lt;/p&gt;
  </pre>
   * @namespace
   */
  bc.templates = {};

  /**
   * The different modes the application can be running in. One of the strings listed in <a href="../bc.core.mode.html">bc.core.mode</a>.
   * @namespace
   */
  bc.core.mode = {};

  /**
   * The configuration object.  The following properties can be set on this object to control the behavior of the SDK.  Properties
   * can be set on this object after the 'init' event has fired on the bc object.
   *
   * <p/>
   * The following properties can be set on this object:
   * <ul>
   *   <li>touchEventsEnabled: Whether or not the App Cloud SDK should detect and fire gestures events such as tap, swipe.  Enabled by
   *       default.  Turn this off if you are using a third party library, such as hammer.js, that will be detecting and firing these events.
   * </ul>
   *
   * @namespace
   */
  bc.config = {};

  /** An application is in development mode if it has not been ingested into the Brightcove App Cloud Studio. */
  bc.core.mode.DEVELOPMENT = "development";
  /**
   * An application is in production mode once it has been created in the Brightcove App Cloud Studio, using
   *  a previously ingested template. */
  bc.core.mode.PRODUCTION = "production";
  /** An application is in preview mode if it is being previewed in the Brightcove App Cloud Studio.*/
  bc.core.mode.PREVIEW = "preview";
  /** The current mode that the application is running in. */
  bc.core.current_mode = bc.core.mode.DEVELOPMENT;
  /** App level configurations*/
  bc.currentGlobalConfigs = undefined;


  /***************************************************************************************
    * Private helper functions
    ***************************************************************************************/

   function findValueInObject( object, name ) {
     if( $.isPlainObject( object ) ) {
       return object;
     }

     for( var i = 0, len = object.length; i < len; i++ ) {
       if( object[i].name === name ) {
         return object[i];
       }
     }
     return {};
   }

   /* Calculates the URL to be used to make the request to the appcloud server.*/
   function getContentFeedURL( contentFeed ) {
     var url,
        feedValueFromManifest = bc.core.getManifestConfiguration( { "type": "data", "name": contentFeed } );

     if( bc.core.current_mode === bc.core.mode.DEVELOPMENT ) {
      contentFeed = ( feedValueFromManifest === null ) ? contentFeed : feedValueFromManifest;
      url = bc.SERVER_URL + "/content/" + contentFeed + "/fetch";
     } else {
      if( feedValueFromManifest === null ) {
        url = bc.SERVER_URL + "/content/" + contentFeed + "/fetch";
      } else {
        url = bc.SERVER_URL + "/apps/" + bc.appID + "/views/" + bc.viewID + "/data.json?content_feed_name=" + contentFeed;
      }
     }

     return url;
   }

   function storeGlobalConfigs( global ) {
     if( !bc.utils.isEqual( global, bc.currentGlobalConfigs ) ) {
       bc.core.cache( bc.appID + "_global_configs", global );
       bc.currentGlobalConfigs = global;
       return true;
     }

     return false;
   }

  function storeSettings( settings ) {
     if( !bc.utils.isEqual( settings, bc.core.cache( bc.viewID + "_settings" ) ) ) {
       bc.core.cache( bc.viewID + "_settings", settings );
       return true;
     }
     return false;
   }

  function storeStyles( styles ) {
    if( !bc.utils.isEqual( styles, bc.core.cache( bc.viewID + "_styles" ) ) ) {
      bc.core.cache( bc.viewID + "_styles", styles );
      return true;
    }
    return false;
  }

  function createTables() {
    if( !bc.db ) {
      return;
    }

    bc.db.transaction(
      function (transaction) {
        transaction.executeSql( "CREATE TABLE IF NOT EXISTS components(id INTEGER NOT NULL PRIMARY KEY, component_id TEXT NOT NULL, modified TIMESTAMP NOT NULL);" );
      }
    );
  }

  function bcAppDB() {
    if( typeof( window.openDatabase ) !== "function") {
      return null;
    }

    try {
      bc.db = window.openDatabase(bc.appID, "1.0", "BC_" + bc.appID, 1024*1024);
      createTables();
    } catch(e) {
      bc.utils.warn("THERE WAS AN ERROR OPENING THE DB");
      bc.db = null;
    }
  }

  function setGlobalIDValues() {
    bc.viewID = $( "body" ).data( "bc-view-id" ) || location.href;
    bc.appID = $( "body" ).data( "bc-app-id" );
    bc.accountID = $( "body" ).data( "bc-account-id" );

    if( bc.appID !== undefined) {
     if( bc.core.isPreview() ) {
       bc.core.current_mode = bc.core.mode.PREVIEW;
     } else {
       bc.core.current_mode = bc.core.mode.PRODUCTION;
     }
    }
    bcAppDB();
  }

  function pruneCache() {
    if( bc.db !== null ) {
     var ids_to_remove = "";
     bc.db.transaction(
       function (transaction) {
         transaction.executeSql( "SELECT component_id from components ORDER BY modified;", [], function( tx, results ) {
           for ( var i = 0, len = results.rows.length; i < len/2; i++ ) {
             var item = results.rows.item( i ).component_id;
             window.localStorage.removeItem( item );
             ids_to_remove += "component_id = '" + item + "' OR ";
           }

           //Once we have cleaned up the local storage we should now clean up the DB.
           ids_to_remove = ids_to_remove.substring( 0, ( ids_to_remove.length - 4 ) );
           bc.db.transaction(
             function (transaction) {
               transaction.executeSql( "DELETE FROM components WHERE " + ids_to_remove + ";", [] );
             }
           );
         });
       }
     );
    } else {
      //If there is no DB then we do not have a more intelligent way to prune other then to remove
      window.localStorage.clear();
    }
  }

  function updateDB(component_id) {
    if(bc.db === null) {
     return;
    }

    bc.db.transaction(
      function (transaction) {
        transaction.executeSql( "SELECT component_id FROM components WHERE component_id ='" + component_id +"';", [], function( tx, results ) {
          if(results.rows.length === 0) {
            bc.db.transaction(
              function ( transaction ) {
                transaction.executeSql( "INSERT INTO components (component_id, modified) VALUES ('" + component_id + "', '" + Date() + "');" );
              }
            );
          } else {
            bc.db.transaction(
              function ( transaction ) {
                transaction.executeSql( "UPDATE components SET modified = '" + Date() + "' WHERE component_id ='" + component_id + "';" );
              }
            );
          }
        });
      }
    );
  }

  function storeAdConfigurations( adConfigsFromServer ) {
    var adConfigs,
        defaults = {
          "ad_code": undefined,
          "ad_position": "none",
          "ad_network": "admob"
        };

    adConfigs = $.extend( {}, defaults, adConfigsFromServer );

    adConfigs.should_show_ad = ( !!adConfigs.ad_code && !!adConfigs.ad_position && adConfigs.ad_position !== "none" );
    bc.core.cache( bc.viewID + "_ad_settings", adConfigs );
    setAdPolicy( adConfigs );
  }

  function setAdPolicy( adConfigs ) {
    adConfigs = adConfigs || bc.core.cache( bc.viewID + "_ad_settings");
    //If we have already set an ad policy we do not want to do again.
    if ( _adsSet !== undefined ) {
      return;
    }

    if( adConfigs && bc.device !== undefined && bc.device.setAdPolicy !== undefined ) {
      bc.device.setAdPolicy( adConfigs );
      _adsSet = true;
    }
  }

   /***************************************************************************************
    * End of private helper functions
    ***************************************************************************************/

  /**
   * Depending on whether one or two values are passed into the cache function, it will either read values from or write
   * values to the localStorage.  Note that there is a limit of 5MB that can be stored in this cache
   * at any given time.  If this cache fills up, then we remove half the items from the cache.  We use a
   * LRU (least recently used) cache algorithm to select what should be removed.
   *
   * @param key The key for where the value is stored.
   * @param value The value that should be stored in the localStorage.
   * @return If only a key is passed in, then the value is returned. If no value is found, null is returned.
   * @example
   //Note that the cache is persisted across startups.
   bc.core.cache( "whales" ); //returns null because it has never been set.
   bc.core.cache( "whales", "a pod of whales" ); //sets the value of the key "whales"
   bc.core.cache( "whales" ); //returns "a pod of whales"
   */
  bc.core.cache = function( key, value ) {
    var ret;

    try {
      if( value !== undefined ){
        try {
          window.localStorage.setItem( key, JSON.stringify( value ) );
          updateDB( key );
          return value;
        } catch( e ) {
          bc.utils.warn( "ERROR: we are assuming that our local storage is full and will now remove half of the existing cache:" + e.toString() );
          pruneCache();
        }
      } else {
        ret = JSON.parse( window.localStorage.getItem( key ) );
        if( ret !== null ) {
          try {
            updateDB( key );
          } catch ( e ) {
            bc.utils.warn( 'ERROR: we were unable to updated the DB with this cache hit' );
          }
        }
        return ret;
      }
    } catch( e ) {
      bc.utils.warn( "Error storing and/or receiving values in local storage: " + e.toString() );
      return null;
    }
  };

  /**
   * Fetches the data for this contentFeed.  This can take in a contentFeed ID or the name of a feed defined for this view in the <code>manifest.json</code> file.
   *
   * @param contentFeed The ID of the contentFeed or the name of the feed, if configurations are defined in the <code>manifest.json</code> file.  The contentFeed ID can be found in the Content section of the App Cloud Studio.
   * @param successCallback The function to call once the data has been retrieved.
   * @param errorCallback The function to call if there is an error retrieving data.
   * @param options An object defining the options for this request. Possible values are:
        <ul>
          <li> parameterizedFeedValues: The query params to pass to the contentFeed as parameters.  See <a href="https://docs.brightcove.com/en/app-cloud-beta/using-parameters-in-content-feed-urls" >Using parameters in content feed URLs</a> for how parameterized feeds work.  Defaults to "".
          <li> requestTimeout:  Number of milliseconds before the request is timed out and the error callback is called.  By default it is 30000 ms.
        </ul>
   * @example

    bc.core.getData( "xxxxxxxxxx",
      successHandler,
      errorHandler,
      { "parameterizedFeedValues":
        { "loc": "01950" }
      }
    );

    function successHandler( data ) {
      //Do something with the data.
    }

    function errorHandler() {
      //Handle the error gracefully.
    }
   */
  bc.core.getData = function( contentFeed, successCallback, errorCallback, options ) {
    var settings,
        globalSessionStore,
        isGlobalRequest = bc.core.isGlobalRequest( contentFeed ),
        defaults = {
          "parameterizedFeedValues": "",
          "requestTimeout": 30000
        };

    function success( results ) {
      if( results.status !== undefined ) {

        if( results.status === "ok" && results.data !== undefined ) {
          if ( successCallback ) successCallback( results.data );
        } else {
          if ( errorCallback ) errorCallback( results );
        }

      } else {
        //The /content/{id}/fetch does not return a status.
        if ( successCallback ) successCallback( results );
      }

      //Cache this response.
      if( ( !results.status || results.status === "ok" ) && isGlobalRequest ) {
        window.sessionStorage.setItem( bc.appID + "_data_" + contentFeed, JSON.stringify( results ) );
      }
    }

    function error( err ) {
      console.warn( "There was an error fetching content for contentFeed: " + contentFeed );
      if ( errorCallback ) errorCallback( err );
    }

    settings = $.extend( {}, defaults, options );
    globalSessionStore = window.sessionStorage.getItem( bc.appID + "_" + contentFeed );
    globalSessionStore = ( globalSessionStore === null ) ? globalSessionStore : JSON.parse( globalSessionStore );
    //If this a global data request then we should check to see if there was a request already being made.
    if( isGlobalRequest && globalSessionStore && bc.core.requestExists( globalSessionStore, settings ) ) {
      if( window.sessionStorage.getItem( bc.appID + "_data_" + contentFeed ) ) {
        success( JSON.parse( window.sessionStorage.getItem( bc.appID + "_data_" + contentFeed ) ) );
        return;
      } else {
        bc.core.pollForRequest( contentFeed, successCallback, errorCallback, options );
      }
    }

    $.ajax(
      {
        url: getContentFeedURL( contentFeed ),
        timeout: settings.requestTimeout,
        dataType: "jsonp",
        data: ( options && options.parameterizedFeedValues ) ? { "query_params": options.parameterizedFeedValues } : "",
        success: success,
        error: error
      }
    );

    if( isGlobalRequest ) {
      //Make this an array of settings, that I then compare?
      globalSessionStore = ( globalSessionStore ) ? globalSessionStore.push( settings ) : [ settings ];
      window.sessionStorage.setItem( bc.appID + "_" + contentFeed, JSON.stringify( globalSessionStore ) );
    }
  };

  /**
   * @private
   */
  bc.core.requestExists = function( globalSessionStore, settings ) {
    for( var i=0, len=globalSessionStore.length; i<len; i++ ) {
      if( bc.utils.isEqual( globalSessionStore[i], settings ) ) {
        return true;
      }
    }
    return false;
  };

  /**
   * @private
   */
  bc.core.isGlobalRequest = function( contentFeed ) {
    var configs = bc.configurations;

    if( !configs || !configs.data ) {
      return false;
    }

    for( var i=0, len = configs.data.length; i < len; i++ ) {
      if( configs.data[i].name === contentFeed ) {
        return !!configs.data[i].global;
      }
    }
    return false;
  };

  /**
   * @private
   */
  bc.core.pollForRequest = function( contentFeed, successCallback, errorCallback, options ) {
    _globalDataRequestPollCount[ contentFeed ] = _globalDataRequestPollCount[ contentFeed ] || 0;
    if( window.sessionStorage.getItem( bc.appID + "_data_" + contentFeed ) ) {
      _globalDataRequestPollCount[ contentFeed ] = undefined;
      successCallback( JSON.parse( window.sessionStorage.getItem( bc.appID + "_data_" + contentFeed ) ) );
      return;
    }

    //Poll for 30 seconds
    if( _globalDataRequestPollCount[ contentFeed ] < 60 ) {
      _globalDataRequestPollCount[ contentFeed ]++;
      setTimeout( function() {
        bc.core.pollForRequest( contentFeed, successCallback, errorCallback, options );
      }, 500 );
    } else {
      //The request has taken way too long so we are going to clear out the session flag to not make the request and let it hit the server.
      window.sessionStorage.setItem( bc.appID + "_" + contentFeed, null );
      _globalDataRequestPollCount[ contentFeed ] = undefined;
      bc.core.getData( contentFeed, successCallback, errorCallback, options );
    }
  };

  /**
   * Gets a configuration from the configurations defined in the <code>manifest.json</code> file.  All of the configurations for this view are
   * available on the bc.configurations property.  Additionally, the entire <code>manifest.json</code> is available at the global variable of manifest.
   * @param options An object that specifies the configuration type to get and the property to find.  Possible values are:
     <ul>
      <li> type: The configuration type, which can be a data, styles, or settings. </li>
      <li> name: The name of the value to get for the configuration.</li>
    </ul>
    @return The corresponding value for the key inside the type that was passed in or null if no value was found.
    @private
   */
  bc.core.getManifestConfiguration = function( options ) {
    var data, getFeedValue;

    getFeedValue = function( obj ) {
      return ( obj.contentFeed ) ? obj.contentFeed : obj.contentConnector;
    };

    if( bc.configurations && options !== undefined && bc.configurations[options.type] !== undefined ) {
      data = bc.configurations[options.type];

      for( var i = 0, len = data.length; i < len; i++ ) {
        if( data[i].name === options.name ) {
          return ( data[i].value !== undefined ? data[i].value : getFeedValue( data[i] ) );
        }
      }
    }
    return null;
  };

  /**
   * Retrieves the styles from the cache for the current view.
   *
   * @return It is expected that most developers will call <code>applyStyles</code>, which both gets the styles and also renders them to the page.
   * This function will return an object that contains the styles for this particular view or an empty object if no styles are found.
   * @example
   // Styles is an object.
   var styles = bc.core.getStyles();
   */
  bc.core.getStyles = function() {
    var styles,
      viewStyles = bc.core.cache( bc.viewID + "_styles" ),
      globalStyles = bc.core.cache( bc.appID + "_global_configs" ) || {};

    styles = bc.utils.merge( globalStyles.styles, viewStyles );

    if( styles.length === 0 && bc.configurations && bc.configurations.styles ) {
      styles = bc.configurations.styles;
    }

    return styles || [];
  };

  /**
   * @private
   */
  bc.core.getStyleValueFromPreviousStylesByName = function( styleName ) {
    var prevStyles = bc.core.cache( bc.viewID + "_current_styles" );

    //This should never be null as the bootstrap file should always put files into the download state.
    if( prevStyles === null ) {
      console.warn( "getStyleValueFromPreviousStylesByName had no previous styles." );
      return "";
    }

    for( var i=0, len=prevStyles.length; i<len; i++ ) {
      if( prevStyles[i].name === styleName ) {
        return prevStyles[i].value;
      }
    }
    return "";
  };

  /**
   * @private
   */
  bc.core.normalizeStylesForBackgroundImages = function( styles ) {

    bc.device.getDownloadInfo( function( downloadInfoArray ) {
      var needToDownload,
          max = downloadInfoArray.length;
      for( var i=0, len = styles.length; i<len; i++ ) {
        needToDownload = false;
        //If we have a background image that is not an empty string then we need to see if we have downlaoded it.
        if( styles[i].attribute === "background-image" && styles[i].value !== "" ) {
          needToDownload = true;
          for( var j=0; j<max; j++ ) {

            //When find the download that matches this background image we need to see its state and take the appropriate action.
            if( downloadInfoArray[j].resource === bc.SERVER_URL + styles[i].value ) {
              needToDownload = false;
              if( downloadInfoArray[j].state === "complete") {
                styles[i].value = "url(" + downloadInfoArray[j].fileURI + ")";
              } else if( downloadInfoArray[j].state === "errored" ) {
                bc.device.removeDownload( downloadInfoArray[j].downloadID );
                needToDownload = true;
              } else {
                //The file is not downloaded yet so we are going to previous value for this image.
                styles[i].value = bc.core.getStyleValueFromPreviousStylesByName( styles[i].name );
              }
            }
          }
        }

        if( needToDownload ) {
          bc.device.requestDownload( (bc.SERVER_URL + styles[i].value), (bc.SERVER_URL + styles[i].value), undefined, undefined, { returnURLOfResourceInWorkshop: true } );
          styles[i].value = bc.core.getStyleValueFromPreviousStylesByName( styles[i].name );
        }
      }
      bc.core.applyActualStyles( styles );
    });

  };

  /**
   * Applies the styles that are set in the Brightcove App Cloud Studio to the elements.
   *
   * @param styles A JSON object representing the styles for this view.  This object is passed as a data
   * parameter to the <code>newconfigurations</code> event fired on the bc object.
   *
   @example
   $( bc ).on( newconfigurations, function( evt, data ) {
     bc.core.applyStyles( data.styles ); //The new styles, such as background colors, are now applied.
   });
   */
  bc.core.applyStyles = function( styles ) {
    var haveDownloadedImages = false;
    styles = styles || bc.core.getStyles();

    //Check to see if we have any downloaded background images
    if( bc.context.isNative ) {
      for( var i = 0, len = styles.length; i < len; i++ ) {
        if( styles[i].attribute === "background-image" && styles[i].value !== "" && styles[i].value.substring(0,6) === "/files" ) {
          haveDownloadedImages = true;
          break;
        }
      }
    }

    if( haveDownloadedImages ) {
      bc.core.normalizeStylesForBackgroundImages( styles );
    } else {
      bc.core.applyActualStyles( styles );
    }

  };

  /**
   * @private
   */
  bc.core.applyActualStyles = function( styles ) {
    var $styleElement,
        cssString = "";

    if( styles === null || styles === undefined ) {
      return;
    }

    for( i = 0, len = styles.length; i < len; i++ ) {
      if( styles[i].value !== "" ) {
        //We are setting the !important tag in order to override any specificity issues since we know this is the style we want.
        if( styles[i].attribute === "background-image" && styles[i].value.substring(0,4) !== "url(" ) {
          cssString += "." + styles[i].name + " { " + styles[i].attribute + ": url(" + styles[i].value + ") !important; } \n";
        } else {
          cssString += "." + styles[i].name + " { " + styles[i].attribute + ":" + styles[i].value + " !important; } \n";
        }
      }
    }

    //persist this file for next startup
    bc.core.cache( bc.viewID + "_current_styles", styles );

    //Remove any existing stylesheets we have injected
    $( ".injected-style" ).remove();

    $( "<style>" ).attr( "type", "text/css" )
                  .addClass("injected-style" )
                  .html( cssString )
                  .appendTo( "head" );
  };

  /**
   * Retrieves a specific style.  First looks to the cache to get the value, then to the manifest, and if not found in either of those
   * places, it will return an empty object.
   *
   *@param nameOfStyle The name of the style to retrieved.  (This name should correspond to the name in the manifest file.)
   *@return An object that has the CSS class name and the value.
   *@example
   var backgroundStyle = bc.core.getStyle( "background-page-color" ); //background-page-color is the name of the style defined in the manifest file.
   alert( backgroundStyle.cssClass ); //alerts "background-color"
   alert( backgroundStyle.value ); //alerts the value set by the server, for example "#FF00000"
   */
  bc.core.getStyle = function( nameOfStyle) {
    return findValueInObject( bc.core.getStyles(), nameOfStyle );
  };

  /**
   * Retrieves the settings from the cache for the current view.
   *
   * @return An object that contains the settings for this particular view or an empty object if no settings are found.
   * @example
   // Settings is an object.
   var setting = bc.core.getSettings();
   if( bc.core.getSetting( "numberOfColumns" ) > 2 ) {
     //render grid layout.
   }
   */
  bc.core.getSettings = function() {
    var settings,
        viewSettings = bc.core.cache( bc.viewID + "_settings" ),
        globalSettings = bc.core.cache( bc.appID + "_global_configs" ) || {};

    settings = bc.utils.merge( globalSettings.settings, viewSettings );

    if( settings.length === 0 && bc.configurations && bc.configurations.settings ) {
      settings = bc.configurations.settings;
    }

    return settings || [];
  };

  /**
   * bc.core.getSetting is a helper function to get the value of a particular setting.  The reason this is
   * helpful is that the settings for a view are stored as an Array.
   * @param nameOfSetting The name of the setting to get the value for. This should correspond to the name provided in
   * the <code>manifest.json</code> file.
   * @example
   var title = bc.core.getSetting( "titleOfPage" );
   alert( "The title of the page that was defined in the manifest.json and set in the Studio: " + title );
   */
  bc.core.getSetting = function( nameOfSetting ) {
    return findValueInObject( bc.core.getSettings(), nameOfSetting ).value;
  };

  /**
   * <b>Deprecated:</b> use <code>getData</code> instead. <code>fetchContentFeed</code> makes a request to the App Cloud Studio to get the data for a given content feed.
   * @param id The ID of the content feed that was setup in the App Cloud Studio.
   * @param successCallback The function to be called once the data has been retrieved.  This callback will be passed a data object containing the results of the request.
   * @param errorCallback The function to be called if an error occurs retrieving the data.  (Timeout is set to 30 seconds.)
   * @param options If the content feed has dynamic values, they can be passed in via the options object.
   */
  bc.core.fetchContentFeed = function( id, successCallback, errorCallback, options ) {
    var url = bc.SERVER_URL + "/content/" + id + "/fetch";

    $.ajax( { url: url,
              timeout: 30000,
              dataType: "jsonp",
              data: ( options ) ? { "query_params": options } : ""
            }
          ).success( successCallback )
           .error( errorCallback );
  };

  /** @private */
  bc.core.refreshConfigurationsForView = function() {
    //If we are in development mode we should not make this request, as we do not have valid IDs.
    if( bc.core.current_mode === bc.core.mode.DEVELOPMENT ) {
      return;
    }
    var url = bc.SERVER_URL + "/apps/" + bc.appID + "/views/" + bc.viewID + "/configurations.json";

    $.ajax(
      {
        url: url,
        dataType: "jsonp",
        data: { "os": bc.context.os }
      }
    ).success( bc.core.configurationsForViewSuccessHandler );
  };

  /**
   * @private
   */
  bc.core.configurationsForViewSuccessHandler = function( data ) {
    var newSettings,
        newStyles,
        newConfigurations,
        newGlobalConfigs,
        globalConfigs = data.global || {};

    newGlobalConfigs = storeGlobalConfigs( globalConfigs );
    newSettings = storeSettings( data.settings );
    newStyles = storeStyles( data.styles );

    if( newSettings || newStyles || newGlobalConfigs ) {
      newConfigurations = {
        "settings": {
          "isNew": ( newSettings || newGlobalConfigs ),
          "values": bc.utils.merge( globalConfigs.settings, data.settings )
        },
        "styles": {
          "isNew": ( newStyles || newGlobalConfigs ),
          "values": bc.utils.merge( globalConfigs.styles, data.styles )
        }
      };
      bc.core.applyStyles();
      $( bc ).trigger( "newconfigurations", newConfigurations );

      //If we are in preview mode then we want to refresh the page.
      if( bc.core.current_mode === bc.core.mode.PREVIEW ) {
        bc.core.forceUpdate( newConfigurations );
      }
    } else {
      //Trigger an event to the studio so they know we are set.
      if( bc.core.current_mode === bc.core.mode.PREVIEW ) {
        $( bc ).trigger( "preview:ready" );
      }
    }
    storeAdConfigurations( data.ads );
  };

  /**
   * @private
   */
  bc.core.forceUpdate = function( configs ) {
    if( configs.styles.isNew && !configs.settings.isNew ) {
      bc.core.applyStyles();
    } else {
      window.location.reload();
    }
  };

  /**
   * Checks to see whether or not we are in preview mode. (In the App Cloud Studio).
   *
   * @private
   * @return A boolean indicating whether or not we are in preview mode.
   */
  bc.core.isPreview = function() {
    return ( window.location !== window.parent.location ) ? true : false;
  };



/**
 * Public Events
 */
/**
 * The <code>vieworientationchange</code> event is fired anytime that the view itself rotates on the device.  The
 * event will contain three properties: <code>orientation</code>, <code>width</code>, and <code>height</code>. The orientation corresponds to <code>landscape</code> or <code>portrait</code>,
 * and the <code>width</code> and <code>height</code> are the dimensions of the view in the new orientation.  This event is fired on the bc
 * object.
 *
 * @example
 * $( bc ).on( "vieworientationchange", function( evt, rslt ) {
 *   alert("I'm " + rslt.orientation);
 * });
 *
 * @name vieworientationchange
 * @event
 * @memberOf bc
 * @param event (type of vieworientationchange)
 * @param result An object that contains three properties; <code>orientation</code>, <code>width</code>, and <code>height</code>.  The
 * orientation will be the new orientation of the view ['portrait' | 'landscape'].  The <code>width</code> and
 * <code>height</code> will be the width and height of the view (window) in pixels.
 */
  $( window ).on( "resize", function( evt, result ) {
    var newWidth = window.innerWidth,
        newHeight = window.innerHeight,
        orientation = ( newWidth > newHeight ) ? "landscape" : "portrait";

    if ( orientation !== bc.context.viewOrientation ) {
      bc.context.viewOrientation = orientation;
      $( bc ).trigger( "vieworientationchange", {
        "orientation": orientation,
        "width": newWidth,
        "height": newHeight
      });
    }
  });

  /**
   * The <code>init</code> event is triggered at the end of the initialization process.  When the init event is fired the following requirements have been satisfied.
   <ul>
   <li>The <code>bc.context</code> object has been initialized</li>
   <li>Any txt files specified in the markup property of the view in the manifest have been loaded, parsed and populated onto the bc.templates object</li>
   <li>Any txt files specified in locales property of the view in the manifest have been loaded and populated on the Mark.includes name space.</li>
   <li>The documentat has loaded</li>
   </ul>
   * @example
   * $( bc ).on( "init", function(evt) {
   *    alert("BC SDK is initialized.  Can access bc.context such as: "  + bc.context.vieworientation);
   * });
   * @name init
   * @event
   * @memberOf bc
   * @param event
   */
  function triggerInitEvent() {
    if( bc.context.initialized ) {
      return;
    }
    bc.context.initialized = true;
    bc.device.setViewIsReady();
    $( bc ).trigger( "init" );
    bc.core.triggerViewFocusInDevelopmentMode();
  }

  /**
   * If we are developing in the browser then we want the viewfocus event to fire.
   * @private
   */
   bc.core.triggerViewFocusInDevelopmentMode = function() {
     if( !bc.context.isNative && bc.core.current_mode === bc.core.mode.DEVELOPMENT ) {
       $( bc ).trigger( "viewfocus" );
     }
   };

  /**
   * The <code>viewfocus</code> event is triggered when a view gains focus.  Note that this will fire after the init event.
   *
   * @example
   * $( bc ).on( "viewfocus", function( evt ) {
   *    alert( "I am the view that is currently in focus.")
   * });
   * @name viewfocus
   * @event
   * @memberOf bc
   * @param event (type of viewfocus )
   */

   /**
    * The <code>viewblur</code> event is triggered when a view loses focus, meaning that the user has switched to a different view.  When the app is closed, it does trigger a <code>viewblur</code> event.
    *
    * @example
    * $( bc ).on( "viewblur", function( evt ) {
    *    alert( "I am no longer in focus.")
    * });
    * @name viewblur
    * @event
    * @memberOf bc
    * @param event (type of viewblur)
    */

  /**
   * The <code>pushnotification</code> event is triggered on the bc object when a new push notification has been received for this application.  If the app is already running, no pop up notification is shown to the user and a pushnotification event is triggered on the currently
   * visible view with the "appLaunched" property set to false.  If the app is not running then a pop up notification is shown to the user; if the user interacts with the pop up, then the app is launched and an event is triggered on the first view with the "appLaunched" property
   * set to true.  If the app is running in the background then a pop up notification is shown to the user; if the user interacts with the pop up, then the app is launched and an event is triggered on the currently visible view with the "appLaunched" property set to true.  Note
   * that if the push notificaiton pop up is shown to the user and the user dismisses the notification the event is never fired within the app.
   *
   * @example
   * $( bc ).on( "pushnotification", function( evt, data ) {
   *   alert( "Push Message: " + data.message );
   *   alert( "App Launched because of push notification: " + data.appLaunched );
   *   alert( "Key value pairs for this push notification: " + data.params );
   * });
   * @name pushnotification
   * @event
   * @memberOf bc
   * @param event (type of pushnotification)
   * @param data An object that has the properies of "message", "appLaunched" and "params".  Params is an object that contains the key/value pairs specified in the App Cloud studio for this push notification event.
   */

  /**
   * The <code>newconfigurations</code> event is triggered when a configuration (styles or settings), is retrieved from the server.
   * The App Cloud SDK checks the server for new configurations whenever the view gains focus.  If <code>newconfigurations</code> are found,
   * then the event is triggered on the bc object and passed configurations as an object that has the values and a property indicating
   * whether or not those values are new.
   *
   * @example
   $( bc ).on( "newconfigurations ", handleNewConfigurations );

   //Possible values for data are:  {
   //   "settings": {
   //     "isNew": boolean,
   //     "values": data.settings
   //   },
   //   "styles": {
   //     "isNew": boolean,
   //     "values": data.styles
   //   }
   function handleNewConfigurations( evt, data ) {
      if( data.styles.isNew ) {
        bc.core.applyStyles();
      }
   }
   * @name newconfigurations
   * @event
   * @memberOf bc
   */

 /**
  * The <code>downloadprogress</code> is triggered on the bc object at the interval specified in the options passed to the <code>bc.device.requestDownload</code> API.
  * <b>Note</b> this only applies to iOS and by default no downloadprogress events will be fired.  Progress events should be used only for displaying progress to the
  * user or other helpful messaging, and not for important business logic decisions in template source code.  The data object that is passed to any registered function
  * will have the following properties:
  <ul>
    <li>progress (number) The amount of bytes received.</li>
    <li>expected (number) The total bytes expected for this download.</li>
    <li>downloadID (String) The unique ID for this download that was passed into the <code>bc.device.requestDownload</code> API.
  </ul>
  *
  * @example
  $( bc ).on( "downloadprogress", handleDownloadProgress );

  function handleDownloadProgress( evt, data ) {
    var percentComplete = data.progress / data.expected;

    //Get the percentage out of a hundered and make it a whole number.
    percentComplete = Math.floor( percentComplete * 100 ) + "%";

    //In this example I assume I have an element that represents a progress indicator, so I am going to set the width of that element.
    $( "#progress" ).css( "width", percentComplete )

  }
  * @name downloadprogress
  * @event
  * @memberOf bc
  */

  /**
   * The <code>downloadcomplete</code> event is dispatched by the container if the download finishes successfully, as the request
   * moves into the "complete" state. The payload to this event is an object containing a single property, "info", whose
   * value is an object with the following properties:
   *
   <ul>
    <li>downloadID (String) The unique ID for this download that was passed into the <code>bc.device.requestDownload</code> API</li>
    <li>resource (String) The URL that was passed into the <code>bc.device.requestDownload</code> API</li>
    <li>state (String) The current state of the download request. For this event it will always be "complete".</li>
    <li>size (Number) The file size of the downloaded data in bytes</li>
    <li>fileURI (String) The path to the file on disk.</li>
  </ul>
  *
  * @example
  $( bc ).on( "downloadcomplete", handleDownloadComplete );

  function handleDownloadComplete( evt, data ) {
    var videoFile = data.info.fileURI;

    //Assume there is a video tag element already on the page with and ID of video.
    $( "video" ).attr( "src", videoFile );
  }
  *
  * @name downloadcomplete
  * @event
  * @memberOf bc
  */

  /**
   * The <code>downloaderror</code> event is dispatched by the container if there is an error downloading the requested resource.  The
   * payload to this event is an object containing a single property, "info", whose value is an object with the following properties:
   <ul>
    <li>downloadID (String) The unique ID for this download that was passed into the <code>bc.device.requestDownload</code> API</li>
    <li>resource (String) The URL that was passed into the <code>bc.device.requestDownload</code> API</li>
    <li>state (String) The current state of the download request. For this event it will always be "errored".</li>
   </ul>
   *
   * @example
   $( bc ).on( "downloaderror", handleDownloadError );

   function handleDownloadError( evt, error ) {
     console.error( "There was an error downloading " + error.resource );
   }

   * @name downloaderror
   * @event
   * @memberOf bc
   */

  /**
   * End Events
   */

   $( bc ).on( "sessionstart", function( evt ) {
     if( !bc.metrics ) {
       console.log( "bc.metrics is not defined" );
       return;
     }

     //If we are starting this session from a push notification we want to add that our metrics object.
     if( window.bc_notificationID ) {
       bc.metrics.addNotificationID( window.bc_notificationID );
     }
     bc.metrics.track( "session" );
   });

   $( bc ).on( "sessionend", function( evt ) {
     window.bc_notificationID = undefined;
     bc.metrics.removeNotificationID();
   });

  /*
   * Initialize the metrics object and triggers events for install and session start where appropriate.
   */
  $( bc ).on( "init", function() {
    var initData;
    //If we are in the Studio, development mode or running in the workshop, we should not trigger events.
    if( bc.core.current_mode !== bc.core.mode.PRODUCTION || bc.utils.runningInWorkShop() ) {
      return;
    }
    //Initialize the metrics object
    if( bc.metrics !== undefined ) {
      initData = {
        "account": bc.accountID,
        "application": bc.appID,
        "view": bc.viewID,
        "os": bc.context.os
      };

      if( window.bc_notificationID ) {
        initData.message = window.bc_notificationID;
      }

      bc.metrics.init( {
          "domain": "appcloud",
          "uri": bc.METRICS_SERVER_URL,
          "interval": "5000",
          "pendingMetrics": bc.core.cache( bc.viewID + "_pendingEvents" )
        }, initData
      );
    }

    //Check for flag to send install event.
    if( window.bc_firstRun && bc.metrics ) {
      bc.metrics.track( "installation" );
    }

    //If the viewfocus event has already fired we need to now start tracking.
    if( window.bc_viewFocus && bc.metrics ) {
      bc.sessionEndCallback = bc.metrics.live( "view" );
    }
  });

  $( bc ).on( "viewfocus", function() {
    //Should get the most recent settings and styles for this view.
    bc.core.refreshConfigurationsForView();

    if( bc.metrics && bc.metrics.isInitialized() ) {
      if( window.bc_notificationID ) {
        bc.metrics.addNotificationID( window.bc_notificationID );
      } else {
        bc.metrics.removeNotificationID();
      }
      bc.sessionEndCallback = bc.metrics.live( "view" );
    } else {
      window.bc_viewFocus = true;
    }
  });

  $( bc ).on( "viewblur", function() {
    if( typeof( bc.sessionEndCallback ) === "function" ) {
      bc.sessionEndCallback();
    }
  });

  //Listen for the event to store pending events.
  $( bc ).on( "metrics:pendingevents", function( evt, data ) {
    bc.core.cache( bc.viewID + "_pendingEvents", data.events );
  });

  /**
   * Set up our context object with any values that can be bootstrapped.
   */
  function initContextObject() {
    bc.context.viewOrientation = ( window.innerWidth > window.innerHeight ) ? "landscape" : "portrait";
    bc.context.os = ( navigator.userAgent.indexOf( "Mac OS X" ) > -1 ) ? "ios" : "android";
    bc.context.onLine = navigator.onLine;
    bc.core.setMoreNavigationState();
    if( bc.device !== undefined ) {
      bc.device.setIsNative();
    }

    //If we are in preview mode, we set a flag so that the Studio knows that we will trigger a preview:ready event after we have finished refreshing the page.
    if( bc.core.current_mode === bc.core.mode.PREVIEW ) {
      bc.context.triggersPreviewReady = true;
    }
  }


  /** @private */
  bc.core.loadMarkUp = function() {
    if( !bc.configurations || !bc.configurations.markup ) {
      _markupLoaded = true;
      return;
    }

    function success( txt ) {
      bc.templates = bc.templates || {};
      //Parse the template and call triggerInit
      txt = txt.split("=====").splice(1);

      for (var t in txt) {
          var i = txt[t].indexOf("\n");
          var key = txt[t].substr(0, i).trim();
          var val = txt[t].substr(i).trim();
          bc.templates[key] = val;
      }
      _markupLoaded = true;
      if( _markupLoaded && _localeResourceFileLoaded ) {
        triggerInitEvent();
      }
    }

    function error() {
      console.error( "There was an error loading the markup text file from: " + bc.configurations.markup + " Continuing the loading of webview without markup." );
      _markupLoaded = true;
      if( _markupLoaded && _localeResourceFileLoaded ) {
        triggerInitEvent();
      }
    }

    $.ajax( {
      url: bc.configurations.markup,
      success: success,
      error: error
    });
  };

  /** @private */
  bc.core.loadLocales = function() {
    if( !bc.configurations || !bc.configurations.locales ) {
      _localeResourceFileLoaded = true;
      return;
    }

    function success( txt ) {
      var s, t;
      txt = txt.split("\n");
      for ( t in txt ) {
        s = txt[t].trim();
        if ( !s.length || s.charAt(0) === "#" ) {
          continue;
        }
        s = s.split("=");
        if( s.length > 1 ) {
          Mark.includes[s[0].trim()] = s[1].trim();
        }
      }
      _localeResourceFileLoaded = true;
      if( _markupLoaded && _localeResourceFileLoaded ) {
        triggerInitEvent();
      }
    }

    function error() {
      console.error( "There was an error loading the locale text file from: " + bc.configurations.locales + " Continuing the loading of webview without locales." );
      _localeResourceFileLoaded = true;
      if( _markupLoaded && _localeResourceFileLoaded ) {
        triggerInitEvent();
      }
    }

    $.ajax( {
      url: bc.configurations.locales,
      success: success,
      error: error
    });
  };

  /**
   * @private
   */
  bc.core.setMoreNavigationState = function() {
    var cachedValue = bc.core.cache( bc.viewID + "_moreNavigationView" );
    if( cachedValue === null ) {
      bc.context.moreNavigationView = window.bc_moreNavigationView === true;
      bc.core.cache( bc.viewID + "_moreNavigationView", bc.context.moreNavigationView );
    } else {
      bc.context.moreNavigationView = cachedValue;
    }
  };

  /**
   * @private
   */
  bc.core.loadConfigurationsFromManifest = function() {
    var $manifest;

    if( window.bc_configurations !== undefined && window.bc_configurations.views !== undefined) {
      bc.core.cache( bc.appID + "_configurations", window.bc_configurations );
      bc.core.setConfiguration( window.bc_configurations, true );
    } else {
     //check the cache to see if we have existing configurations.
     bc.configurations = bc.core.cache( bc.viewID + "_configurations" );
     bc.manifestURI = bc.core.cache( "manifest_uri" );
     if( bc.configurations === null ) {
       $manifest = $( '[name="bc-manifest"]' );
       if( $manifest.length > 0 ) {
         bc.core.loadManifestFromMetaTag( $manifest );
       } else {
         bc.core.loadManifestViaAjax( 0 );
       }
     }
    }
  };

  /**
   * @private
   */
  bc.core.loadManifestFromMetaTag = function( $elem ) {
    bc.manifestURI = $elem.attr( "content" );
    $.ajax(
      {
        "url": bc.manifestURI,
        "async": false
      }
    )
    .success( bc.core.setConfiguration )
    .error( function()
      {
        console.error( "ERROR: Loading manifest.json from: " + bc.manifestURI );
      }
    );
  };

  /**
   * @private
   */
  bc.core.loadManifestViaAjax = function( index ) {
    var directories;

    index++;
    directories = location.href.split( "/" );

    if( index === ( directories.length - 1 ) ) {
      console.error( "ERROR: Did not find a manifest.json file." );
      return;
    }

    bc.manifestURI = directories.slice( 0, directories.length - index )
                      .join( "/" )
                      .concat( "/manifest.json" );
    $.ajax(
      {
        "url": bc.manifestURI,
        "async": false
      }
    )
    .success( bc.core.setConfiguration )
    .error( function()
      {
        bc.core.loadManifestViaAjax( index );
      }
    );
  };

  /**
   * @private
   */
  bc.core.setConfiguration = function( manifest, cache ) {
    var views,
        globalConfigs = {},
        viewURI;

    bc.configurations = {};

    manifest = ( typeof manifest === "string" ) ? JSON.parse( manifest ) : manifest;
    cache = ( typeof cache === "boolean") ? cache : false;

    if( manifest.global ) {
      globalConfigs = manifest.global;
    }

    views = manifest.views;
    for( var i = 0, len = views.length; i < len; i++ ) {
      viewURI = ( views[i].uri.indexOf( "./" ) > -1 ) ? views[i].uri.split( "./" )[1] : views[i].uri;
      if( location.href.toLowerCase().indexOf( viewURI.toLowerCase() )  > -1 ) {
        //We load the locale and markup files from the HTML file so we need to know how many directories to go up to make the correct request.
        bc.configurations.styles = ( globalConfigs && globalConfigs.styles ) ? bc.utils.merge( globalConfigs.styles, views[i].styles ) : views[i].styles;
        bc.configurations.data = ( globalConfigs && globalConfigs.data ) ? bc.utils.merge( globalConfigs.data, views[i].data ) : views[i].data;
        bc.configurations.settings = ( globalConfigs && globalConfigs.settings ) ? bc.utils.merge( globalConfigs.settings, views[i].settings ) : views[i].settings;
        bc.configurations.markup = bc.core.setCorrectPathForResourceFile( viewURI, views[i].markup );
        bc.configurations.locales = bc.core.setCorrectPathForResourceFile( viewURI, views[i].locales );

        if( cache ) {
          bc.core.cache( bc.viewID + "_configurations", bc.configurations );
          bc.core.cache( "manifest_uri", bc.manifestURI );
        }
        return;
      }
    }

  };

  /** @private */
  bc.core.setCorrectPathForResourceFile = function( viewURI, path ) {
    var directoryDepth,
        dir = "";

    if( path === undefined ) {
      return "";
    }

    viewURI = ( viewURI.indexOf( "./" ) > -1 ) ? viewURI.split( "./" )[1] : viewURI;

    //Since the manifest.json file has to be at the root, if the files are located a directory up from here we assume the template author knows exactly where it is, so we return it untouched.
    if( path.indexOf( "../" ) > -1 ) {
      return path;
    }

    directoryDepth = viewURI.split( "/" ).length - 1;
    path = ( path.indexOf( "./" ) > -1 ) ? path.split( "./" )[1] : path;

    for( var i=0; i < directoryDepth; i++ ) {
      dir += "../";
    }
    return dir + path;
  };

  $( document ).ready( function() {
    setGlobalIDValues();
    initContextObject();
    bc.core.applyStyles();
    bc.core.loadConfigurationsFromManifest();
    setAdPolicy();
    bc.currentGlobalConfigs = bc.core.cache( bc.appID + "_global_configs" );
    bc.core.loadMarkUp();
    bc.core.loadLocales();
    if( _markupLoaded && _localeResourceFileLoaded ) {
      triggerInitEvent();
    }
  });

} )( bc.lib.jQuery );
/*global bc:true atob:false*/
/*jshint indent:2, browser: true, white: false devel:true undef:false*/

/**
* Brightcove Utils is a collection of helper functions.
* @namespace
*/
bc.utils = {};

( function( $, undefined ) {
  var _supportsTouch;

  /**
   * Set this property to either true or false to turn logging to the console on or off, defaults to true.
   */
  bc.utils.debug = true;

  /**
   * Detects whether or not this particular device supports touch events.
   *
   * @return A boolean indicating whether or not touch events are currently supported.
   * @example
    if ( bc.utils.hasTouchSupport() ) {
      alert("I support touch!");
    } else {
      alert("Touch is not supported.");
    }
   */
   bc.utils.hasTouchSupport = function() {

     if( _supportsTouch !== undefined ) {
       return _supportsTouch;
     }

     _supportsTouch = "ontouchend" in document;
     return _supportsTouch;
   };

  /**
   * Returns a number from a string that is passed in.  If the string ends in 'px' (for pixels), then it is stripped off and that
   * number is returned.  If a number cannot be parsed out, 0 is returned.
   *
   * @param number The string representation of a number that can end with a 'px'.
   * @returns Returns the a number for the string that is passed in.
   @example
   $( ".page" ).css( "top", "50px" );
   var top = bc.utils.getNum( $( ".page" ).css( "top" ) ); //top is 50.
   */

  bc.utils.getNum = function( number ) {
    var ret;
    if( typeof( number ) === "number" ) {
      return number;
    }

    ret = ( number.indexOf( "px" ) > -1 ) ? parseInt( number.substring( 0, number.indexOf( "px" ) ), 10 ) : parseInt( number, 10 );
    return (ret) ? ret : 0;
  };

  /**
   * Converts a number from hex to RGB.
   *
   * @param hex A number in a hexadecimal format.  For example #ffffff.  (Either ffffff or #ffffff can be passed in.)
   * @returns The RGB value for the hexadecimal value passed in.
   @example
   var rgb = bc.utils.hexToRGB( "#ffffff" ); //rbg is now { "red": 255, "green": 255, "blue": 255 }
   */
  bc.utils.hexToRGB = function( hex ) {
    var red,
        green,
        blue;
    if( !hex ) {
      return;
    }

    if( hex.indexOf( "#" ) > -1 ) {
      hex = hex.replace( "#", "0x");
    }

    try {
      red = ( hex & 0xff0000 ) >> 16;
      green = ( hex & 0x00ff00 ) >> 8;
      blue = hex & 0x0000ff;

      return { "red": red, "green": green, "blue": blue };
    } catch (e) {
      bc.utils.warn( "Bad value passed into hexToRGB of: " + hex + ".  Threw error of: " + e.toString() );
    }
  };

  /**
   * Returns the WebKitCSSMatrix for this element or generates a new one if one does not exist.
   *
   * @private
   * @param node - The element to get or create the WebkitCSSMatrix from.
   * @return - A WebKitCSSMatrix for this element.
   */
  bc.utils.getMatrixFromNode = function( node ) {
    if( window.getComputedStyle( node ).webkitTransform === "none" ) {
      return new WebKitCSSMatrix();
    } else {
      return new WebKitCSSMatrix( window.getComputedStyle( node ).webkitTransform );
    }
  };

  /**
   * Returns the number of properties in a given object.
   *
   * @param obj The object to inspect.
   * @return The number of properties in the object.
   * @example
   var testObj = { "quiver": "cobras", "raft": "otters" };
   var length = bc.utils.numberOfProperties( testObj ); // length is equal to 2
   */
  bc.utils.numberOfProperties = function( obj ) {
    var count = 0;
    for( var prop in obj ) {
      if( obj.hasOwnProperty( prop ) ) {
        ++count;
      }
    }

    return count;
  };

  /**
   * Unescapes HTML from the given string.  This is handy if data returned to you that has escaped HTML in it that you now want
   * to render.
   *
   * @param htmlString The string that contains escaped HTML.
   * @return A string with the HTML tags unescaped.
   @example
   var escapedHTML = "&amp;lt;h1&amp;gt;hello there avid reader&amp;lt;/h1&amp;gt;"
   var html = bc.util.unescapeHTML( escapedHTML ); //html is now &lt;h1&gt;hello there avid reader&lt;/h1&gt;
   */
  bc.utils.unescapeHTML = function( htmlString ) {
    return $( "<div>" ).html( htmlString ).text();
  };

  /**
   * Determines how many hours have passed since the date passed in and returns the results in as formatted string.
   * @private
   * @param pastDate - A JavaScript Date object representing the starting time that the calculation should be determined from.
   * @results - A String specifying how many hours, days, weeks or months have passed since the date passed in.
   */
  bc.utils.hoursAgoInWords = function( pastDate ){
    var now = new Date(),
        hoursAgo = Math.floor( ( ( now.getTime() - pastDate.getTime()) / 3600000) );
    if( hoursAgo === 0 ) {
      var minutesAgo = Math.floor( ( now.getTime() - pastDate.getTime() ) / 60000) ;
      return minutesAgo + " minute" + ( minutesAgo > 1 ? "s" : "") + " ago";
    } else if( hoursAgo < 24 ) {
      return hoursAgo + " hour" + ( hoursAgo > 1 ? "s" : "" ) + " ago";
    } else if(hoursAgo < 168) {
      var daysAgo = Math.floor( hoursAgo / 24 );
      return daysAgo + " day" + ( daysAgo > 1 ? "s" : "") + " ago";
    } else if( hoursAgo < 744 ) {
      var weeksAgo = Math.floor( hoursAgo / 168 );
      return  weeksAgo + " week" + ( weeksAgo > 1 ? "s" : "" ) + " ago";
    } else {
      var monthsAgo = Math.floor( hoursAgo / 744 );
      return monthsAgo + " month" + ( monthsAgo > 1 ? "s" : "" ) + " ago";
    }
  };

  /**
   * Removes any tags from a given string. Useful for removing any HTML tags from a string.
   *
   * @param string A String that may include HTML tags that should be removed.
   * @return A string with its HTML tags removed.
   @example
   var htmlString = "&lt;h1&gt;hello there avid reader&lt;/h1&gt;";
   var cleanString = bc.utils.stripTags( htmlString ); //cleanString is "Hello there avid reader"
   */
  bc.utils.stripTags = function(string) {
    if( string === undefined || string === null ) {
      return "";
    }
    return string.replace( /<\/?[^>]+>/gi, "" );
  };

  /**
   * Generates a unique ID.
   *
   * @return A unique number.
   * @example
   var unique = bc.utils.uniqueID(); //unique is...wait for it...yup, a unique number
   @private
   */
  bc.utils.uniqueID = function() {
    return Math.floor(new Date().getTime() * Math.random());
  };

  /**
   * Determines whether or not a string is a valid URL.  ( Regex borrowed from http://snippets.dzone.com/posts/show/452 )
   * @param url The string that should be checked to see whether or not it is valid.
   * @return A boolean indicating whether or not a string is a valid URL. True if valid.
   @example
   var valid = bc.utils.validURL( "http://www.brightcove.com" ); //valid is true.
   @private
   */
  bc.utils.validURL = function( url ) {
    var regexp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;
    return regexp.test( url );
  };

  /**
   * @private
   */
  bc.utils.runningInWorkShop = function() {
    return ( bc.context.isNative && location.href.substring( 0, 4 ) === "http" );
  };

  /**
   * A wrapper for console.log  If debugging is turned off, then no console.log messages will logged.
   * @param message The string that is logged out.
   */
  bc.utils.log = function ( message ) {
    if( bc.utils.debug ) {
      console.log( message );
    }
  };

  /**
   * A wrapper for console.warn.  If debugging is turned off, then no console.warn messages will logged.
   * @param message The string that is logged out as a warning.
   */
  bc.utils.warn = function( message ) {
    if( bc.utils.debug ) {
      console.warn( message );
    }
  };

  /**
   * A wrapper for console.error.  If debugging is turned off, then no console.error messages will logged.
   * @param message The string that is logged out as an error.
   */
  bc.utils.error = function( message ) {
    if( bc.utils.debug ) {
      console.error( message );
    }
  };

  /**
   * Encode the supplied fragment according to the rules specified in RFC3986.  Specifically, the encoding
   * will follow:
   * fragment    = *( ALPHA / DIGIT / "-" / "." / "_" / "~" / "%" HEXDIG HEXDIG / "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=" / ":" / "@" / "/" / "?" )
   *
   * @param message The string that is to be encoded
   */
  bc.utils.encodeFragment = function( fragment ) {
    if ( fragment === undefined ) {
      return fragment;
    }

    return fragment.replace( /%/g, '%25').replace( /#/g, '%23').replace( /\[/g, '%5B').replace( /\]/g, '%5D');
  };

  /**
   * Decode the supplied fragment according to the rules specified in RFC3986.  This is expected to be used for values received from a hashchange event
   * on the window object.  Here is an example of a typical use:
   *
   * $( window ).bind( "hashchange", function( evt) {
   *   var decodedHash = bc.utils.decodeFragment( location.hash );
   * });
   *
   * @param message The string that is to be decoded.  Typically, this will be a string that has been previously encoded using bc.utils.encodeFragment().
   */
  bc.utils.decodeFragment = function( fragment ) {
    if ( fragment === undefined ) {
      return fragment;
    }

    return fragment.replace( /%25/g, '%').replace( /%23/g, '#').replace( /%5B/g, '[').replace( /%5D/g, ']');
  };


  /**
   * @private
   */
  bc.utils.merge = function( globalArray, viewArray ) {
    viewArray = viewArray || [];
    var ret = viewArray,
        overriden;

    if( !globalArray ) {
      return ret;
    }

    for( var i=0, len=globalArray.length; i<len; i++ ) {
      overriden = false;

      for( var j=0, max=viewArray.length; j<max; j++ ) {
        if( globalArray[i].name === viewArray[j].name ) {
          overriden = true;
          break;
        }
      }

      if( !overriden ) {
        globalArray[i].global = true;
        ret.push( globalArray[i] );
      }

    }
    return ret;
  };

  /**
   * Compares two objects to see if they are equal.  The objects can be complex objects, meaning nested objects.
   * @param obj1 The first object to be compared.
   * @param obj2 The second object to be comapared to the first.
   * @example
   var oneObject = { "blessing": "unicorns" }
     , otherObject = { "blessing": "unicorns" };

   //returns true
   bc.utils.isEqual( oneObject, otherObject );

   //returns false
   bc.utils.isEqual( oneObject, { "army": "ants" } );

   //Returns false
   bc.utils.isEqual( oneObject, {
     "yes": {
        "complex": "I am"
     }
   });
   */
  bc.utils.isEqual = function( obj1, obj2 ) {

    if( !obj1 || !obj2 ) {
      return false;
    }

    for( var prop in obj1 ) {
      if( typeof( obj2[prop] ) == 'undefined' ) {
        return false;
      }
    }

    for( prop in obj1 ) {
      if ( obj1[prop] ) {
        switch( typeof( obj1[prop] ) ) {
          case 'object':
            if ( !bc.utils.isEqual( obj1[prop], obj2[prop] ) ) {
              return false;
            }
            break;
          case 'function':
            if ( typeof( obj2[prop] ) == "undefined" || (p != 'equals' && obj1[prop].toString() != obj2[prop].toString()) ) {
              return false;
            }
            break;
          default:
            if ( obj1[prop] != obj2[prop] ) {
              return false;
            }
        }
      } else {
        if ( obj2[prop] ) {
          return false;
        }
      }
    }

    for( prop in obj2 ) {
      if( typeof( obj1[prop]) == 'undefined' ) {
        return false;
      }
    }

    return true;
  };

})( bc.lib.jQuery );
/*global bc:true atob:false*/
/*jshint indent:2, browser: true, white: false devel:true undef:false*/

/**
 * bc.device provides functions to interact with the native capabilities of a device.
 *
 * Note that all functions take an optional success and error handler.
 *
 * @namespace
 */
bc.device = {};

/**
 * <b>Note:</b> The functions on the b.device.externalscreen object are only available on iOS devices
 * at this time.
 *
 * <br/><br/>bc.device.externalscreen provides functions to interact with a connected screen.  Specifically,
 * this means a connected Apple TV screen.  These functions work if the source iOS device (iPhone, iPad)
 * have mirroring turned on for a specific Apple TV.
 *
 * These functions only work on iOS devices.
 *
 * Note that all functions take an optional success and error handler.
 *
 * @namespace
 */
bc.device.externalscreen = {};

( function( $ ) {

 /*****************************************
  * Universal callback methodology
  ****************************************/
  var _callbackFunctionMap = {},
      _callStack = [],
      _enqueueCommands = true;

  /**
   * Possible codes returned by the error callback functions.
   *
   * @namespace
   */
  bc.device.codes = {};

  /** An error occurred. */
  bc.device.codes.GENERAL = 100;

  /** The user canceled this action. */
  bc.device.codes.USER_CANCEL = 101;

  /** The device is not running in a native container. */
  bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION = 102;

  /** The camera is not available on this device. */
  bc.device.codes.CAMERA_UNAVAILABLE = 103;

  /** Unable to fetch contents for URL via xhr request.  Possible cross domain issue? */
  bc.device.codes.ERROR_FETCHING_CONTENTS_OF_URL_VIA_BROWSER = 104;

  /** Missing required parameter */
  bc.device.codes.MISSING_REQUIRED_PARAMETER = 105;

  /** Invalid downloadID */
  bc.device.codes.INVALID_DOWNLOAD_ID = 106;


/**
 * Public Events
 */

/**
 * The <code>externalscreenpostmessage</code> event is fired when a message has been posted to the screen
 *
 * @example
 * $( bc ).on( "externalscreenpostmessage", function( evt, result ) {
 *    $("#message").text(result.message) ;
 * });
 *
 * @name externalscreenpostmessage
 * @event
 * @memberOf bc
 * @param event (type of externalscreenpostmessage)
 * @param result The result parameter to the event handler contains a property <i>message</i>.  This property contains the string value sent from another screen.
 */

/**
 * The <code>externalscreenvideoprogress</code> event is fired at a 1s interval.  This is fired during the playback of a video and stopped during pause/stop actions.
 *
 * @example
 * $( bc ).on( "externalscreenvideoprogress", function( evt, result ) {
 *    $("#currenttime").text( Math.floor(result.currenttime) ;
 *    $("#currenttime").text("% Complete: " + Math.floor((result.currenttime/result.totaltime)*100));
 * });
 *
 * @name externalscreenvideoprogress
 * @event
 * @memberOf bc
 * @param event (type of externalscreenvideoplaying)
 * @param result The result parameter to the event handler contains two properties.  The first is <i>currenttime</i>.  This indicates the current timecode in the play of the video.  The
 * second property is the <i>totaltime</i> property.  This indicates the total duration of the video.  You can use these two numbers to determine the % of the video that has
 * been watched and the remaining amount.
 */

/**
 * The <code>externalscreenvideoend</code> event is fired when the video has completed playback.  This means that the video has reached
 * the full length of the stream and there is no more content to play.  In addition to an externalscreenvideoend event being
 * fired an externalscreenvideopaused event will also be fired.
 *
 * @example
 * $( bc ).on( "externalscreenvideoend", function( evt ) {
 *    // update to play next video automatically
 *    bc.device.externalscreen.playVideo("http://urltonext/video");
 * });
 *
 * @name externalscreenvideoend
 * @event
 * @memberOf bc
 * @param event (type of externalscreenvideoend)
 */

/**
 * The <code>externalscreenvideoplaying</code> event is fired anytime that video playback begins on the external screen.  This is fired after the first frame
 * of the video has begun playing back.
 *
 * @example
 * $( bc ).on( "externalscreenvideoplaying", function( evt ) {
 *    bc.device.alert("Enjoy your video!", successHandler, errorHandler);
 * });
 *
 * @name externalscreenvideoplaying
 * @event
 * @memberOf bc
 * @param event (type of externalscreenvideoplaying)
 */

/**
 * The <code>externalscreenvideostopped</code> event is fired anytime that video has stopped playback.  This occurs when the video has previously been playing and  the <i>bc.device.externalscreen.stopVideo</i>
 * is called.
 *
 * @example
 * $( bc ).on( "externalscreenvideostopped", function( evt ) {
 *    bc.device.alert("Your video has ended, watch another?", successHandler, errorHandler);
 * });
 *
 * @name externalscreenvideostopped
 * @event
 * @memberOf bc
 * @param event (type of externalscreenvideostopped)
 */

/**
 * The <code>externalscreenvideopaused</code> event is fired anytime that video playback is paused as a result of the call to <i>bc.device.externalscreen.pauseVideo</i> or the stream completes playing back.
 *
 * @example
 * $( bc ).on( "externalscreenvideopaused", function( evt ) {
*     // update play icon to show a pause
 * });
 *
 * @name externalscreenvideopaused
 * @event
 * @memberOf bc
 * @param event (type of externalscreenvideopaused)
 */

/**
 * The <code>externalscreenconnected</code> event is fired anytime that an externalscreen is connected as a result of the user turning on mirroring on their iOS device.  This typically means
 * that the user has paired their iPad/iPhone with an AppleTV and the AppleTV is mirroring what is on the iPad/iPhone.  This indicates that the
 * the externalscreen can be interacted with.  For example, the commands under bc.device.externalscreen can now be called.
 *
 * @example
 * $( bc ).on( "externalscreenconnected", function( evt ) {
 *     // AppleTV connected so I can now send a separate video stream to the AppleTV
 *     bc.device.externalscreen.playVideo("http://someurl/somepath/video.m4v", successHandler, errorHandler);
 *     // Also have ability to now change UI on iPad/iPhone to take advantage of dual screen experience
 * });
 *
 * @name externalscreenconnected
 * @event
 * @memberOf bc
 * @param event (type of externalscreenconnected)
 */

/**
 * The <code>externalscreendisconnected</code> event is fired anytime that a previously connected external screen becomes unavailable.  This may happen as a result of the user turning off
 * mirroring on their iOS device or going out of range of their Apple TV.  Once this event is fired, calls to the function under <i>bc.device.externalscreen</i> can no longer be made.
 *
 * @example
 * $( bc ).on( "externalscreendisconnected", function( evt ) {
 *    bc.device.alert("Oops, AppleTV no longer available", successHandler, errorHandler);
 * });
 *
 * @name externalscreendisconnected
 * @event
 * @memberOf bc
 * @param event (type of externalscreendisconnected)
 */

/**
 * The <code>modalwebbrowserclosed</code> event is fired anytime the modal web browser window is closed.
 *
 * @example
 * $( bc ).on( "modalwebbrowserclosed", function( evt ) {
 *    bc.device.alert("The modal web browser was closed.", successHandler, errorHandler);
 * });
 *
 * @name modalwebbrowserclosed
 * @event
 * @memberOf bc
 * @param event (type of modalwebbrowserclosed)
 */

  $( document ).ready( function() {
    //We need to inject an iFrame into the page in order to flag the container that we have commands to pull
    createIframeBridge();
  });

  /*****************************************
   * Utility functions
   ****************************************/

  function createIframeBridge() {
    return $( '<iframe id="bc-device-bridge" style="display: none;" height="0px" width="0px" frameborder="0"></iframe>' ).appendTo( "body" );
  }
   /**
    *@private
    */
  function createNativeCall( successCallback, errorCallback, command, parameters ) {
    var successCallbackID,
         errorCallbackID,
         jsonCommand;

     //If this is not the current view then do not enqueue the request.
     if( !_enqueueCommands ) {
       console.warn( "This view is not currently in focus.  Commands are enqueued for the currently active view." );
       return;
     }

     if( successCallback === undefined ) {
       successCallback = function() {/*noop*/};
     }

     if( errorCallback === undefined ) {
       errorCallback = function() {/*noop*/};
     }

     if( !bc.device.isNative() ) {
       return errorCallback(
         {
           "errorCode": bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION,
           "errorMessage": command + " is not available for non native applications"
         }
       );
     }

     successCallbackID = bc.utils.uniqueID();
     errorCallbackID = bc.utils.uniqueID();

     _callbackFunctionMap[successCallbackID] = {
       "associatedCallbackID": errorCallbackID,
       "callback": successCallback
     };

     _callbackFunctionMap[errorCallbackID] = {
       "associatedCallbackID": successCallbackID,
       "callback": errorCallback
     };

     jsonCommand = {
       "command" : command,
       "successCallbackID" : successCallbackID,
       "errorCallbackID": errorCallbackID,
       "parameters" : parameters
     };

     bc.device.nativeCall( JSON.stringify( jsonCommand ) );
  }

  /*****************************************
   * Event registration
   ****************************************/

  $( bc ).on( "viewfocus", function() {
    _enqueueCommands = true;
  });

  $( bc ).on( "viewblur", function() {
    _enqueueCommands = false;
  });

  /*****************************************
   * Helper functions
   ****************************************/

  function callErrorCallback( errorCallback, errorCode, errorMessage ) {
    if( typeof errorCallback === "function" ) {
      errorCallback( {
        "errorCode": errorCode,
        "errorMessage": errorMessage
      });
    }
    console.warn( errorMessage );
  }

  /**
   * @private
   */
   bc.device.callbackHandle = function( id, data ) {
     var associatedCallbackID,
         callbackData;

     if ( data ) {
       callbackData = JSON.parse( atob( data ) );
       callbackData = callbackData.result;
     }

     if( _callbackFunctionMap[id] ) {
       associatedCallbackID = _callbackFunctionMap[id].associatedCallbackID;
       _callbackFunctionMap[id].callback( callbackData );
       delete _callbackFunctionMap[id];
       if ( associatedCallbackID ) {
         delete _callbackFunctionMap[associatedCallbackID];
       }
     } else {
       bc.utils.error( "The ID passed by the native container is not in the queue." );
     }
   };

 /*****************************************
  * Native APIs
  ****************************************/

  /**
   * @private
   */
  bc.device.registerListeners = function() {
    var hrefNoHash = window.location.href;

    $( window ).on( "hashchange", function() {
      if ( !bc.device.isNative() ) {
        return;
      }
      else {
        hrefNoHash = hrefNoHash.indexOf( "#" ) != -1 ? hrefNoHash.substring( 0, hrefNoHash.indexOf( "#" ) ) : hrefNoHash;

        bc.device.navigateToView( hrefNoHash,
                                  null,
                                  null,
                                  { fragmentID: window.location.hash } );
      }
    });
  };


 /**
  * Deprecated - Should use the bc.context.isNative property.  Determine whether we are running as a native application or as a web site.  If true, we are
  * running as a native iPhone, Android  or other application.
  *
  * @return A boolean representing whether or not this is running as a native application.
  * @example
  *   if ( bc.device.isNative() ) {
         bc.device.takePhoto();
       } else {
         alert("No camera available when in a browser.");
       }
   }
   @private
  */
  bc.device.isNative = function() {
    if( bc.context !== undefined && bc.context.isNative !== undefined ) {
      return bc.context.isNative;
    } else {
      return bc.device.setIsNative();
    }
  };

  /**
   * Tells the container that it is now safe to communicate with the view.
   * @private
   */
  bc.device.setViewIsReady = function() {
    createNativeCall( undefined, undefined, "SetViewIsReady", { version: bc.context.version } );
    bc.device.registerListeners();
  };

  /**
   * @private
   */
  bc.device.setIsNative = function() {
     var cachedValue = bc.core.cache( "isNative" );

     //Need to make sure that the context object is available.
     if( bc.context === undefined ) {
       bc.context = {};
     }
     //Our first time visiting this page.
     if( cachedValue === null ) {
       bc.context.isNative = window.bc_isNative === true;
       bc.core.cache( "isNative", bc.context.isNative );
     } else {
       bc.context.isNative = cachedValue;
     }
     return bc.context.isNative;
   };

  /**
   * @private
   */
  bc.device.playBCVideo = function( videoID, videoURL, successCallback, errorCallback ) {
    var query = "video_id=" + videoID + "&video_url=" + encodeURIComponent(videoURL);
    createNativeCall( successCallback, errorCallback, "PlayVideo", query );
  };

 /**
  * Gets the current location of the user and calls into the success handler with the results.  What is
  * returned to the success handler is an object that looks like:
  * <code>{"latitude":70.35, "longitude":40.34}</code>
  * If this API is called in a browser and the browser supports geolocation, then we will use the JavaScript API to get the user location.
  * @param successCallback A function to be called with the results of the location lookup.  This includes latitude and longitude properties, which have values that are of type float.
  * @param errorCallback An optional function that will be called if there is an error getting the location.  This callback is passed
  an object containing the property <code>errorCode</code>, which maps one of the values specified in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
  * @example

  bc.device.getLocation( function( locationInfo ) {
                          if ( locationInfo.latitude > 80 ) {
                            alert("Brrrrr...");
                          }
                        },
                        function( data ) {
                          bc.utils.warn( data.errorCode );
                        }
                      );
  */
  bc.device.getLocation = function( successCallback, errorCallback ) {
    if( !bc.context.isNative && navigator.geolocation ) {
      navigator.geolocation.getCurrentPosition( function( geolocation ) {
        successCallback( { "latitude": geolocation.coords.latitude, "longitude": geolocation.coords.longitude } );
      }, errorCallback );
      return;
    }
    createNativeCall( successCallback, errorCallback, "GetLocation" );
  };

 /**
  * Get an existing photo from the user's photo library.  When this function is called, the device will bring up the
  * photo gallery. After the user chooses an image, the success handler is called.  If you want the user to take a picture
  * with the camera instead, use the <code>takePhoto</code> function instead.  If <code>getPhoto</code> is called from
  * the browser we will call the <code>errorCallback</code> with the <code>errorCode:
  * bc.device.codes.CAMERA_UNAVAILABLE</code>.
  *
  * <p>The success callback will be called with an object whose result value is a string pointing to the local path of the image.  Here is an
  * example of that object:<br/>
  * "/a/path/to/an/image.jpg"</p>
  *
  * <b>Note:</b> When using the Workshop application, the returned path will actually be a data-uri.
  * In either case, you can set the resulting string to be the source of an image.
  *
  * @param successCallback A function to be called with the URL to the image.
  * @param errorCallback An optional function that will be called if an error is encountered, the device does not support getPhoto, or the user cancels the action.
    The <code>errorCallback</code> function is passed an object that contains a property of <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides
    additional information about this error.
  * @example
  bc.device.getPhoto( function( data ) {
                        //data is the path to the image on the file system.
                      },
                      function( data ) {
                        bc.utils.warn( data.errorCode );
                      }
                    );
  *
  */
  bc.device.getPhoto = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.CAMERA_UNAVAILABLE, "There is no camera available to this device" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "GetPhoto" );
  };

 /**
  * Opens the camera and allows the user to take a picture.  Once the picture has been taken, the success handler is called.
  * If you want to access an image from the photo gallery, use the <code>getPhoto</code> function instead.
  * Here is an example of what the return object will look like:<br/>
  * "/a/path/to/an/image.jpg"
  *
  * <p><b>Note:</b> When using the Workshop app, the returned path will actually be a data-uri.
  * In either case, you can set the resulting string to be the source of an image.</p>
  *
  * <p><b>Note:</b> If <code>takePhoto</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.CAMERA_UNAVAILABLE</code>.</p>
  *
  * @param successCallback The function to be called with the URL to the image the user just took with their camera.
  * @param errorCallback The function that is called if an error is encountered, the device does not support taking a picture, or the user cancels the action.
   The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides
    additional information about this error.
  * @example
    bc.device.takePhoto( function( data ) {
                          //my success handler
                         },
                         function( data ) {
                           if( data.errorCode === bc.device.codes.USER_CANCEL ) {
                             //Convince them not to cancel.
                           }

                         }
                      );
  */
  bc.device.takePhoto = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.CAMERA_UNAVAILABLE, "There is no camera available to this device" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "TakePhoto" );
  };

 /**
  * Checks to see if this device has a camera available.  The
  * success handler will be called with an object that looks like:
  *
  * true if the camera is available or false if it is not
  *
  * <b>Note</b>: If this is called from within a browser, we will call the success callback function and return false.
  *
  * @param successCallback The function to be called with a boolean specifying whether or not a camera is available.
  * @param errorCallback The function that is called if an error is encountered.
    The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides
    additional information about this error.
  * @example
    bc.device.isCameraAvailable( function( data ) {
                                   alert( "Camera available? " + data );
                                   if( data ) {
                                     alert( "Camera is available!" );
                                   } else {
                                     alert( "No camera :( ");
                                   }
                                 },
                                 function( data ) {
                                   bc.utils.warn( data.errorCode );
                                 }
                              );

  */
  bc.device.isCameraAvailable = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      successCallback( false );
      return;
    }
    createNativeCall( successCallback, errorCallback, "IsCameraAvailable" );
  };

  /**
   * Allows a developer to programmatically switch between views.  Just as in web development, the API allows a developer to navigate to a
   * URI and also provide a fragmentID to append to that URL.  (fragmentID is the technical term for a '#' in a URL.)  If you are using the fragmentID to pass contextual
   * data then you should simply register an event listener for the <code>hashchangeevent</code>.  An example use case would be if you had a photo on your home page, and when the
    * user clicks a photo, you open the photo view and navigate to that particular photo.
   * @param uri The URI of the view to navigate to.  This is the URI that was specified in the manifest.json file.
   * @param successCallback The callback function that is called if the view is successfully navigated to.
   * @param errorCallback The callback function that is called if the container is unable to navigate to the view.
   * @param options An options object.  We look for the fragmentID to see if the fragmentID of the URL should be set.
   *
   * @example
   //home.html
   bc.device.navigateToView( "photo.html", successCallback,
                    errorCallback, { "fragmentID": "id-of-photo" } );

   //photo.html
   $( window ).on( "hashchange", function( evt ) {
     var photoID = window.location.hash;
     //do something photoID.
   })
   */
  bc.device.navigateToView = function( uri, successCallback, errorCallback, options ) {
    if( !bc.context.isNative ) {
      if ( successCallback ) {
        successCallback();
      }
      if( bc.manifestURI ) {
        uri = bc.manifestURI.split( "manifest.json" )[0] + uri;
        window.open( uri + ( options && options.fragmentID ? "#" + bc.utils.encodeFragment( options.fragmentID ): "" ) );
      }
      return;
    } else {
      options = options || {};
      options.uri = uri;
      if( options.fragmentID ) {
        options.fragmentID = bc.utils.encodeFragment( options.fragmentID );
      }
      createNativeCall( successCallback, errorCallback, "NavigateToView", options );
    }
  };

  /**
   * Changes the active view to the 'more' menu, which is the view that appears on iOS if there are more then 5 views in the template.  This command is most often used by views that
   * fall under the "more menu" list, so that user can navigate back to the list.
   * @param successCallback The function to be called once the 'more' menu has been navigated to.
   * @param errorCallback The function to be called if there is an error.
   *
   * @example
   //The back button on a static page, such as an about page in a more section.
   $( ".back-button" ).on( "tap", function() {

     //Make sure we are in a more navigation view
     if( bc.context.moreNavigationView ) {

       //Transition back the more menu.
       bc.device.navigateToMoreMenu();
     }
   });
   */
  bc.device.navigateToMoreMenu = function( successCallback, errorCallback ) {
    if( bc.context.os !== "ios" ) {
      callErrorCallback( errorCallback, bc.device.codes.GENERAL, "bc.device.navigateToMoreMenu called from a non iOS device." );
      return;
    }
    createNativeCall( successCallback, errorCallback, "NavigateToMoreMenu" );
  };

 /**
  * Retrieves the information about the device that the application is running on.
  *
  * @example
  bc.device.getDeviceInfo( function( data ) {
                             //my success handler
                           },
                           function( data ) {
                             bc.utils.warn( data.errorCode );
                           }
                        );
   * @param successCallback The function that is called by the container once the device has been retrieved.
   * @param errorCallback The function that is called if there is an error retrieving the device info.
   The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides
    additional information about this error.
   * @private
  */
  bc.device.getDeviceInfo = function( successCallback, errorCallback ) {
    createNativeCall( successCallback, errorCallback, "GetDeviceInfo");
  };

 /**
  * Fetches the content of a given URL and returns the contents as a string. Making a call to any domain is allowed.
  *  This is useful if you need to make calls that would normally not be allowed via an AJAX
  * call because of cross-domain policy.
  * Upon success, an object will be passed to the success handler that looks like: "URL contents"
  * <p>If <code>fetchContentsOfURL</code> is called from within the browser, we will use the browser XHR object to make the request. This means that the request is now subject to cross-domain restrictions.  To circumvent
  * this during development, you can use the Chrome browser and start with web security disabled.  The windows command for this is <code>chrome.exe --disable-web-security</code> while the OSX command is
  * <code>/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --disable-web-security</code>.
  * @example
    bc.device.fetchContentsOfURL(
        'http://my.sweet.feed/blob.xml',
        function( data ) {
        //data is equal to the contents of http://my.sweet.feed/blob.xml as a string.
        },
        function( data ) {
            bc.utils.warn( data.errorCode );
        }
    );
   *

   *
   * @param url The URL that the request should be made to.
   * @param successCallback The function that is called once the contents of the URL have been fetched.  The callback is passed a string which is the contents of the URL.
   * @param errorCallback The function that is called if there is an error fetching the contents of the URL.
     The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>,
     and a property named <code>errorMessage</code>, which provides additional information about this error.
  */
  bc.device.fetchContentsOfURL = function( url, successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      $.ajax( {
        url: url,
        success: successCallback,
        converters: {"* text": window.String,"text json": window.String, "text xml": window.String },
        error: function( err ) {
                  callErrorCallback( errorCallback, bc.device.codes.ERROR_FETCHING_CONTENTS_OF_URL_VIA_BROWSER, "It appears you are trying to use the fetchContentsOfURL request from within a browser.  However, there was an error fetching the contents of the URL via the browser xhr request.  Most likely this is due to a limitation of cross domain policies.  It is recommended that you use the Chrome browser and start the browser from the command line with the following command, 'chrome.exe --disable-web-security',  to circumvent this limitation during your development process.  NOTE you should only do this during development." );
                }
      });
      return;
    }

    createNativeCall( successCallback, errorCallback, "FetchContentsOfURL", { "url": url } );
  };

  /**
   * Posts data to the given URL and returns the results of this web request to the success callback function if one is passed to the request.  This is useful if you need to make a POST request that would normally not be allowed via an AJAX request
   * because of cross-domain policy.  If <code>postDataToURL</code> is called from within the browser, we will attempt to use the browser XHR object to make the request.  This means that the request is now subject to cross-domain restrictions.
   * To circumvent this during development, you can use the Chrome browser and start with web security disabled.  The windows command for this is <code>chrome.exe --disable-web-security</code> while the OSX command is
   * <code>/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --disable-web-security</code>.
   * @example
      var username = "test";
      var password = "password";
      var options = {
        data: {
          "username": username,
          "password": password
        },
        headers: {
          "Authorization": token
        }
      };

      bc.device.postDataToURL( "http://url/of/authentication/system", success, error, options );

      function success( results ) {
        if( results.status === "success" ) {
          //Handle code for logging the user in.
        } else {
          //There was an error logging the user in.
        }
      }

      function error( error ) {
        //There was an error making the request.
      }
   *
   * @param url The URL that request should be made to.
   * @param successCallback The function that is called once the POST request has been successfully made and a result returned.  The results are passed into the success callback.
   * @param errorCallback The function that is called if there was an error making this request.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>,
    and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @param options An object of options that specify additional properties to be sent to the server.  The options object accepts two properties of:
   <ul>
    <li>data - This is the data that will be passed to the server.  Typically another object.
    <li>headers - This allows you to specify the headers to be sent to the server.  This is useful for authentication.
  </ul>
   *
   */
  bc.device.postDataToURL = function( url, successCallback, errorCallback, options ) {
    var params = {};

    options = options || {};

    if( url === undefined ) {
      callErrorCallback( errorCallback, bc.device.codes.MISSING_REQUIRED_PARAMETER, "Missing required parameter of URL." );
      return;
    }

    if ( !bc.context.isNative ) {
      $.ajax( {
        url: url,
        type: "POST",
        data: options.data,
        headers: ( options.headers || {} ),
        success: successCallback,
        error: function( err ) {
                  callErrorCallback( errorCallback, bc.device.codes.GENERAL, "It appears you are trying to use the postDataToURL request from within a browser.  However, there was an error making the requst via the browser xhr request.  Most likely this is due to a limitation of cross domain policies.  It is recommended that you use the Chrome browser and start the browser from the command line with the following command, 'chrome.exe --disable-web-security',  to circumvent this limitation during your development process.  NOTE you should only do this during development." );
                }
      });
      return;
    }

    params.url = url;

    if( options.headers ) {
      params.headers = options.headers;
    }

    if( options.data ) {
      params.data = options.data;
    }

    createNativeCall( successCallback, errorCallback, "PostDataToURL",  params );
  };

  /**
   * The isDownloadAvailable api allows the developer to know whether or not this device supports the ability to download files.  If the device does support file download the successCallback will be called with a boolean
   * of true, if not false will be passed to the successCallback.  In general support for file download is universally available on iOS and any Android device running 2.3 or higher.
   * @param successCallback The callback function to be called with a boolean indicating whether or not this device supports file download.
   * @param errorCallback The callback function to be called if there is an error fetching this information from the device.
   * @example
   bc.device.isDownloadAvailable( showDownloadLinks );

   function showDownloadLinks( downloadSupported ) {
     if( !downloadSupported ) {
       console.log( "Downloads are not supported on this device.  Do not update UI to show download links." );
       return;
     }

     $( ".downloadLinks" ).addClass( "show" );
   }
   */
  bc.device.isDownloadAvailable = function( successCallback, errorCallback ) {
    if( bc.context.os === "ios" ) {
      successCallback( true );
      return;
    }
    createNativeCall( successCallback, errorCallback, "IsDownloadAvailable" );
  };

  /**
   * Allows a developer to programmatically download a file to the device.  This storage is persisted until explicity removed using the <code>bc.device.removeDownload</code>
   * API.  This is very useful, but not limited, for downloading media files such as video, audio or image files.  The success callback function is immediatly called once the device has registered the request to
   * download the files, NOT after the file has downloaded.  You can register event listeners for the <code>downloadprogress</code>, <code>downloaderror</code> and <code>downloadcomplete</code> on the bc object.
   * Below are the possible options that the requestDownload API takes.
   * <ul>
   *   <li>returnURLOfResourceInWorkshop - In the workshop we cannot access files stored on the file system, however, since the workshop cannot be run in offline mode and we realize that developers do not want to
   litter their code if statements checking if they are in the workshop we simply return the URL to the resource file when we are in the workshop.  This allows developers to use the same file path returned in
   the downloadinfo object for both apps running in the workshop and apps running in published container.  This defaults to true.</li>
       <li>progressInterval - The interval at which progress events are fired.  For example if 5 is passed in then a progress event will be fired when 5%, 10%, 15%...100% of the file has been downloaded. If 0 or an invalid value such as 101 then no progress events will be fired.  Defaults to 0.  <b>Note:</b> This event is only fired on iOS devices.</li>
       <li>showAndroidNativeProgress - A boolean specifing whether or not to show the progress indicator in the notification area on Android.  Defaults to true.</li>
       <li>downloadTitle - A title to show in the notification are on Anroid devices.</li>
    </ul>
   * @example
   var video = {
    "id": 1234567,
    "FLVURL": "http://url/to/the/mp4/file.mp4"
   };

   function success() {
     $( bc ).on( "downloadprogress", handleProgressEvent );
   }

   function error( error ) {
     //handle error
   }

   function handleProgressEvent( evt, info ) {
      //Draw progress indicator to screen.
   }

   bc.device.requestDownload( video.FLVURL, video.id.toString(), success, error, { progressInterval: 5 } );

   * @param resource The path the to the file that you would like to download, most likely a URL to the media file.
   * @param downloadID A unique ID for this particular download.  If you pass in an ID that already exists then the this file will be downloaded and will overwrite the current file with this ID.
   * @param successCallback The function that will be called once the download request has been registered by the device.
   * @param errorCallback The funciton that will be called if there is an error registering for the download.
   * @param options An object with overrides for the default options of "returnURLOfResourceInWorkshop", "progressInterval", "downloadTitle" and "showAndroidNativeProgress".
   */
  bc.device.requestDownload = function( resource, downloadID, successCallback, errorCallback, options ) {
    var settings = {
      returnURLOfResourceInWorkshop: true,
      progressInterval: 0,
      showAndroidNativeProgress: true
    };

    //Resource and uniqueID are required fields. If either are undefined we should call the error callback if exists and return.
    if( !resource || !downloadID ) {
      callErrorCallback( errorCallback, bc.device.codes.MISSING_REQUIRED_PARAMETER, "resource and downloadID are required fields for the bc.device.requestDownload API.  Not calling API as undefined was passed in for one of these values." );
      return;
    }

    if( typeof downloadID !== "string" ) {
      callErrorCallback( errorCallback, bc.device.codes.GENERAL, "downloadID must be of type string." );
      return;
    }

    $.extend( settings, options );

    settings.resource = resource;
    settings.downloadID = downloadID;
    createNativeCall( successCallback, errorCallback, "RequestDownload", settings );
  };

  /**
   * Allows a developer to retrieve information about any files that have been or are currently being downloaded to the device.  To retrieve information about a specific file or
   * files then an array of download IDs can be passed as an option.  These IDs must correspond to the uniqueID that was passed into the <code>bc.device.requestDownload</code> API.  If no downloadIDs are passed
   * in via the options then all downloads will be returned to the success handler as an array of <code>DownloadInfo</code> objects.  If <b>any</b> of the downloadIDs are invalid then
   * the error callback function is called.  The options parameter only accepts one valid property of downloadIDs, which is an array of downloadIDs.
   * @example
   function success( downloadInfoArray ) {
     //Passes in an array of download info objects.
   }

   //Called if an error occurs or an invalid ID is passed in via the downloadIDs property.
   function error( error ) {
     //Handle error
   }

   var options = { downloadIDs: [ "1234567", "7654321" ] };

   //Retrieves the DownloadInfo for the downloads with the unique ids of "1234567" and "7654321".
   bc.device.getDownloadInfo( success, error, options );

   //Retrieves all DownloadInfo objects that this app has ever downloaded and not removed.
   bc.device.getDownloadInfo( success, error );

   * @param successCallback The function that will be called with an array of <code>DownloadInfo</code> objects, which as the following properties:
    <ul>
     <li>downloadID (String) The unique ID for this download that was passed into the <code>bc.device.requestDownload</code> API</li>
     <li>resource (String) The URL that was passed into the <code>bc.device.requestDownload</code> API</li>
     <li>state (String) The current state of the download request. The possible values for this are "enqueued", "downloading", "errored", and "complete".</li>
     <li>size (Number) The file size of the downloaded data in bytes</li>
     <li>fileURI (String) The path to the file on disk.</li>
   </ul>
   * @param errorCallback The function that will be called if an error occurs or any invalid ID is passed in via the downloadIDs option.
   * @param options An object that currently has one valid property of "downloadIDs" which takes a value of an array of downloadIDs.
   */
  bc.device.getDownloadInfo = function( successCallback, errorCallback, options ) {
    createNativeCall( successCallback, errorCallback, "GetDownloadInfo", options );
  };

  /**
   * Removes a previously downloaded file from the device.  If the download is currently in progress then it will cancel the download and remove any partially download of the file.  The downloadID is a required
   * parameter and must correspond to the uniqueID that was passed into the <code>bc.device.requestDownload</code>.  The successCallback will be called once the file has been successfully removed.  The errorCallback
   * function will be called if there is no file that matches the provided downloadID or there is an error removing the file.
   * @example
   var video = {
    "id": 1234567,
    "FLVURL": "http://url/to/the/mp4/file.mp4",
    "downloaded": true
   };

   function success( downloadID ) {
     //Success.  If I keep any state locally I will want to update this now.
     video.downloaded = false;
   }

   function error( error ) {
     //There was an error removing the file download.
     console.warn( "Error removing file download with ID: " + error.downloadID );
   }

   bc.device.removeDownload( video.id.toString(), success, error );

   * @param downloadID A uniqueID that represents this downloaded file.  A list of currently downloaded files can be fetched via the <code>bc.device.getDownloadInfo</code> API.
   * @param successCallback The function that will be called once the file has been successfully removed.  The downloadID of the file will be passed to this success callback function.
   * @param errorCallback The function that will be called if an error occurs trying to remove a downloaded file.  The error object will have a property of errorCode, errorMessage and downloadID.
   */
  bc.device.removeDownload = function( downloadID, successCallback, errorCallback ) {

    //Make sure a downloadID was passed in and if not log an error and call the errorCallback.
    if( downloadID === undefined ) {
      callErrorCallback( errorCallback, bc.device.codes.MISSING_REQUIRED_PARAMETER, "The downloadID is a required parameter for the removeDownload API." );
      return;
    }

    if( typeof downloadID !== "string" ) {
      callErrorCallback( errorCallback, bc.device.codes.GENERAL, "downloadID must be of type string." );
      return;
    }

    createNativeCall( successCallback, errorCallback, "RemoveDownload", { downloadID: downloadID } );
  };


  /**
   * Opens the URI in the native application of the device if it supports that URI.  For example a URI of http://www.google.com would switch to the safari
   * browser and an open up to http://www.google.com, where as a URI of mailto:john@example.com would open the native mail client.  By default App Cloud opens
   * any a href link in a modal window, however, if you would like to programmatically control the opening of a modal window you can do so by passing in a value of true
   * for the modalWebBrowser property.  The container will call the success callback once it successfully passes the URI to the device to handle or has opened the modal window, if modalWebBrowser is set to true.
   * The error callback if the native device is unable to do anything with the URI that is passed in.  For example <code>bc.device.openURI( "badrequest", success, error )</code> would call the error callback
   * because the device would not know how to handle a URI of "badrequest".
   *
   * @param uri Is a required parameter, which is the URI that should be opened.  This can be any URI that the device knows how to open, for example http://, https:// or mailto:
   * @param successCallback The function that will be called once the modal window is opened or the device has opened the URI in the native application, for example Safari on iOS.
   * @param errorCallback The function that will be called if there is an error opening the URI on the device.  The error object will have a property of errorCode and errorMessage.
   * @param options An object that currently supports one property of "modalWebBrowser" that expects a boolean value.  This defaults to false.
   * @example
   function success() {
     //Opened the URI successfully.
   }

   function error( error ) {
     console.log( "There was an error opening the URI with error code: " + error.errorCode + " and an error message of: " + error.errorMessage );
   }

   bc.device.openURI( "http://www.brightcove.com", success, error, { modalWebBrowser: false } );
   */
  bc.device.openURI = function( uri, successCallback, errorCallback, options ) {
    var settings = {
      modalWebBrowser: false
    };

    if( uri === undefined ) {
      callErrorCallback( errorCallback, bc.device.codes.MISSING_REQUIRED_PARAMETER, "The URI to open is a required parameter for the openURI API." );
      return;
    }

    if( !bc.context.isNative ) {
      window.open( uri );
      if( typeof successCallback === "function" ) {
        successCallback();
      }
      return;
    }

    $.extend( settings, options );
    settings.uri = uri;
    createNativeCall( successCallback, errorCallback, "OpenURI", settings);
  };

 /**
  * Vibrates the device if the current device supports it.
  *
  * @example
    bc.device.vibrate( function( ) {
                         //my success handler
                       },
                       function( data ) {
                         bc.utils.warn( data.errorCode );
                       }
                     );
  *
  * @param successCallback The function to be called if the phone successfully vibrates.
  * @param errorCallback The function to be called if there is an error vibrating the phone.
    The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides
    additional information about this error.
  */
  bc.device.vibrate = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      $( "body" ).addClass( "vibrate" );
      if( typeof( successCallback ) === "function" ) {
        successCallback();
      }
      setTimeout( function() {
        $( "body" ).removeClass( "vibrate" );
      }, 1000 );
      return;
    }
    createNativeCall( successCallback, errorCallback, "Vibrate" );
  };


 /**
  * Specify which directions the application can be rotated to.  <b>Note that all of the views in a given template should allow for the device to be rotated in the same directions.  In future releases this will be enforced by the App Cloud
  * containers.</b>  The directions should be passed in as an array and can take in five different values:
  * <ul>
  * <li> <code>bc.ui.orientation.PORTRAIT</code> </li>
  * <li> <code>bc.ui.orientation.LANDSCAPE_LEFT</code> </li>
  * <li> <code>bc.ui.orientation.LANDSCAPE_RIGHT</code> </li>
  * <li> <code>bc.ui.orientation.PORTRAIT_UPSIDEDOWN</code> </li>
  * <li> <code>all</code></li>
  * </ul>
  *
  * @example
   bc.device.setAutoRotateDirections (
            [bc.ui.orientation.PORTRAIT, bc.ui.orientation.LANDSCAPE_RIGHT],
            function() {
              //my success handler
            },
            function( data ) {
               bc.utils.warn( data.errorCode );
            }
        );

  * @param direction An array of directions that the device can rotate to.  Possible values are: <code>bc.ui.orientation.PORTRAIT</code>, <code>bc.ui.orientation.LANDSCAPE_LEFT</code>, <code>bc.ui.orientation.LANDSCAPE_RIGHT</code>, <code>bc.ui.orientation.PORTRAIT_UPSIDEDOWN</code> or simply <code>all</code>.
  *
  * @param successCallback The function to be called if this registration successfully happens.
  * @param errorCallback The function to be called if there is an error.
        The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>,
        and a property named <code>errorMessage</code>, which provides additional information about this error.
  */
  bc.device.setAutoRotateDirections = function( directions, successCallback, errorCallback ) {
    createNativeCall( successCallback, errorCallback, "SetAutorotateOrientations", { "directions": directions.join(",") } );
  };

  /**
   * Make the application go full screen, hiding any other visible parts of the application except for the active view.  For example,
   * if running in the iOS container, this will hide the tab bar.
   *
   * <b>Note</b>: If called from the browser, the <code>successCallback</code> is called.
   *
   * @param successCallback The function to be called once the application goes into full screen.
   * @param errorCallback The function to be called if there is an error going into full screen.
     The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>,
     and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @param options An object with a set of optional parameters that can be passed in to control behavior.
   * <ul>
   *   <li>hideStatusBar: A boolean indicating whether on iOS devices the status bar should be hidden when going full screen. This defaults
   *    to false.
   * </ul>
   * @example
    bc.device.enterFullScreen(
                          function() {
                            alert("I'm fullscreen!");
                          },
                          function( data ) {
                            bc.utils.warn( data.errorCode );
                          },
                          {
                            "hideStatusBar":"true"
                          }
              );
   */
  bc.device.enterFullScreen = function( successCallback, errorCallback, options ) {
    var settings = {
      "hideStatusBar": false
    };


    if( !bc.context.isNative ) {
      if( typeof( successCallback ) === "function" ) {
        successCallback();
      }
      return;
    }

    $.extend( settings, options );

    createNativeCall( successCallback, errorCallback, "EnterFullScreen", settings );
  };

  /**
   * Exit full screen of the application.
   *
   * <b>Note</b>: If called from the browser, the <code>successCallback</code> is called.
   *
   * @param successCallback The function that is called once we have exited full screen.
   * @param errorCallback The function that is called if we hit an issue exiting full screen.
     The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>, and a
     property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
    bc.device.exitFullScreen( function() {
                            alert("I'm not fullscreen!");
                          },
                          function( data ) {
                            bc.utils.warn( data.errorCode );
                          }
                        );
   */
  bc.device.exitFullScreen = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      if( typeof( successCallback ) === "function" ) {
        successCallback();
      }
      return;
    }
    createNativeCall( successCallback, errorCallback, "ExitFullScreen" );
  };

  /**
   * Returns a boolean indicating whether or not the application is in full screen.  The returned
   * object is true if we are in full screen or false if not.
   *
   * <b>Note</b>: If called from the browser, the <code>successCallback</code> is called passing the value of true.
   *
   * @param successCallback The function to be called with data specifying whether or not the application is in full screen mode.
   * @param errorCallback The function to be called if there is an error.
     The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>,
     and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example bc.device.isFullScreen( function( data ) {
                                        if( data ) {
                                          alert( "I am in fullscreen" );
                                        } else {
                                          alert( "I am NOT in fullscreen" )
                                        }
                                     },
                                     function( data ) {
                                       bc.utils.warn( data.errorCode );
                                     }
               );
   */
  bc.device.isFullScreen = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      if( typeof( successCallback ) === "function" ) {
        successCallback( true );
      }
      return;
    }
    createNativeCall( successCallback, errorCallback, "IsFullScreen" );
  };

  /**
   * Shows an alert in a native dialog.  This is useful to use instead of a JavaScript alert function
   * call, because the JavaScript alert will show the name of the page (for example, <code>videos.html</code>) which is
   * not always desirable.  The success handler will be called after the user has dismissed the
   * alert.
   *
   * <b>Note</b>: If called from the browser, then a default JavaScript alert will be used.  The <code>successCallback</code> is then called once the alert has been interacted with.
   *
   * @param message The message to show in the native alert dialog.
   * @param successCallback The function to be called after the dialog alert has been dismissed.
   * @param errorCallback The function to be called if an error occurs.
     The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the codes defined in <code>bc.device.codes</code>,
     and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
    bc.device.alert( "Many turkeys are a rafter",
                      function() {
                        // my success handler
                      },
                      function( data ) {
                        bc.utils.warn( data.errorCode );
                      }
              });
   */
  bc.device.alert = function( message, successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      alert( message );
      if( typeof( successCallback ) === "function" ) {
        successCallback();
      }
      return;
    }
    createNativeCall( successCallback, errorCallback, "Alert", { "message": message } );
  };

  /**
   *@private
   */
  bc.device.isViewShowing = function( successCallback, errorCallback ) {
    createNativeCall( successCallback, errorCallback, "IsViewShowing" );
  };

  /**
   *@private
   */
  bc.device.setAdPolicy = function( ad_policy, successCallback, errorCallback ) {
    createNativeCall( successCallback, errorCallback, "SetAdPolicy", ad_policy );
  };

  /**
   * Brings up a native QR scanner to read 2D QR codes.  On success, this will call the <code>successCallback</code>, passing to the function the string that is represented by
   * reflects the scanned QR code.
   *
   * <p><b>Note:</b> If <code>getQRCode</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.CAMERA_UNAVAILABLE</code>.</p>
   *
   * @param successCallback The function that is called once the QR code has been read.  The <code>successCallback</code> is passed a string that reflects the QR code.
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   */
  bc.device.getQRCode = function(successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.CAMERA_UNAVAILABLE, "There is no camera available to this device" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "GetQRCode" );
  };

  /**
   * @private
   */
  bc.device.goBack = function( successCallback, errorCallback ) {
    createNativeCall( successCallback, errorCallback, "GoBack" );
  };

   /**
    * Internal API for container to fire JavaScript event
    * @private
    */
   bc.device.trigger = function( eventType, eventData ) {
     if(eventData === undefined) {
       $( bc ).trigger( eventType );
     } else {
       $( bc ).trigger( eventType, [ JSON.parse( atob( eventData ) ).result ]);
     }
   };


 /*****************************************
  * External Screen APIs
  ****************************************/

  /**
   * Given a URL to a video (encoded to H.264 as progressive download or HLS) will play the video on an externally connected screen.
   * Typically this means playing the video on an Apple TV.  In this case, the phone/tablet will continue to show whatever view is
   * currently in focus and the video will be sent to the Apple TV (externally connected screen).  If this function is called
   * with the same URL as the one that is currently loaded into the external video player, the effect is that playback continues
   * from the current timecode.  This is most useful in the circumstance where the video is currently paused.  Calling the playVideo
   * video function with the same URL would resume playback.
   *
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object.
   *
   * <p><b>Note:</b>This API only works on iOS devices.
   *
   * <p><b>Note:</b> If <code>playVideo</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION</code>.</p>
   *
   * @param videoURL The URL to a video to playback.  The URL must be in a format that can playback on an iOS device.  It is strongly
   * recommended that this be an HLS encoded video.  This parameter is passed as a String.
   * @param successCallback The function that is called if the URL is successfully passed to the video player.  Note: this does not mean that playback has begun.
   * It only means that the URL has been registered with the video player.  You can listen for the "externalscreenvideoplaying" event to be fired on the bc object.
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @param options An options object.  We look for the timecode which if not 0, will play the video at the given time.
   * Support for this depends on encoding of the video, as explained here:
   * http://developer.apple.com/library/ios/#documentation/mediaplayer/reference/MPMoviePlayerController_Class/Reference/Reference.html#//apple_ref/occ/instp/MPMoviePlayerController/initialPlaybackTime
	@example
    $(bc).bind( "externalscreenconnected", function() {
      bc.device.externalscreen.playVideo( "http://someurl.com/a.m4v", successHandler, errorHandler);
    });

    $(bc).bind( "externalscreenvideoplaying", function() {
      // update UI on iPad to give them controls to pause/stop video playing on Apple TV
    });

   */
  bc.device.externalscreen.playVideo = function( videoURL, successCallback, errorCallback, options) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.playVideo is only available in native applications" );
      return;
    }
 	options = options || {};
	options.url = videoURL;

    createNativeCall( successCallback, errorCallback, "ExternalScreenVideoPlay", options );
  };

  /**
   * This function will pause any currently playing video on a connected Apple TV where playback was initiated by calling the
   * the <i>bc.device.externalscreen.playVideo</i> function.  If no video is currently playing, calling this function has no
   * effect.  You can resume playback of a paused video by calling <i>bc.device.externalscreen.playVideo</i> and pass in the URL
   * to the video for the currently paused video.  Calling playVideo with the same URL will resume playback from the timecode that the video
   * was paused at.
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object. </p>
   *
   *<p><b>Note:</b>This API only works on iOS devices.</p>
   *
   * <p><b>Note:</b> If <code>pauseVideo</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION</code>.</p>
   *
   * @param successCallback The function that is called if the video is successfully paused.
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
    $(bc).bind( "externalscreenconnected", function() {
      // start playing back a video
      bc.device.externalscreen.playVideo( "http://someurl.com/a.m4v" );
    });

    // register a tap handler for the user hitting the pause button.  Typically, this pause button would be displayed on the iOS device
    $("#pauseButton").bind( "tap", function() {
      bc.device.externalscreen.pauseVideo( pauseSuccessHandler );
    });

    function pauseSuccessHandler() {
      // now that pause was called successfully we update the pause button control on the iPad to show the play action
    }
   */
  bc.device.externalscreen.pauseVideo = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.pauseVideo is only available in native applications" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "ExternalScreenVideoPause" );
  };

  /**
   * This function will stop any currently playing video on a connected Apple TV where playback was initiated by calling the
   * the <i>bc.device.externalscreen.playVideo</i> function.  When this function is called the timecode of the video is set
   * back to 0.  Calling playVideo would start the video over from the beginning.  If you only want to pause the video then call
   * <i>bc.device.externalscreen.pauseVideo</i>.  This function is most frequently used when you want to stop playback of a video
   * and let a user choose a new video to playback.
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object.
   *
   *<p><b>Note:</b>This API only works on iOS devices.
   *
   * <p><b>Note:</b> If <code>stopVideo</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION</code>.</p>
   *
   * @param successCallback The function that is called if the video is successfully stopped.
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
    $(bc).bind( "externalscreenconnected", function() {
      // start playing back a video
      bc.device.externalscreen.playVideo( "http://someurl.com/a.m4v", successHandler, errorHandler);
    });

    // register a tap handler for the user hitting the stop button.  Typically, this stop button would be displayed on the iOS device
    $("#stopButton").bind( "tap", function() {
      bc.device.externalscreen.stopVideo( stopSuccessHandler, stopErrorHandler );
    });

    function stopSuccessHandler() {
      // now that stop was called successfully we let the user pick from a new set of videos to playback
    }
   */
  bc.device.externalscreen.stopVideo = function( successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.stopVideo is only available in native applications" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "ExternalScreenVideoStop" );
  };

  /**
   * This function will seek to the specified timecode for a video that is on the AppleTV.  The video must have been initiated on the
   * AppleTV by calling <i>bc.device.externalscreen.playVideo</i> function.  This function will work if the video is either currently
   * playing or is paused.
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object.
   *
   *<p><b>Note:</b>This API only works on iOS devices.
   *
   * <p><b>Note:</b> If <code>seekVideo</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION</code>.</p>
   *
   * @param timecode The timecode that you would like to seek to.  Could be forward or backward from the current timecode.  This
   * parameter is passed as a Number.  This timecode represents the 'seconds' that you want to seek to.  For example, if you wanted
   * to seek to the three minute mark then you would call <i>bc.device.externalscreen.seekVideo( 180, successHandler, errorHandler)
   * @param successCallback The function that is called if the video is successfully seeked into.
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
   $( "#skip" ).bind( "tap", function() {
     //Jump to minute 5
      bc.device.externalscreen.seekVideo( 600 );
   });
   */
  bc.device.externalscreen.seekVideo = function( timecode, successCallback, errorCallback ) {
    var params = {
      timecode: timecode
    };

    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.seekVideo is only available in native applications" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "ExternalScreenVideoSeek", params );
  };

  /**
   * This function will display a webview on an external screen using specified the URI.
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object.
   *
   *<p><b>Note:</b>This API only works on iOS devices.
   *
   * <p><b>Note:</b> If <code>seekVideo</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION</code>.</p>
   *
   * @param uri The URI string specified in the manifest
   * @param successCallback The function that is called if the webview is displayed
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
   $( "#display" ).bind( "tap", function() {
      bc.device.externalscreen.openExternalWebview( "test.html" );
   });
   */
  bc.device.externalscreen.openExternalWebView = function( uri, successCallback, errorCallback ) {
    var params = {
      uri: uri
    };

    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.openExternalWebview is only available in native applications" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "ExternalScreenWebViewOpen", params );
  };

  /**
   * This function will remove the view on an external screen.
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object.
   *
   *<p><b>Note:</b>This API only works on iOS devices.
   *
   * @param successCallback The function that is called if the webview is displayed
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
   $( "#close" ).bind( "tap", function() {
      bc.device.externalscreen.closeExternalScreen();
   });
   */
  bc.device.externalscreen.closeExternalScreen = function(successCallback, errorCallback ) {
    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.closeExternalScreen is only available in native applications" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "ExternalScreenClose");
  };

  /**
   * This function is used for communication between an external webview and the device's active web view.  If called from the device,
   * this will post the message to the external screen if the external screen has an active webview.  If called from the external web view,
   * this will post the message to the active device webview.
   *
   * <p><b>Note</b>:In order for the Apple TV to be connected the user of the iOS device must have turned on mirroring.  You can listen for
   * mirroring to be turned on/off by the user by listening for the "externalscreenconnected" event on the bc object.
   *
   *<p><b>Note:</b>This API only works on iOS devices.
   *
   * <p><b>Note:</b> If <code>seekVideo</code> is called from the browser, we will call the errorCallback with the <code>errorCode: bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION</code>.</p>
   *
   * @param successCallback The function that is called if the webview is displayed
   * @param errorCallback The function that is called if an error occurs.  The <code>errorCallback</code> function is passed an object that contains a property named <code>errorCode</code>, which maps to one of the
     codes defined in <code>bc.device.codes</code>, and a property named <code>errorMessage</code>, which provides additional information about this error.
   * @example
   $( "#postmessage" ).bind( "tap", function() {
      bc.device.externalscreen.postMessage();
   });
   */
  bc.device.externalscreen.postMessage = function(message, successCallback, errorCallback ) {
    var params = {
      message: message
    };

    if( !bc.context.isNative ) {
      callErrorCallback( errorCallback, bc.device.codes.COMMAND_ONLY_AVAILABLE_IN_A_NATIVE_APPLICATION, "bc.device.externalscreen.postMessage is only available in native applications" );
      return;
    }
    createNativeCall( successCallback, errorCallback, "PostMessage", params );
  };

 /*****************************************
  * Internal use only
  ****************************************/
 /**
  * @private
  */
  bc.device.getCallbackFunctionMap = function() {
    return _callbackFunctionMap;
  };

 /**
  * @private
  */
  bc.device.clearCallbackFunctionMap = function() {
    _callStack = [];
    _callbackFunctionMap = {};
  };

 /**
  * @private
  */
  bc.device.nativeCall = function( api ) {
   var $bridge;
   // window.androidCommandQueue is inject by the android container
   if( window.androidCommandQueue !== undefined ) {
     window.androidCommandQueue.enqueue( api );
   } else {
     _callStack.push( api );
     $bridge = $( "#bc-device-bridge" );
     if( $bridge.length === 0 ) {
       $bridge = createIframeBridge();
     }
     $bridge.attr( "src", "bccommand://checkqueue" );
    }
  };

 /**
  * @private
  * This is actually doing a shift, but we call it pop for backwards compatiability.
  */
  bc.device.popNativeCall = function() {
    return _callStack.shift();
  };

}( bc.lib.jQuery ));
/*global bc:true atob:false*/
/*jshint indent:2, browser: true, white: false devel:true undef:false, evil:true */

/**
 * bc.ui provides functions that interact with the DOM.  This includes initializing and managing
 * elements for momentum scrolling, functions to help transition between pages, and helper functions to draw common UI
 * elements (for example an AJAX loader).
 * @namespace
 */
bc.ui = {};

( function( $, undefined ) {

  var _pendingTransition,
      _currentTransitionDirection,
      TRANSITION_FORWARD = "forwardPage",
      TRANSITION_BACK = "backPage";

  /**
   * The type of transitions that we support.
   * @namespace
   */
  bc.ui.transitions = {};
  /** Transition type of SLIDE_LEFT will slide the current page off the screen to the left. */
  bc.ui.transitions.SLIDE_LEFT = 0;
  /** Transition type of SLIDE_RIGHT will slide the current page off the screen to the right. */
  bc.ui.transitions.SLIDE_RIGHT = 1;

  /**
   * The possible orientation directions, which can be set in <a href="bc.device.html#.setAutoRotateDirections"><code>bc.device.setAutoRotateDirections</code></a>.
   * @namespace
   */
  bc.ui.orientation = {};
  /** The view is being displayed in the portrait mode. */
  bc.ui.orientation.PORTRAIT = "1";
  /** The view is being rendered as if it were rotated 180 degrees. */
  bc.ui.orientation.PORTRAIT_UPSIDEDOWN = "2";
  /** The view is being rendered as if it were rotated 270 degrees clockwise. */
  bc.ui.orientation.LANDSCAPE_LEFT = "3";
  /** The view is being rendered as if it were rotated 90 degrees clockwise. */
  bc.ui.orientation.LANDSCAPE_RIGHT = "4";

  /**
   * An array that keeps track of the page history.  For example, if our first page is a list of videos and then when we click
   * on a item it transitions (using the <code>bc.ui.forwardPage</code> function) to a video detail page, we would have two pages in our <code>bc.ui.pageStack</code>:
   * The first item being the original page and the second the new page we transitioned to, $detailsPage in this example.
   */
  bc.ui.pageStack = [];

  /**
   * Tracks whether or not the current view is in transition.
   */
  bc.ui.inTransition = false;

  /** The currently active page, meaning the page that is currently in view.*/
  bc.ui.currentPage = undefined;

  function addScroller( scroller ) {
    var $scroller = $( scroller );
    if( $scroller.data( "bc-scroller" ) === undefined ) {
      $scroller.data( "bc-scroller", new Scrollbox( scroller ) );
    }
  }

  function enableScrollerForPage( $page ) {
    $page.children( '.scroller' ).each( function( index, scroller ) {
      addScroller( scroller );
    });

    if( $page.hasClass( 'scroller' ) ) {
      addScroller( $page[0] );
    }
  }

  //When we remove a page from the DOM, we set the image src to an empty image to release them from RAM.  (just removing the image tag does not release it)
  function destroyImages( $page ) {
    $page.find( 'img' ).each( function() {
      this.src = "data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs=";
    });
  }

  function destroyScrollers( $page ) {
    var $scrollers = $page.children( '.scroller' ),
        aScroller;
    if ( $scrollers.length > 0 ) {
      $.each( $scrollers, function( idx, scroller ) {
        aScroller = $( scroller ).data( 'bc-scroller' );
        if ( aScroller ) {
          aScroller = null;
          $( scroller ).data( 'bc-scroller', null );
        }
      });
    }
  }

  function destroyVideos( $page ) {
    $page.find( 'video' ).each( function() {
      this.pause();
      $( this ).remove();
    });
  }

  function freeRAM( $page ) {
    destroyScrollers( $page );
    destroyVideos( $page );
    destroyImages( $page );
  }

  function forwardPageEnd( toPage ) {
    bc.ui.inTransition = false;
    bc.ui.currentPage.find( '.bc-active' ).removeClass( 'bc-active' );
    $( bc ).trigger( "pagehide", bc.ui.currentPage );

    bc.ui.pageStack.push( $( toPage[0] ) );
    bc.ui.currentPage = toPage;
    $( bc ).trigger( "pageshow", toPage );
  }

  function backPageEnd( toPage ) {
    var $previousPage = bc.ui.pageStack.pop(),
        removePage = $previousPage.data( "bc-internal-injected" ),
        aScroller;

    bc.ui.inTransition = false;
    bc.ui.currentPage.find( '.header .back' ).removeClass( 'active' );
    bc.ui.currentPage = toPage;
    $previousPage.removeData( "bc-internal-injected" );

    //If we hit memory issues start by setting the transform to nothing here.
    if ( removePage ) {
      freeRAM( $previousPage );
      $previousPage.css( 'display', 'none' ).remove();
    } else {
      aScroller = ( $previousPage.hasClass( "scroller" ) ? $previousPage : $previousPage.find( ".scroller" ) );
      bc.ui.scrollToTop( aScroller );
      $( bc ).trigger( "pagehide", $previousPage );
    }
    $( bc ).trigger( "pageshow", bc.ui.currentPage );
  }

  function changePage( from, to, options ) {

    if( bc.ui.currentPage !== from ) {
      bc.utils.warn('ERROR: trying to transition with a page that is not the currently displayed page.');
    }

    switch( options.transitionType ) {
      case bc.ui.transitions.SLIDE_LEFT:
        to[0].style.setProperty( "-webkit-transition", "-webkit-transform " + options.transitionTime + "ms ease-out" );
        to[0].style.setProperty( "-webkit-transform", "translate3d( 0px, 0px, 0px )" );
        from[0].style.setProperty( "-webkit-transform", "translate3d( -100%, 0px, 0px )" );
        from[0].style.setProperty( "-webkit-transition", "-webkit-transform " + options.transitionTime + "ms ease-out" );
        break;
      case bc.ui.transitions.SLIDE_RIGHT:
        from[0].style.setProperty( "-webkit-transition", "-webkit-transform " + options.transitionTime + "ms ease-out" );
        from[0].style.setProperty( "-webkit-transform", "translate3d( 100%, 0px, 0px )" );
        to[0].style.setProperty( "-webkit-transition", "-webkit-transform " + options.transitionTime + "ms ease-out" );
        to[0].style.setProperty( "-webkit-transform", "translate3d( 0px, 0px, 0px )" );
        break;
    }

    // WARNING: Extreme edge case. 'webkitTransitionEnd' doesn't fire on it's own when time is 0
    if( options.transitionTime === 0) {
        from.trigger('webkitTransitionEnd');
    }
  }

  function registerEventListeners() {
    $( bc ).on( "backbuttonpressed", function( evt ) {
      if( bc.ui.inTransition ) {
        return;
      }

      if( bc.ui.pageStack.length > 1 ) {
        bc.ui.backPage();
      } else {
        bc.device.goBack();
      }
    });
  }

  function checkForPendingTransitions() {
    var pendingFunction,
        page,
        options;

    if( bc.ui.inTransition ) {
      setTimeout( checkForPendingTransitions, 100 );
      return;
    }

    pendingFunction = _pendingTransition.pendingFunction;
    page = _pendingTransition.page;
    options = _pendingTransition.options;
    _pendingTransition = undefined;
    if( page !== undefined ) {
      bc.ui[pendingFunction]( page, options );
    } else {
      bc.ui[pendingFunction]( options );
    }
  }

  function jQueryWrappedDOM( toPage ) {
    // take either a string or jQuery object.
    if ( typeof( toPage ) === "string" || toPage instanceof Element ) {
      return $( toPage );
    } else if( toPage instanceof jQuery ){
      return toPage;
    } else {
      console.error( "forwardPage must take a valid CSS selector, an HTML element or jQuery object as a parameter." );
      return null;
    }
  }

  $( bc ).on( "init", function() {
    bc.ui.init();
    registerEventListeners();
  });

  /**
   * @private
   */
  bc.ui.init = function() {
    if( bc.ui.pageStack.length !== 0 || $( ".page" ).length === 0 ) {
      return;
    }
    $( ".page:eq(0)" )[0].style.setProperty( "-webkit-transform", "translate3d( 0px, 0px, 0px )" );

    bc.ui.currentPage = $( '.page:eq(0)' );
    bc.ui.enableScrollers();
    bc.ui.pageStack.push( bc.ui.currentPage );
  };

  bc.ui.setCurrentPage = function( elem ) {
    var $elem = $( elem );
    if( !$elem.hasClass( "page" ) ) {
      console.warn( "Tyring to set page with an element that does not have class page." );
      return;
    }
    $elem[0].style.setProperty( "-webkit-transform", "translate3d( 0px, 0px, 0px )" );
    bc.ui.currentPage = $elem;
    bc.ui.pageStack[0] = $elem;
  };

  /**
   * <b>DEPRECATED</b>  With the release of 1.7.2 this is no longer necessary.Called to refresh all existing scrollers on the page.
   * The Brightcove App Cloud microframework
   * attempts to call this function for you automatically as appropriate.  For example,
   * when pages are first added to the DOM, a page is transitioned to, or whenever the window size changes.
   *
   * <p>However, there are cases where you will need to call this function explicitly.  The most likely case
   * is when changes are made to the contents of the active page that affects its size.  For example,
   * if the active page is a list of entries and additional entries are injected.</p>
   *
   * @param options The options object has the possible value of <code>allPages</code>, which is a boolean indicating whether or not to refresh
   *                scrollers on all of the pages or just the currently active page.  The default value is false, since updating all of the pages
   *                is usually unnecessary and expensive.
   * @example
   bc.ui.refreshScrollers( { "allPages": true } ); //Will refresh the scrollers for all pages on the view.
   */
  bc.ui.refreshScrollers = function( options ) {
    console.log( "bc.ui.refreshScrollers is no longer necessary.  This call can be removed from your code." );
    return;
  };

  /**
   * Scroll to the top of the provided momentum scroller.
   *
   * @param $scroller A jQuery object that represents the scroller element to scroll to the top of the provided scroller.
   * @example
   bc.ui.scrollToTop( $( '.scroller' ) ); //Scrolls the page to the top of the page.
   */
  bc.ui.scrollToTop = function( $scroller ) {
    var aScroller = $scroller.data( 'bc-scroller' );
    if ( aScroller ) {
      aScroller.scrollToY( 0, "0ms");
    }
  };

  /**
   * <b>Note</b> that the App Cloud SDK automatically manages the construction and destruction of these scrollers for you. Therefore
   * by default you should not have to call <code>enableScrollers</code>. The App Cloud SDK calls <code>enableScrollers</code> when it first loads and any time we
   * transition to a new page.
   *
   * <p>This function can be called to enable momentum scrolling for any element with a class of <code>scroller</code> that is a direct child of the page
   * that was passed in.  If no page is passed to the function, then it defaults to the currently active page.</p>
   *
   * @param $page An optional jQuery object that either has a class of <code>scroller</code> on it or is a parent of an element(s) that has
   * the class <code>scroller</code> on it.
   * @example
   bc.ui.enableScrollers(); //Will initialize momentum scrolling for this current page.
   */
  bc.ui.enableScrollers = function( $page ) {
    if ( $page ) {
      enableScrollerForPage( $page );
    } else {
      $( ".page" ).each( function() {
        enableScrollerForPage( $( this ) );
      });
    }
  };

  /**
   * @private
   */
  bc.ui.getScrollerForPage = function( index ) {
    var $page;
    if( index !== undefined ) {
      $page = bc.ui.pageStack[index];
    }

    $page = $page || bc.ui.currentPage;

    return $page.find( ".scroller" ).data( "bc-scroller" );
  };

  /**
   * Transitions to the <code>toPage</code> parameter from the current page.  The type of transition to be applied can be passed as parameter; otherwise it
   * defaults to <code>SLIDE_LEFT</code>.  The <code>toPage</code> parameter can be passed as either a CSS selector, DOM Element, or jQuery Object.  The passed <code>toPage</code> can already be part of the
   * Document or can be independent.  If it is independent, then this function will dynamically insert the <code>toPage</code> into the DOM.  If this function
   * inserts the page into the Document, then when the back function is called, it will automatically remove the associated page.  Generally speaking,
   * it is recommended to allow pages to be dynamically inserted and removed from the DOM so as to keep the DOM in-memory as small as possible.
   *
   * <p>Both the current page and the new page should have a CSS class of <code>page</code> as defined in the theme file.
   * This function triggers a <code>pageshow</code> and a <code>pagehide</code> event once the transition has completed.  The <code>pageshow</code> event passes the
   * new page as data parameter, while the <code>pagehide</code> event passes the page we transitioned from as data parameter.</p>
   *
   * <code>bc.ui.forwardPage</code> should be used when logically transitioning from one page to the next.  In addition to providing a visual
   * transition, it will add pages to the <code>bc.ui.pageStack</code> so that a history stack of pages can be maintained. To return to the original page (the from page)
   * call <code>bc.ui.backPage()</code>.
   *
   * @param toPage The page we want to transition to.
   * @param options An object that overrides the default values of the <code>forwardPage</code> function.  The possible values are:
     <ul>
        <li><code>transitionType</code> specifies the direction of the type of transition to use during the transition. Defaults to <code>SLIDE_LEFT</code></li>
        <li><code>transitionTime</code> specifies how the long the transition should take.  Smaller = faster.  The time is in milliseconds.</li>
     </ul>
   * .
   * @example
   $( bc ).on( 'pageshow', function( $secondPage ) {
     //Got the pageshow event and the page we transitioned to.
   });

   $(bc ).on( 'pagehide', function( $firstPage ) {
     //Got the pagehide event and the page we transition from.
   });

   bc.ui.forwardPage( $( '.second_page' ) ); //transitions to the new page
   */
  bc.ui.forwardPage = function( toPage, options ) {
    var $toPage,
        settings,
        timeoutValue = 1;

    //We want to protect against getting double transition events
    if( toPage === undefined || _pendingTransition !== undefined ) {
      return;
    }

    if( bc.ui.inTransition ) {
      if( _currentTransitionDirection !== TRANSITION_FORWARD ) {
        _pendingTransition = {
                              "pendingFunction": "forwardPage",
                              "page": toPage,
                              "options": options
                             };
        checkForPendingTransitions();
      }
      return;
    }

    $toPage = jQueryWrappedDOM( toPage );

    //No valid toPage was passed in.
    if( $toPage === null ) {
      return;
    }

    // determine if we need to inject into the page
    if ( $toPage.parent().length === 0 ) {
      $toPage[0].style.setProperty( "-webkit-transform", "translate3d( 100%, 0px, 0px )" );
      $toPage.appendTo( "body" );
      $toPage.data( "bc-internal-injected", true );
      timeoutValue = 300;
    } else {
      $toPage.data( "bc-internal-injected", false );
    }

    settings = {
      "transitionType": bc.ui.transitions.SLIDE_LEFT,
      "transitionTime": 300
    };

    $.extend( settings, options );

    bc.ui.inTransition = true;
    _currentTransitionDirection = TRANSITION_FORWARD;

    //register event listener for when the transition is complete so that we can clean things up and trigger events.
    bc.ui.currentPage.one( 'webkitTransitionEnd', function() {
      forwardPageEnd( $toPage );
    });

    bc.ui.enableScrollers( $toPage );
    changePage( bc.ui.currentPage, $toPage, settings );
    $( ".back-button" ).addClass( "show" );
  };

  /**
   * Transitions from the current page back to the previous page.  The type of transition can be specified, but by default the current page will
   * slide off the page to the right.  Once the transition has completed, the previous page is removed from the DOM if the page was injected into the DOM via the forwardPage API.  We remove
   * these pages from the DOM in order to minimize memory use.  The backPage function triggers a <code>pageshow</code> event once the transition has completed and a <code>pagehide</code> event
   * once the current page has been hidden.  <b>Note</b> that the <code>pagehide</code> event is only fired if the page was not removed.
   *
   * <p><code>bc.ui.backPage()</code> is associated with the <code>bc.ui.forwardPage()</code> function.  After a previous use of <code>bc.ui.forwardPage()</code> to transition to a page,
   * call the <code>bc.ui.backPage()</code> function to transition back to the original page.  A common use would be when a user taps on a back button.  You would
   * call <code>bc.ui.backPage()</code> to transition back to the original page.</p>
   *
   * @param options An object that contains the options that can be provided to the transition function.  The possible values are:
    <ul>
      <li> <code>transitionType</code> - defines the type of transition to use when moving back to the previous page and must correspond to a value defined in <code>bc.ui.transitions</code>.
      The default value is <code>bc.ui.transitions.SLIDE_RIGHT</code>, which will slide the current page off to the right.</li>
      <li> <code>toPage</code> - If you would like to inject a new page into the DOM and transition to this page you can pass in the DOM element to inject into the page.  <b>Note</b> If there is
      more then one page in the page stack this value is ignored</b></li>
      <li><code>transitionTime</code> specifies how the long the transition should take.  Smaller = faster.  The time is in milliseconds.</li>
    </ul>
   *
   * @example
   $( bc ).on( 'pageshow', function( $firstPage ) {
     //Got the pageshow event and the page we transitioned to.
     //In this example the first page we started on.
   });

   bc.ui.backPage(); //transitions back to the first page

   //The above line is equivalent to calling
   // bc.ui.backPage( {
   //  "transitionType": bc.ui.transitions.SLIDE_RIGHT
   // })
   */
   bc.ui.backPage = function( options ) {
     var settings,
         $toPage,
         $fromPage = bc.ui.currentPage;

     if( _pendingTransition !== undefined ) {
       return;
     }

     //We want to protect against getting double transition events
     if( bc.ui.inTransition ) {
       if( _currentTransitionDirection !== TRANSITION_BACK ) {
         _pendingTransition = {
                               "pendingFunction": TRANSITION_BACK,
                               "options": options
                              };
         checkForPendingTransitions();
       }
       return;
     }

     settings = {
       "transitionType": bc.ui.transitions.SLIDE_RIGHT,
       "transitionTime": 300
      };
     $.extend( settings, options );


     //If a DOM element was passed in for the page to transition to and it is not in the DOM we should inject it into the page and the pagestack and then transition to it.
     if( settings.toPage && ( bc.ui.pageStack.length === 1 || bc.ui.pageStack.length === 0 ) ) {
       $toPage = jQueryWrappedDOM( settings.toPage );

       //No valid toPage was passed in.
       if( $toPage === null ) {
         return;
       }

       if( !$toPage.hasClass( "page" ) ) {
         console.warn( "The back page we are trying to inject and transition to does not have a class of 'page'." );
         return;
       }

       $toPage[0].style.setProperty( "-webkit-transform", "translate3d( -100%, 0px, 0px )" );

       // determine if we need to inject into the page
       if( $toPage.parent().length === 0 ) {
         $toPage.appendTo( "body" );
       }

       //Add this page pageStack.
       bc.ui.pageStack.splice( bc.ui.pageStack.length - 1, 0, $toPage );
     }

     if( bc.ui.pageStack.length === 1 || bc.ui.pageStack.length === 0 ) {
       //If we are in a "more navigation view" then we should navigate back to the more page.  (This is the more menu on iOS)
       if( bc.context.moreNavigationView ) {
         bc.device.navigateToMoreMenu();
         return;
       }
       bc.utils.warn( "ERROR: Calling transition back when there is only one page in the page stack" );
       return;
     }

     $toPage = bc.ui.pageStack[ bc.ui.pageStack.length - 2 ];

     if( $toPage === undefined || $toPage === null ) {
       bc.utils.warn( "There is no page to transition back to" );
       return;
     }

     // set our down state for the back button
     $fromPage.find( '.header .back-button' )
                      .addClass( 'active' );

     bc.ui.inTransition = true;
     _currentTransitionDirection = TRANSITION_BACK;

     bc.ui.currentPage.one( 'webkitTransitionEnd', function() {
       backPageEnd( $toPage );
     });
     changePage( bc.ui.currentPage, $toPage, settings );
     if( bc.ui.pageStack.length === 2 && !bc.context.moreNavigationView ) {
       $( ".back-button" ).removeClass( "show" );
     }
   };

  /**
   * Returns an HTML snippet that can be used to inject a CSS3 animated spinner into the DOM.  The size and color are controlled in the theme file.
   *
   * @return An HTML snippet that represents a CSS3 animated spinner.  (AJAX loader)
   * @example
   $( 'body' ).append( bc.ui.spinner() ); //Injects an HTML spinner into the body of the page.
   */
  bc.ui.spinner = function() {
    return '<div class="spinner ' + bc.context.os +'">' +
                  '<div class="bar1"></div>' +
                  '<div class="bar2"></div>' +
                  '<div class="bar3"></div>' +
                  '<div class="bar4"></div>' +
                  '<div class="bar5"></div>' +
                  '<div class="bar6"></div>' +
                  '<div class="bar7"></div>' +
                  '<div class="bar8"></div>' +
                  '<div class="bar9"></div>' +
                  '<div class="bar10"></div>' +
                  '<div class="bar11"></div>' +
                  '<div class="bar12"></div>' +
                '</div>';
  };

  //Load the spinner into an included template
  Mark.includes.spinner = bc.ui.spinner();

  /**
   * Generates the HTML snippet for the header.
   * @param options An object that represents the settings that can be overridden for this HTML snippet.  Below are the default values.
   <pre>
   {
     "backButton": false, //A boolean for whether or not to show a back button.
     "refreshButton": false, //A boolean for whehter or not to show a refreshButton.
     "title": ""
   }
   </pre>
   @return A string that is the HTML snippet for the header.
   * @private
   */
  bc.ui.headerHTML = function( options ) {
    var html = "",
        settings = {
          "backButton": false,
          "refreshButton": false,
          "title": ""
        };

    $.extend( settings, options );

    html = "<header class='header'>";

    if( settings.backButton ) {
      html += "<div class='back-button'></div>";
    }

    html += "<h1 class='header-a ellipsis'>" + settings.title + "</h1>";

    if( settings.refreshButton ) {
      html += "<div class='refresh-button'></div>";
    }

    return ( html += "</header>" );
  };

  /**
    * Returns the current width of the viewport.
    * @return The width of the viewport as a number, in pixels.
    * @example
    var width = bc.ui.width(); //sets width to the current width of the viewport.
    */
   bc.ui.width = function() {
     if( $( "#BCDeviceWrapper" ).length > 0) { //If we are inside our developer extension return the width of the wrapper.
       return $( "#BCDeviceWrapper" ).width();
     } else {
       return $( window ).width();
     }
   };

   /**
    * Returns the current height of the viewport.
    * @return The height of the viewport as a number, in pixels.
    @example
    var height = bc.ui.height(); //sets height to the current height of the viewport
    */
   bc.ui.height = function() {
     if( $( "#BCDeviceWrapper" ).length > 0) { //If we are inside our developer extension return the height of the wrapper.
       return $( "#BCDeviceWrapper" ).height();
     } else {
       return $( window ).height();
     }
   };

  /**
   * @private
   * Should only be used by Jasmine tests to override private variables.
   */
  bc.ui.setPrivateVariables = function( options ) {
    for( var prop in options ) {
      if( typeof options[prop] === "string" ) {
        eval( prop + " = '" + options[prop] + "'");
      } else {
        eval( prop + " = " + options[prop] );
      }
    }
  };

  //The browser is sporadically showing all white pages, due to rendering issues.  This addresses that.
  $( bc ).on( "pageshow", function() {
    setTimeout( function() {
      document.body.style.display = "none";
      document.body.style.display = "block";
    }, 0 );
  });

})( bc.lib.jQuery );
/**
* Brightcove Metrics provides functions to measure interactions with applications.
* @namespace
*/
bc.metrics = {};

/**
 * The <code>connectionstatechange</code> event is fired when there is change in the state of the connection to the internet.  The event passes a data object that
 * currently has a single property of <code>online</code>, which is a boolean indicating whether or not the device is currently connected to the internet.
 *
 * @example
 * $( bc ).on( "connectionstatechange", function( evt, data ) {
 *   if( data.online ) {
 *     //Check to see if there is new data available.
 *   }
 * });
 *
 * @name connectionstatechange
 * @event
 * @memberOf bc
 * @param event (type of connectionstatechange)
 * @param data The data object currently has a single property of <code>online</code>, which is a boolean indicating whether or not the device is currently connected to the internet.
 */

( function( bc, undefined ) {

  var _settings,
      _transit,
      _poll_interval,
      _loader,
      _events = [],
      _liveEvents = [],
      _errors = 0,
      _store_pendingevents_interval,
      _previous_pending_events,
      _$bc = $( bc );

  _$bc.bind( "init", function() {
    var $img;
    var frequency = 5000;
    var url = "https://trk.kissmetrics.com/e?_k=46b26eea9908c85fa960e11c169fda7bc84c67ef&_n=workshop+session&_p=start&account_id=" + bc.accountID;
    var sessionURL = "https://trk.kissmetrics.com/e?_k=46b26eea9908c85fa960e11c169fda7bc84c67ef&_n=workshop+session+time&_p=session&account_id=" + bc.accountID + "&frequency=" + frequency;

    //If we are in the workshop we want to ping kissmetrics
    if( bc.utils.runningInWorkShop() ) {
      $img = $( "<img />" );
      $img.attr( "src", url );

      setInterval( function() {
        $img.attr( "src", sessionURL );
      }, frequency );

      $img.on( "load", function() {
        handleOnlineEvent( true );
      });

      $img.on( "error", function() {
        handleOnlineEvent( false );
      });
    }

  });

  /**@private*/
  bc.metrics._contentSession = {};

  function Event(data) {
    this.getData = function() {
      return data;
    };

    this.isReady = function() {
      return true;
    };

    this.complete = function() {
      _events.shift();
      storePendingEventsQueue();
    };

    this.error = function() {};
  }

  function LiveEvent(data) {
    var last = new Date().getTime(),
        transit;

    this.getData = function() {
      transit = new Date().getTime();
      data.units = transit - last;
      return data;
    };

    this.isReady = function() {
      var d = new Date().getTime();
      return ( _settings.interval > 0 && d - last > _settings.interval );
    };

    this.complete = function() {
      last = transit;
      transit = undefined;
    };

    this.error = function() {
      transit = undefined;
    };
  }

  function getEventData( event, eventData ) {
    return $.extend({
      event: event,
      time:( new Date() ).getTime()
    }, eventData );
  }

  function flush( force ) {
    if( bc.metrics.isInitialized() ) {
      if( force || _settings.interval <= 0 ) {
        send();
      } else if( _poll_interval === undefined ) {
        _poll_interval = setInterval( function() {
          send();
        }, _settings.interval );
      }
    }
  }

  function send() {
    var url, data;
    if( !bc.metrics.isInitialized() || _transit !== undefined ){
      // not ready, event already in _transit or nothing to send
      return;
    }
    while( !_transit ) {
      if( _events.length !== 0 ) {
        _transit = _events[0];
      } else {
        for( var i=0, len=_liveEvents.length; i < len; i++ ) {
          if( _liveEvents[i].isReady() ) {
            _transit = _liveEvents[i];
            break;
          }
        }
        if( !_transit ) {
          return;
        }
      }
    }

    data = $.extend( _transit.getData(), _settings.data );
    url = _settings.uri + "?" + $.param( data );
    _loader.attr( "src",url );
  }

  function storePendingEventsQueue() {
    var pendingEvents = [];

    for( var i = 0, len = _events.length; i < len; i++ ) {
      pendingEvents.push( _events[i].getData() );
    }

    for( i = 0, len = _liveEvents.length; i < len; i++ ) {
      pendingEvents.push( _liveEvents[i].getData() );
    }

    if( !bc.utils.isEqual( pendingEvents, _previous_pending_events ) ) {
      _previous_pending_events = pendingEvents;
      $( bc ).trigger( "metrics:pendingevents", { events: pendingEvents } );
    }

  }

  function handleOnlineEvent( success ) {
    if( success ) {
      if( !bc.context.online ) {
        bc.context.online = true;
        _$bc.trigger( "connectionstatechange", { online: true } );
      }
    } else {
      if( bc.context.online ) {
        bc.context.online = false;
        _$bc.trigger( "connectionstatechange", { online: false } );
      }
    }
  }

  function bind_loader() {
    _loader.on( "load", function() {
      _errors = 0;
      _transit.complete();
      _transit = undefined;
      handleOnlineEvent( true );
      send();
    });

    _loader.on( "error", function() {
      console.log( "ERROR: unable to send metrics to", _settings.uri );
      handleOnlineEvent( false );
      setTimeout( function(){
        if( _transit !== undefined ) {
          _transit.error();
          _transit=undefined;
        }
        send();
      }, _settings.interval * Math.log( ++_errors ) );
    });
  }

  /**
   * Initialize and bind the metrics runtime
   *
   * @param options - an object containing the metrics options
   *    - uri - the url used to send metric events
   *    - interval - the millisecond interval between event polling
   *        (zero or negative will cause all tracking events to fire immediately,
   *        but will also mean that live tracking must be explicitly dispatched )
   * @param data - session wide metadata that will be included with each event
   * @private
   */
  bc.metrics.init = function( options, data ) {
    $( function(){
      _settings = $.extend( {}, bc.metrics.defaults, options );
      _settings.data = data || {};
      _settings.data.domain = _settings.domain;
      _settings.uri = ( _settings.uri.indexOf( "tracker" ) > -1 ) ? _settings.uri : _settings.uri + "/tracker";

      if( _settings.pendingMetrics ) {
        for( var i = 0, len = _settings.pendingMetrics.length; i < len; i++ ) {
          _events.push( new Event( _settings.pendingMetrics[i] ) );
        }
      }
      _loader = _settings.loader || $( "<img />" ).appendTo( $( "head" ) );
      bind_loader();
      flush();
      _store_pendingevents_interval = setInterval( storePendingEventsQueue, 5000 );
    });
  };

  /**
   * @private
   */
  bc.metrics.addNotificationID = function( notificationID ) {
    _settings.data.message = notificationID;
  };

  /**
   * @private
   */
  bc.metrics.removeNotificationID = function() {
    if( _settings && _settings.data && _settings.data.message ) {
      delete _settings.data.message;
    }
  };

  /**
   * Send a tacking event
   *
   * @param event - the name of the event
   * @param properties - metadata specific to this event
   * @private
   */
  bc.metrics.track = function( event, properties ) {
    _events.push( new Event( getEventData( event, properties ) ) );
    flush();
  };

  /**
   * Create a live tracking event which sends time delta information for each poll interval.
   *
   * @param event - the name of the event
   * @param properties - metadata specific to this event
   * @returnValue - a closure which can be used to cancel the tracking and flush the last time delta
   * @private
   */
  bc.metrics.live = function( event, properties ) {
    var liveEvent = new LiveEvent( getEventData( event + "_usage", properties ) );

    bc.metrics.track( event + "_view" , properties);
    _liveEvents.push(liveEvent);

    liveEvent.die = function(){
      for( var i = 0, len = _liveEvents.length; i < len; i++ ) {
        if( _liveEvents[i] == liveEvent ) {
          _events.push( new Event( liveEvent.getData() ) );
          _liveEvents.splice( i, 1 );
          flush();
          return;
        }
      }
    };

    flush();
    return function() { liveEvent.die(); };
  };

  /**
   * Start tracking how long a user interacts with a given peice of content within the application.  For example the blog.js view tracks how long the user
   * spends on each article by calling bc.metrics.startContentSession when they open the article and then bc.metrics.endContentSession when they either navigate away from the
   * view or back to the list of the articles.
   * @param uri A unique identifier for this content.  Ideally a URI to the content on the web, but any unique ID will suffice.
   * @param name A human readable name to be displayed in the analytics section of App Cloud.
   */
  bc.metrics.startContentSession = function( uri, name ) {
    if( !uri || !name ) {
      console.log( "bc.metrics.startContentSession requires the parameters 'uri' and 'name'." );
      return;
    }

    if( bc.metrics._contentSession[uri] ) {
      console.log( uri + " content session is already being tracked." );
      return;
    }
    bc.metrics._contentSession[uri] = bc.metrics.live( "content", { uri: uri, name: name } );
  };

  /**
   * Stop tracking the users session for a given peice of content.  "endContentSession" should be called with the same URI that was called with its corresponding "startContentSession".
   * @param uri A unique identifier for this content.  This needs to match the URI that was passed into the startContentSession event.
   */
  bc.metrics.endContentSession = function( uri ) {
    if( !uri ) {
      console.log( "bc.metrics.endContentSession requires a uri." );
      return;
    }

    if( !bc.metrics._contentSession[uri] ) {
      console.log( "bc.metrics.endContentSession cannot find a matching startContentSession for the URI: " + uri );
      return;
    }
    bc.metrics._contentSession[uri].call();
    delete bc.metrics._contentSession[uri];
  };

  /**
   * @private
   */
  bc.metrics.isInitialized = function() {
    return _settings !== undefined;
  };

  /** @private */
  bc.metrics.clear = function() {
    _transit = undefined;
    _poll_interval = undefined;
    _events = [];
    _liveEvents = [];
    _loader = undefined;
  };

  bc.metrics.defaults =  {
    uri:"http://localhost:44080/tracker", // the url of the event tracking service
    interval:5000 // the default poll interval
  };

})( bc );
/*global bc:true atob:false jQuery:false*/
/*jshint indent:2, browser: true, white: false devel:true*/

 /**
* Brightcove App Cloud events that are added to the jQuery object.  This enables you to
* use the jQuery event attachment functions of (on) with these set of events.
* These events will work across both desktops and mobile devices.
*
* @namespace
* @name Events
*/
bc.events = {};

( function( $, undefined ) {
  var MOVE_THRESHOLD = 20;

  if( bc.utils.hasTouchSupport() ) {
    bc.events.start = "touchstart";
    bc.events.move = "touchmove";
    bc.events.end = "touchend";
    bc.events.cancel = "touchcancel";
  } else {
    bc.events.start = "mousedown";
    bc.events.move = "mousemove";
    bc.events.end = "mouseup";
    bc.events.cancel = "touchcancel";
  }


  /**
   * Private functions
   */

  /**
   * Set up our config object to register getter/setter functions for its properties to ensure we can tie into the SDK where
   * appropriate
   */
  function initConfigObject() {
    var touchEventsEnabled = true;

    Object.defineProperty( bc.config, "touchEventsEnabled", {
      get: function() {
        return touchEventsEnabled;
      },
      set: function( value ) {
        if ( !value ) {
          removeAllEvents();
        }

        touchEventsEnabled = value;
      }
    });
  }


  /**
   * De-register all of the gesture events that the SDK had registered
   */
  function removeAllEvents() {
    delete $.event.special.tap;
    delete $.event.special.swipe;
  };

  initConfigObject();

  /**
   * @event
   * @memberOf Events
   * @name tap
   *
   * @description Tap is an event that represents a user 'tapping' on an element.  It is recommended to use <code>tap </code> rather than <code>click</code>
   * as it eliminates 300ms of delay that binding to a <code>click</code> event introduces on some platforms.  On non-touch
   * devices, the <code>tap</code> event  is equivalent to <code>click</code>.  This means binding to <code>tap</code> will work across both
   * touch and non-touch devices.
   *
   * @example $( '.cancel-button' ).on( 'tap', function() {
      alert('Are you sure you want to cancel form submission?');
   });
   */
  $.event.special.tap = {
    setup: function( data ) {
      var $this = $( this );

      $this.on( bc.events.start, function( event ) {
        if ( !bc.config.touchEventsEnabled ) {
          return;
        }

        var moved = false,
            touching = true,
            origTarget = event.target,
            origEvent = event.originalEvent,
            origPos = event.type == "touchstart" ? [origEvent.touches[0].pageX, origEvent.touches[0].pageY] : [ event.pageX, event.pageY ],
            originalType,
            tapHoldTimer;

        var touchMoveHandler = function( event ) {
          var newPageXY = event.type == "touchmove" ? event.originalEvent.touches[0] : event;
          if ( ( Math.abs( origPos[0] - newPageXY.pageX ) > MOVE_THRESHOLD ) || ( Math.abs( origPos[1] - newPageXY.pageY ) > MOVE_THRESHOLD ) ) {
            moved = true;
          }
        };

        var touchEndHandler = function( event ) {
          $this.off( bc.events.move, origTarget, touchMoveHandler );
          clearTimeout( tapHoldTimer );
          touching = false;

          /* ONLY trigger a 'tap' event if the start target is
           * the same as the stop target.
           */
          if ( !moved && ( origTarget === event.target ) ) {
            originalType = event.type;
            event.type = "tap";
            event.pageX = origPos[0];
            event.pageY = origPos[1];
            $.event.handle.call( $this[0], event );
            event.type = originalType;
          }
        };

        //We want to protect against them tapping and holding.  So we start a timer to see if they haven't moved or released.
        tapHoldTimer = setTimeout( function() {
          $this.off( bc.events.end, touchEndHandler )
               .off( bc.events.move, touchMoveHandler );
        }, 750 );

        //Register the move event listener so we know if this is not actually a tap but a swipe or scroll
        $this.on( bc.events.move, touchMoveHandler );

        //Register the end event so we can check to see if we should fire a tap event and cleanup.
        $this.one( bc.events.end, touchEndHandler );
      });
    }
  };

 /**
  * @event
  * @memberOf Events
  * @name swipe
  *
  * @description On touch platforms, users can provide input with a 'swipe' gesture.  For example, a user placing their finger on the screen
  * and dragging it.  When the <code>swipe</code> event is fired, the type of event will be <code>swipe</code>.  An additional parameter, either <code>swipeRight</code> or <code>swipeLeft</code>, will be passed to
  * any bound functions.  This additional parameter can be used to understand in which
  * direction the user is swiping.
  *
  * @example  $('.image').on( 'swipe', function(evt, direction) {
      if( direction === 'swipeRight' ) {
        handleSwipeRight( this );
      } else {
        handleSwipeLeft( this );
      }
   });
  *
  */

  $.event.special.swipe = {
    setup: function( data ) {
      var $this = $( this );

      $this.on( bc.events.start, function( event ) {
        if ( !bc.config.touchEventsEnabled ) {
          return;
        }

        var touching = true,
            origEvent = event.originalEvent,
            origTarget = event.target,
            origPos = event.type == "touchstart" ? [origEvent.touches[0].pageX, origEvent.touches[0].pageY] : [ event.pageX, event.pageY ],
            tapHoldTimer,
            $elem = $( event.target );

        var touchMoveHandler = function( event ) {
          var newPageXY = event.type == "touchmove" ? event.originalEvent.touches[0] : event;
          if ( (Math.abs(origPos[0] - newPageXY.pageX) > MOVE_THRESHOLD) && (  Math.abs(origPos[1] - newPageXY.pageY) < MOVE_THRESHOLD ) ) {
            $this.off( bc.events.end, origTarget, touchEndHandler );
            $this.off( bc.events.move, touchMoveHandler );
            clearTimeout( tapHoldTimer );
            $elem.trigger( 'swipe', ( origPos[0] > newPageXY.pageX ) ? 'swipeLeft' : 'swipeRight' );
          }
        };

        var touchEndHandler = function( event ) {
          $this.off( bc.events.move, touchMoveHandler );
          clearTimeout( tapHoldTimer );
          touching = false;
        };

        //We want to protect against them tapping and holding.  So we start a timer to see if they haven't moved or released.
        tapHoldTimer = setTimeout( function() {
          $this.off( bc.events.end, touchEndHandler )
                .off( bc.events.move, touchMoveHandler );
          }, 750 );

        //Register the move event listener so we know if this is not actually a tap but a swipe or scroll
        $this.on( bc.events.move, touchMoveHandler );

        //Register the end event so we can check to see if we should fire a tap event and cleanup.
        $this.one( bc.events.end, touchEndHandler );

      });
    }
  };


})( bc.lib.jQuery );
// Underscore.js 1.3.3
// (c) 2009-2012 Jeremy Ashkenas, DocumentCloud Inc.
// Underscore is freely distributable under the MIT license.
// Portions of Underscore are inspired or borrowed from Prototype,
// Oliver Steele's Functional, and John Resig's Micro-Templating.
// For all details and documentation:
// http://documentcloud.github.com/underscore
(function(){function r(a,c,d){if(a===c)return 0!==a||1/a==1/c;if(null==a||null==c)return a===c;a._chain&&(a=a._wrapped);c._chain&&(c=c._wrapped);if(a.isEqual&&b.isFunction(a.isEqual))return a.isEqual(c);if(c.isEqual&&b.isFunction(c.isEqual))return c.isEqual(a);var e=l.call(a);if(e!=l.call(c))return!1;switch(e){case "[object String]":return a==""+c;case "[object Number]":return a!=+a?c!=+c:0==a?1/a==1/c:a==+c;case "[object Date]":case "[object Boolean]":return+a==+c;case "[object RegExp]":return a.source==
c.source&&a.global==c.global&&a.multiline==c.multiline&&a.ignoreCase==c.ignoreCase}if("object"!=typeof a||"object"!=typeof c)return!1;for(var f=d.length;f--;)if(d[f]==a)return!0;d.push(a);var f=0,g=!0;if("[object Array]"==e){if(f=a.length,g=f==c.length)for(;f--&&(g=f in a==f in c&&r(a[f],c[f],d)););}else{if("constructor"in a!="constructor"in c||a.constructor!=c.constructor)return!1;for(var h in a)if(b.has(a,h)&&(f++,!(g=b.has(c,h)&&r(a[h],c[h],d))))break;if(g){for(h in c)if(b.has(c,h)&&!f--)break;
g=!f}}d.pop();return g}var s=this,I=s._,o={},k=Array.prototype,p=Object.prototype,i=k.slice,J=k.unshift,l=p.toString,K=p.hasOwnProperty,y=k.forEach,z=k.map,A=k.reduce,B=k.reduceRight,C=k.filter,D=k.every,E=k.some,q=k.indexOf,F=k.lastIndexOf,p=Array.isArray,L=Object.keys,t=Function.prototype.bind,b=function(a){return new m(a)};"undefined"!==typeof exports?("undefined"!==typeof module&&module.exports&&(exports=module.exports=b),exports._=b):s._=b;b.VERSION="1.3.3";var j=b.each=b.forEach=function(a,
c,d){if(a!=null)if(y&&a.forEach===y)a.forEach(c,d);else if(a.length===+a.length)for(var e=0,f=a.length;e<f;e++){if(e in a&&c.call(d,a[e],e,a)===o)break}else for(e in a)if(b.has(a,e)&&c.call(d,a[e],e,a)===o)break};b.map=b.collect=function(a,c,b){var e=[];if(a==null)return e;if(z&&a.map===z)return a.map(c,b);j(a,function(a,g,h){e[e.length]=c.call(b,a,g,h)});if(a.length===+a.length)e.length=a.length;return e};b.reduce=b.foldl=b.inject=function(a,c,d,e){var f=arguments.length>2;a==null&&(a=[]);if(A&&
a.reduce===A){e&&(c=b.bind(c,e));return f?a.reduce(c,d):a.reduce(c)}j(a,function(a,b,i){if(f)d=c.call(e,d,a,b,i);else{d=a;f=true}});if(!f)throw new TypeError("Reduce of empty array with no initial value");return d};b.reduceRight=b.foldr=function(a,c,d,e){var f=arguments.length>2;a==null&&(a=[]);if(B&&a.reduceRight===B){e&&(c=b.bind(c,e));return f?a.reduceRight(c,d):a.reduceRight(c)}var g=b.toArray(a).reverse();e&&!f&&(c=b.bind(c,e));return f?b.reduce(g,c,d,e):b.reduce(g,c)};b.find=b.detect=function(a,
c,b){var e;G(a,function(a,g,h){if(c.call(b,a,g,h)){e=a;return true}});return e};b.filter=b.select=function(a,c,b){var e=[];if(a==null)return e;if(C&&a.filter===C)return a.filter(c,b);j(a,function(a,g,h){c.call(b,a,g,h)&&(e[e.length]=a)});return e};b.reject=function(a,c,b){var e=[];if(a==null)return e;j(a,function(a,g,h){c.call(b,a,g,h)||(e[e.length]=a)});return e};b.every=b.all=function(a,c,b){var e=true;if(a==null)return e;if(D&&a.every===D)return a.every(c,b);j(a,function(a,g,h){if(!(e=e&&c.call(b,
a,g,h)))return o});return!!e};var G=b.some=b.any=function(a,c,d){c||(c=b.identity);var e=false;if(a==null)return e;if(E&&a.some===E)return a.some(c,d);j(a,function(a,b,h){if(e||(e=c.call(d,a,b,h)))return o});return!!e};b.include=b.contains=function(a,c){var b=false;if(a==null)return b;if(q&&a.indexOf===q)return a.indexOf(c)!=-1;return b=G(a,function(a){return a===c})};b.invoke=function(a,c){var d=i.call(arguments,2);return b.map(a,function(a){return(b.isFunction(c)?c||a:a[c]).apply(a,d)})};b.pluck=
function(a,c){return b.map(a,function(a){return a[c]})};b.max=function(a,c,d){if(!c&&b.isArray(a)&&a[0]===+a[0])return Math.max.apply(Math,a);if(!c&&b.isEmpty(a))return-Infinity;var e={computed:-Infinity};j(a,function(a,b,h){b=c?c.call(d,a,b,h):a;b>=e.computed&&(e={value:a,computed:b})});return e.value};b.min=function(a,c,d){if(!c&&b.isArray(a)&&a[0]===+a[0])return Math.min.apply(Math,a);if(!c&&b.isEmpty(a))return Infinity;var e={computed:Infinity};j(a,function(a,b,h){b=c?c.call(d,a,b,h):a;b<e.computed&&
(e={value:a,computed:b})});return e.value};b.shuffle=function(a){var b=[],d;j(a,function(a,f){d=Math.floor(Math.random()*(f+1));b[f]=b[d];b[d]=a});return b};b.sortBy=function(a,c,d){var e=b.isFunction(c)?c:function(a){return a[c]};return b.pluck(b.map(a,function(a,b,c){return{value:a,criteria:e.call(d,a,b,c)}}).sort(function(a,b){var c=a.criteria,d=b.criteria;return c===void 0?1:d===void 0?-1:c<d?-1:c>d?1:0}),"value")};b.groupBy=function(a,c){var d={},e=b.isFunction(c)?c:function(a){return a[c]};
j(a,function(a,b){var c=e(a,b);(d[c]||(d[c]=[])).push(a)});return d};b.sortedIndex=function(a,c,d){d||(d=b.identity);for(var e=0,f=a.length;e<f;){var g=e+f>>1;d(a[g])<d(c)?e=g+1:f=g}return e};b.toArray=function(a){return!a?[]:b.isArray(a)||b.isArguments(a)?i.call(a):a.toArray&&b.isFunction(a.toArray)?a.toArray():b.values(a)};b.size=function(a){return b.isArray(a)?a.length:b.keys(a).length};b.first=b.head=b.take=function(a,b,d){return b!=null&&!d?i.call(a,0,b):a[0]};b.initial=function(a,b,d){return i.call(a,
0,a.length-(b==null||d?1:b))};b.last=function(a,b,d){return b!=null&&!d?i.call(a,Math.max(a.length-b,0)):a[a.length-1]};b.rest=b.tail=function(a,b,d){return i.call(a,b==null||d?1:b)};b.compact=function(a){return b.filter(a,function(a){return!!a})};b.flatten=function(a,c){return b.reduce(a,function(a,e){if(b.isArray(e))return a.concat(c?e:b.flatten(e));a[a.length]=e;return a},[])};b.without=function(a){return b.difference(a,i.call(arguments,1))};b.uniq=b.unique=function(a,c,d){var d=d?b.map(a,d):a,
e=[];a.length<3&&(c=true);b.reduce(d,function(d,g,h){if(c?b.last(d)!==g||!d.length:!b.include(d,g)){d.push(g);e.push(a[h])}return d},[]);return e};b.union=function(){return b.uniq(b.flatten(arguments,true))};b.intersection=b.intersect=function(a){var c=i.call(arguments,1);return b.filter(b.uniq(a),function(a){return b.every(c,function(c){return b.indexOf(c,a)>=0})})};b.difference=function(a){var c=b.flatten(i.call(arguments,1),true);return b.filter(a,function(a){return!b.include(c,a)})};b.zip=function(){for(var a=
i.call(arguments),c=b.max(b.pluck(a,"length")),d=Array(c),e=0;e<c;e++)d[e]=b.pluck(a,""+e);return d};b.indexOf=function(a,c,d){if(a==null)return-1;var e;if(d){d=b.sortedIndex(a,c);return a[d]===c?d:-1}if(q&&a.indexOf===q)return a.indexOf(c);d=0;for(e=a.length;d<e;d++)if(d in a&&a[d]===c)return d;return-1};b.lastIndexOf=function(a,b){if(a==null)return-1;if(F&&a.lastIndexOf===F)return a.lastIndexOf(b);for(var d=a.length;d--;)if(d in a&&a[d]===b)return d;return-1};b.range=function(a,b,d){if(arguments.length<=
1){b=a||0;a=0}for(var d=arguments[2]||1,e=Math.max(Math.ceil((b-a)/d),0),f=0,g=Array(e);f<e;){g[f++]=a;a=a+d}return g};var H=function(){};b.bind=function(a,c){var d,e;if(a.bind===t&&t)return t.apply(a,i.call(arguments,1));if(!b.isFunction(a))throw new TypeError;e=i.call(arguments,2);return d=function(){if(!(this instanceof d))return a.apply(c,e.concat(i.call(arguments)));H.prototype=a.prototype;var b=new H,g=a.apply(b,e.concat(i.call(arguments)));return Object(g)===g?g:b}};b.bindAll=function(a){var c=
i.call(arguments,1);c.length==0&&(c=b.functions(a));j(c,function(c){a[c]=b.bind(a[c],a)});return a};b.memoize=function(a,c){var d={};c||(c=b.identity);return function(){var e=c.apply(this,arguments);return b.has(d,e)?d[e]:d[e]=a.apply(this,arguments)}};b.delay=function(a,b){var d=i.call(arguments,2);return setTimeout(function(){return a.apply(null,d)},b)};b.defer=function(a){return b.delay.apply(b,[a,1].concat(i.call(arguments,1)))};b.throttle=function(a,c){var d,e,f,g,h,i,j=b.debounce(function(){h=
g=false},c);return function(){d=this;e=arguments;f||(f=setTimeout(function(){f=null;h&&a.apply(d,e);j()},c));g?h=true:i=a.apply(d,e);j();g=true;return i}};b.debounce=function(a,b,d){var e;return function(){var f=this,g=arguments;d&&!e&&a.apply(f,g);clearTimeout(e);e=setTimeout(function(){e=null;d||a.apply(f,g)},b)}};b.once=function(a){var b=false,d;return function(){if(b)return d;b=true;return d=a.apply(this,arguments)}};b.wrap=function(a,b){return function(){var d=[a].concat(i.call(arguments,0));
return b.apply(this,d)}};b.compose=function(){var a=arguments;return function(){for(var b=arguments,d=a.length-1;d>=0;d--)b=[a[d].apply(this,b)];return b[0]}};b.after=function(a,b){return a<=0?b():function(){if(--a<1)return b.apply(this,arguments)}};b.keys=L||function(a){if(a!==Object(a))throw new TypeError("Invalid object");var c=[],d;for(d in a)b.has(a,d)&&(c[c.length]=d);return c};b.values=function(a){return b.map(a,b.identity)};b.functions=b.methods=function(a){var c=[],d;for(d in a)b.isFunction(a[d])&&
c.push(d);return c.sort()};b.extend=function(a){j(i.call(arguments,1),function(b){for(var d in b)a[d]=b[d]});return a};b.pick=function(a){var c={};j(b.flatten(i.call(arguments,1)),function(b){b in a&&(c[b]=a[b])});return c};b.defaults=function(a){j(i.call(arguments,1),function(b){for(var d in b)a[d]==null&&(a[d]=b[d])});return a};b.clone=function(a){return!b.isObject(a)?a:b.isArray(a)?a.slice():b.extend({},a)};b.tap=function(a,b){b(a);return a};b.isEqual=function(a,b){return r(a,b,[])};b.isEmpty=
function(a){if(a==null)return true;if(b.isArray(a)||b.isString(a))return a.length===0;for(var c in a)if(b.has(a,c))return false;return true};b.isElement=function(a){return!!(a&&a.nodeType==1)};b.isArray=p||function(a){return l.call(a)=="[object Array]"};b.isObject=function(a){return a===Object(a)};b.isArguments=function(a){return l.call(a)=="[object Arguments]"};b.isArguments(arguments)||(b.isArguments=function(a){return!(!a||!b.has(a,"callee"))});b.isFunction=function(a){return l.call(a)=="[object Function]"};
b.isString=function(a){return l.call(a)=="[object String]"};b.isNumber=function(a){return l.call(a)=="[object Number]"};b.isFinite=function(a){return b.isNumber(a)&&isFinite(a)};b.isNaN=function(a){return a!==a};b.isBoolean=function(a){return a===true||a===false||l.call(a)=="[object Boolean]"};b.isDate=function(a){return l.call(a)=="[object Date]"};b.isRegExp=function(a){return l.call(a)=="[object RegExp]"};b.isNull=function(a){return a===null};b.isUndefined=function(a){return a===void 0};b.has=function(a,
b){return K.call(a,b)};b.noConflict=function(){s._=I;return this};b.identity=function(a){return a};b.times=function(a,b,d){for(var e=0;e<a;e++)b.call(d,e)};b.escape=function(a){return(""+a).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;").replace(/\//g,"&#x2F;")};b.result=function(a,c){if(a==null)return null;var d=a[c];return b.isFunction(d)?d.call(a):d};b.mixin=function(a){j(b.functions(a),function(c){M(c,b[c]=a[c])})};var N=0;b.uniqueId=
function(a){var b=N++;return a?a+b:b};b.templateSettings={evaluate:/<%([\s\S]+?)%>/g,interpolate:/<%=([\s\S]+?)%>/g,escape:/<%-([\s\S]+?)%>/g};var u=/.^/,n={"\\":"\\","'":"'",r:"\r",n:"\n",t:"\t",u2028:"\u2028",u2029:"\u2029"},v;for(v in n)n[n[v]]=v;var O=/\\|'|\r|\n|\t|\u2028|\u2029/g,P=/\\(\\|'|r|n|t|u2028|u2029)/g,w=function(a){return a.replace(P,function(a,b){return n[b]})};b.template=function(a,c,d){d=b.defaults(d||{},b.templateSettings);a="__p+='"+a.replace(O,function(a){return"\\"+n[a]}).replace(d.escape||
u,function(a,b){return"'+\n_.escape("+w(b)+")+\n'"}).replace(d.interpolate||u,function(a,b){return"'+\n("+w(b)+")+\n'"}).replace(d.evaluate||u,function(a,b){return"';\n"+w(b)+"\n;__p+='"})+"';\n";d.variable||(a="with(obj||{}){\n"+a+"}\n");var a="var __p='';var print=function(){__p+=Array.prototype.join.call(arguments, '')};\n"+a+"return __p;\n",e=new Function(d.variable||"obj","_",a);if(c)return e(c,b);c=function(a){return e.call(this,a,b)};c.source="function("+(d.variable||"obj")+"){\n"+a+"}";return c};
b.chain=function(a){return b(a).chain()};var m=function(a){this._wrapped=a};b.prototype=m.prototype;var x=function(a,c){return c?b(a).chain():a},M=function(a,c){m.prototype[a]=function(){var a=i.call(arguments);J.call(a,this._wrapped);return x(c.apply(b,a),this._chain)}};b.mixin(b);j("pop,push,reverse,shift,sort,splice,unshift".split(","),function(a){var b=k[a];m.prototype[a]=function(){var d=this._wrapped;b.apply(d,arguments);var e=d.length;(a=="shift"||a=="splice")&&e===0&&delete d[0];return x(d,
this._chain)}});j(["concat","join","slice"],function(a){var b=k[a];m.prototype[a]=function(){return x(b.apply(this._wrapped,arguments),this._chain)}});m.prototype.chain=function(){this._chain=true;return this};m.prototype.value=function(){return this._wrapped}}).call(this);
//     Backbone.js 0.9.10

//     (c) 2010-2012 Jeremy Ashkenas, DocumentCloud Inc.
//     Backbone may be freely distributed under the MIT license.
//     For all details and documentation:
//     http://backbonejs.org

(function(){

  // Initial Setup
  // -------------

  // Save a reference to the global object (`window` in the browser, `exports`
  // on the server).
  var root = this;

  // Save the previous value of the `Backbone` variable, so that it can be
  // restored later on, if `noConflict` is used.
  var previousBackbone = root.Backbone;

  // Create a local reference to array methods.
  var array = [];
  var push = array.push;
  var slice = array.slice;
  var splice = array.splice;

  // The top-level namespace. All public Backbone classes and modules will
  // be attached to this. Exported for both CommonJS and the browser.
  var Backbone;
  if (typeof exports !== 'undefined') {
    Backbone = exports;
  } else {
    Backbone = root.Backbone = {};
  }

  // Current version of the library. Keep in sync with `package.json`.
  Backbone.VERSION = '0.9.10';

  // Require Underscore, if we're on the server, and it's not already present.
  var _ = root._;
  if (!_ && (typeof require !== 'undefined')) _ = require('underscore');

  // For Backbone's purposes, jQuery, Zepto, or Ender owns the `$` variable.
  Backbone.$ = root.jQuery || root.Zepto || root.ender;

  // Runs Backbone.js in *noConflict* mode, returning the `Backbone` variable
  // to its previous owner. Returns a reference to this Backbone object.
  Backbone.noConflict = function() {
    root.Backbone = previousBackbone;
    return this;
  };

  // Turn on `emulateHTTP` to support legacy HTTP servers. Setting this option
  // will fake `"PUT"` and `"DELETE"` requests via the `_method` parameter and
  // set a `X-Http-Method-Override` header.
  Backbone.emulateHTTP = false;

  // Turn on `emulateJSON` to support legacy servers that can't deal with direct
  // `application/json` requests ... will encode the body as
  // `application/x-www-form-urlencoded` instead and will send the model in a
  // form param named `model`.
  Backbone.emulateJSON = false;

  // Backbone.Events
  // ---------------

  // Regular expression used to split event strings.
  var eventSplitter = /\s+/;

  // Implement fancy features of the Events API such as multiple event
  // names `"change blur"` and jQuery-style event maps `{change: action}`
  // in terms of the existing API.
  var eventsApi = function(obj, action, name, rest) {
    if (!name) return true;
    if (typeof name === 'object') {
      for (var key in name) {
        obj[action].apply(obj, [key, name[key]].concat(rest));
      }
    } else if (eventSplitter.test(name)) {
      var names = name.split(eventSplitter);
      for (var i = 0, l = names.length; i < l; i++) {
        obj[action].apply(obj, [names[i]].concat(rest));
      }
    } else {
      return true;
    }
  };

  // Optimized internal dispatch function for triggering events. Tries to
  // keep the usual cases speedy (most Backbone events have 3 arguments).
  var triggerEvents = function(events, args) {
    var ev, i = -1, l = events.length;
    switch (args.length) {
    case 0: while (++i < l) (ev = events[i]).callback.call(ev.ctx);
    return;
    case 1: while (++i < l) (ev = events[i]).callback.call(ev.ctx, args[0]);
    return;
    case 2: while (++i < l) (ev = events[i]).callback.call(ev.ctx, args[0], args[1]);
    return;
    case 3: while (++i < l) (ev = events[i]).callback.call(ev.ctx, args[0], args[1], args[2]);
    return;
    default: while (++i < l) (ev = events[i]).callback.apply(ev.ctx, args);
    }
  };

  // A module that can be mixed in to *any object* in order to provide it with
  // custom events. You may bind with `on` or remove with `off` callback
  // functions to an event; `trigger`-ing an event fires all callbacks in
  // succession.
  //
  //     var object = {};
  //     _.extend(object, Backbone.Events);
  //     object.on('expand', function(){ alert('expanded'); });
  //     object.trigger('expand');
  //
  var Events = Backbone.Events = {

    // Bind one or more space separated events, or an events map,
    // to a `callback` function. Passing `"all"` will bind the callback to
    // all events fired.
    on: function(name, callback, context) {
      if (!(eventsApi(this, 'on', name, [callback, context]) && callback)) return this;
      this._events || (this._events = {});
      var list = this._events[name] || (this._events[name] = []);
      list.push({callback: callback, context: context, ctx: context || this});
      return this;
    },

    // Bind events to only be triggered a single time. After the first time
    // the callback is invoked, it will be removed.
    once: function(name, callback, context) {
      if (!(eventsApi(this, 'once', name, [callback, context]) && callback)) return this;
      var self = this;
      var once = _.once(function() {
        self.off(name, once);
        callback.apply(this, arguments);
      });
      once._callback = callback;
      this.on(name, once, context);
      return this;
    },

    // Remove one or many callbacks. If `context` is null, removes all
    // callbacks with that function. If `callback` is null, removes all
    // callbacks for the event. If `name` is null, removes all bound
    // callbacks for all events.
    off: function(name, callback, context) {
      var list, ev, events, names, i, l, j, k;
      if (!this._events || !eventsApi(this, 'off', name, [callback, context])) return this;
      if (!name && !callback && !context) {
        this._events = {};
        return this;
      }

      names = name ? [name] : _.keys(this._events);
      for (i = 0, l = names.length; i < l; i++) {
        name = names[i];
        if (list = this._events[name]) {
          events = [];
          if (callback || context) {
            for (j = 0, k = list.length; j < k; j++) {
              ev = list[j];
              if ((callback && callback !== ev.callback &&
                               callback !== ev.callback._callback) ||
                  (context && context !== ev.context)) {
                events.push(ev);
              }
            }
          }
          this._events[name] = events;
        }
      }

      return this;
    },

    // Trigger one or many events, firing all bound callbacks. Callbacks are
    // passed the same arguments as `trigger` is, apart from the event name
    // (unless you're listening on `"all"`, which will cause your callback to
    // receive the true name of the event as the first argument).
    trigger: function(name) {
      if (!this._events) return this;
      var args = slice.call(arguments, 1);
      if (!eventsApi(this, 'trigger', name, args)) return this;
      var events = this._events[name];
      var allEvents = this._events.all;
      if (events) triggerEvents(events, args);
      if (allEvents) triggerEvents(allEvents, arguments);
      return this;
    },

    // An inversion-of-control version of `on`. Tell *this* object to listen to
    // an event in another object ... keeping track of what it's listening to.
    listenTo: function(obj, name, callback) {
      var listeners = this._listeners || (this._listeners = {});
      var id = obj._listenerId || (obj._listenerId = _.uniqueId('l'));
      listeners[id] = obj;
      obj.on(name, typeof name === 'object' ? this : callback, this);
      return this;
    },

    // Tell this object to stop listening to either specific events ... or
    // to every object it's currently listening to.
    stopListening: function(obj, name, callback) {
      var listeners = this._listeners;
      if (!listeners) return;
      if (obj) {
        obj.off(name, typeof name === 'object' ? this : callback, this);
        if (!name && !callback) delete listeners[obj._listenerId];
      } else {
        if (typeof name === 'object') callback = this;
        for (var id in listeners) {
          listeners[id].off(name, callback, this);
        }
        this._listeners = {};
      }
      return this;
    }
  };

  // Aliases for backwards compatibility.
  Events.bind   = Events.on;
  Events.unbind = Events.off;

  // Allow the `Backbone` object to serve as a global event bus, for folks who
  // want global "pubsub" in a convenient place.
  _.extend(Backbone, Events);

  // Backbone.Model
  // --------------

  // Create a new model, with defined attributes. A client id (`cid`)
  // is automatically generated and assigned for you.
  var Model = Backbone.Model = function(attributes, options) {
    var defaults;
    var attrs = attributes || {};
    this.cid = _.uniqueId('c');
    this.attributes = {};
    if (options && options.collection) this.collection = options.collection;
    if (options && options.parse) attrs = this.parse(attrs, options) || {};
    if (defaults = _.result(this, 'defaults')) {
      attrs = _.defaults({}, attrs, defaults);
    }
    this.set(attrs, options);
    this.changed = {};
    this.initialize.apply(this, arguments);
  };

  // Attach all inheritable methods to the Model prototype.
  _.extend(Model.prototype, Events, {

    // A hash of attributes whose current and previous value differ.
    changed: null,

    // The default name for the JSON `id` attribute is `"id"`. MongoDB and
    // CouchDB users may want to set this to `"_id"`.
    idAttribute: 'id',

    // Initialize is an empty function by default. Override it with your own
    // initialization logic.
    initialize: function(){},

    // Return a copy of the model's `attributes` object.
    toJSON: function(options) {
      return _.clone(this.attributes);
    },

    // Proxy `Backbone.sync` by default.
    sync: function() {
      return Backbone.sync.apply(this, arguments);
    },

    // Get the value of an attribute.
    get: function(attr) {
      return this.attributes[attr];
    },

    // Get the HTML-escaped value of an attribute.
    escape: function(attr) {
      return _.escape(this.get(attr));
    },

    // Returns `true` if the attribute contains a value that is not null
    // or undefined.
    has: function(attr) {
      return this.get(attr) != null;
    },

    // ----------------------------------------------------------------------

    // Set a hash of model attributes on the object, firing `"change"` unless
    // you choose to silence it.
    set: function(key, val, options) {
      var attr, attrs, unset, changes, silent, changing, prev, current;
      if (key == null) return this;

      // Handle both `"key", value` and `{key: value}` -style arguments.
      if (typeof key === 'object') {
        attrs = key;
        options = val;
      } else {
        (attrs = {})[key] = val;
      }

      options || (options = {});

      // Run validation.
      if (!this._validate(attrs, options)) return false;

      // Extract attributes and options.
      unset           = options.unset;
      silent          = options.silent;
      changes         = [];
      changing        = this._changing;
      this._changing  = true;

      if (!changing) {
        this._previousAttributes = _.clone(this.attributes);
        this.changed = {};
      }
      current = this.attributes, prev = this._previousAttributes;

      // Check for changes of `id`.
      if (this.idAttribute in attrs) this.id = attrs[this.idAttribute];

      // For each `set` attribute, update or delete the current value.
      for (attr in attrs) {
        val = attrs[attr];
        if (!_.isEqual(current[attr], val)) changes.push(attr);
        if (!_.isEqual(prev[attr], val)) {
          this.changed[attr] = val;
        } else {
          delete this.changed[attr];
        }
        unset ? delete current[attr] : current[attr] = val;
      }

      // Trigger all relevant attribute changes.
      if (!silent) {
        if (changes.length) this._pending = true;
        for (var i = 0, l = changes.length; i < l; i++) {
          this.trigger('change:' + changes[i], this, current[changes[i]], options);
        }
      }

      if (changing) return this;
      if (!silent) {
        while (this._pending) {
          this._pending = false;
          this.trigger('change', this, options);
        }
      }
      this._pending = false;
      this._changing = false;
      return this;
    },

    // Remove an attribute from the model, firing `"change"` unless you choose
    // to silence it. `unset` is a noop if the attribute doesn't exist.
    unset: function(attr, options) {
      return this.set(attr, void 0, _.extend({}, options, {unset: true}));
    },

    // Clear all attributes on the model, firing `"change"` unless you choose
    // to silence it.
    clear: function(options) {
      var attrs = {};
      for (var key in this.attributes) attrs[key] = void 0;
      return this.set(attrs, _.extend({}, options, {unset: true}));
    },

    // Determine if the model has changed since the last `"change"` event.
    // If you specify an attribute name, determine if that attribute has changed.
    hasChanged: function(attr) {
      if (attr == null) return !_.isEmpty(this.changed);
      return _.has(this.changed, attr);
    },

    // Return an object containing all the attributes that have changed, or
    // false if there are no changed attributes. Useful for determining what
    // parts of a view need to be updated and/or what attributes need to be
    // persisted to the server. Unset attributes will be set to undefined.
    // You can also pass an attributes object to diff against the model,
    // determining if there *would be* a change.
    changedAttributes: function(diff) {
      if (!diff) return this.hasChanged() ? _.clone(this.changed) : false;
      var val, changed = false;
      var old = this._changing ? this._previousAttributes : this.attributes;
      for (var attr in diff) {
        if (_.isEqual(old[attr], (val = diff[attr]))) continue;
        (changed || (changed = {}))[attr] = val;
      }
      return changed;
    },

    // Get the previous value of an attribute, recorded at the time the last
    // `"change"` event was fired.
    previous: function(attr) {
      if (attr == null || !this._previousAttributes) return null;
      return this._previousAttributes[attr];
    },

    // Get all of the attributes of the model at the time of the previous
    // `"change"` event.
    previousAttributes: function() {
      return _.clone(this._previousAttributes);
    },

    // ---------------------------------------------------------------------

    // Fetch the model from the server. If the server's representation of the
    // model differs from its current attributes, they will be overriden,
    // triggering a `"change"` event.
    fetch: function(options) {
      options = options ? _.clone(options) : {};
      if (options.parse === void 0) options.parse = true;
      var success = options.success;
      options.success = function(model, resp, options) {
        if (!model.set(model.parse(resp, options), options)) return false;
        if (success) success(model, resp, options);
      };
      return this.sync('read', this, options);
    },

    // Set a hash of model attributes, and sync the model to the server.
    // If the server returns an attributes hash that differs, the model's
    // state will be `set` again.
    save: function(key, val, options) {
      var attrs, success, method, xhr, attributes = this.attributes;

      // Handle both `"key", value` and `{key: value}` -style arguments.
      if (key == null || typeof key === 'object') {
        attrs = key;
        options = val;
      } else {
        (attrs = {})[key] = val;
      }

      // If we're not waiting and attributes exist, save acts as `set(attr).save(null, opts)`.
      if (attrs && (!options || !options.wait) && !this.set(attrs, options)) return false;

      options = _.extend({validate: true}, options);

      // Do not persist invalid models.
      if (!this._validate(attrs, options)) return false;

      // Set temporary attributes if `{wait: true}`.
      if (attrs && options.wait) {
        this.attributes = _.extend({}, attributes, attrs);
      }

      // After a successful server-side save, the client is (optionally)
      // updated with the server-side state.
      if (options.parse === void 0) options.parse = true;
      success = options.success;
      options.success = function(model, resp, options) {
        // Ensure attributes are restored during synchronous saves.
        model.attributes = attributes;
        var serverAttrs = model.parse(resp, options);
        if (options.wait) serverAttrs = _.extend(attrs || {}, serverAttrs);
        if (_.isObject(serverAttrs) && !model.set(serverAttrs, options)) {
          return false;
        }
        if (success) success(model, resp, options);
      };

      // Finish configuring and sending the Ajax request.
      method = this.isNew() ? 'create' : (options.patch ? 'patch' : 'update');
      if (method === 'patch') options.attrs = attrs;
      xhr = this.sync(method, this, options);

      // Restore attributes.
      if (attrs && options.wait) this.attributes = attributes;

      return xhr;
    },

    // Destroy this model on the server if it was already persisted.
    // Optimistically removes the model from its collection, if it has one.
    // If `wait: true` is passed, waits for the server to respond before removal.
    destroy: function(options) {
      options = options ? _.clone(options) : {};
      var model = this;
      var success = options.success;

      var destroy = function() {
        model.trigger('destroy', model, model.collection, options);
      };

      options.success = function(model, resp, options) {
        if (options.wait || model.isNew()) destroy();
        if (success) success(model, resp, options);
      };

      if (this.isNew()) {
        options.success(this, null, options);
        return false;
      }

      var xhr = this.sync('delete', this, options);
      if (!options.wait) destroy();
      return xhr;
    },

    // Default URL for the model's representation on the server -- if you're
    // using Backbone's restful methods, override this to change the endpoint
    // that will be called.
    url: function() {
      var base = _.result(this, 'urlRoot') || _.result(this.collection, 'url') || urlError();
      if (this.isNew()) return base;
      return base + (base.charAt(base.length - 1) === '/' ? '' : '/') + encodeURIComponent(this.id);
    },

    // **parse** converts a response into the hash of attributes to be `set` on
    // the model. The default implementation is just to pass the response along.
    parse: function(resp, options) {
      return resp;
    },

    // Create a new model with identical attributes to this one.
    clone: function() {
      return new this.constructor(this.attributes);
    },

    // A model is new if it has never been saved to the server, and lacks an id.
    isNew: function() {
      return this.id == null;
    },

    // Check if the model is currently in a valid state.
    isValid: function(options) {
      return !this.validate || !this.validate(this.attributes, options);
    },

    // Run validation against the next complete set of model attributes,
    // returning `true` if all is well. Otherwise, fire a general
    // `"error"` event and call the error callback, if specified.
    _validate: function(attrs, options) {
      if (!options.validate || !this.validate) return true;
      attrs = _.extend({}, this.attributes, attrs);
      var error = this.validationError = this.validate(attrs, options) || null;
      if (!error) return true;
      this.trigger('invalid', this, error, options || {});
      return false;
    }

  });

  // Backbone.Collection
  // -------------------

  // Provides a standard collection class for our sets of models, ordered
  // or unordered. If a `comparator` is specified, the Collection will maintain
  // its models in sort order, as they're added and removed.
  var Collection = Backbone.Collection = function(models, options) {
    options || (options = {});
    if (options.model) this.model = options.model;
    if (options.comparator !== void 0) this.comparator = options.comparator;
    this.models = [];
    this._reset();
    this.initialize.apply(this, arguments);
    if (models) this.reset(models, _.extend({silent: true}, options));
  };

  // Define the Collection's inheritable methods.
  _.extend(Collection.prototype, Events, {

    // The default model for a collection is just a **Backbone.Model**.
    // This should be overridden in most cases.
    model: Model,

    // Initialize is an empty function by default. Override it with your own
    // initialization logic.
    initialize: function(){},

    // The JSON representation of a Collection is an array of the
    // models' attributes.
    toJSON: function(options) {
      return this.map(function(model){ return model.toJSON(options); });
    },

    // Proxy `Backbone.sync` by default.
    sync: function() {
      return Backbone.sync.apply(this, arguments);
    },

    // Add a model, or list of models to the set.
    add: function(models, options) {
      models = _.isArray(models) ? models.slice() : [models];
      options || (options = {});
      var i, l, model, attrs, existing, doSort, add, at, sort, sortAttr;
      add = [];
      at = options.at;
      sort = this.comparator && (at == null) && options.sort != false;
      sortAttr = _.isString(this.comparator) ? this.comparator : null;

      // Turn bare objects into model references, and prevent invalid models
      // from being added.
      for (i = 0, l = models.length; i < l; i++) {
        if (!(model = this._prepareModel(attrs = models[i], options))) {
          this.trigger('invalid', this, attrs, options);
          continue;
        }

        // If a duplicate is found, prevent it from being added and
        // optionally merge it into the existing model.
        if (existing = this.get(model)) {
          if (options.merge) {
            existing.set(attrs === model ? model.attributes : attrs, options);
            if (sort && !doSort && existing.hasChanged(sortAttr)) doSort = true;
          }
          continue;
        }

        // This is a new model, push it to the `add` list.
        add.push(model);

        // Listen to added models' events, and index models for lookup by
        // `id` and by `cid`.
        model.on('all', this._onModelEvent, this);
        this._byId[model.cid] = model;
        if (model.id != null) this._byId[model.id] = model;
      }

      // See if sorting is needed, update `length` and splice in new models.
      if (add.length) {
        if (sort) doSort = true;
        this.length += add.length;
        if (at != null) {
          splice.apply(this.models, [at, 0].concat(add));
        } else {
          push.apply(this.models, add);
        }
      }

      // Silently sort the collection if appropriate.
      if (doSort) this.sort({silent: true});

      if (options.silent) return this;

      // Trigger `add` events.
      for (i = 0, l = add.length; i < l; i++) {
        (model = add[i]).trigger('add', model, this, options);
      }

      // Trigger `sort` if the collection was sorted.
      if (doSort) this.trigger('sort', this, options);

      return this;
    },

    // Remove a model, or a list of models from the set.
    remove: function(models, options) {
      models = _.isArray(models) ? models.slice() : [models];
      options || (options = {});
      var i, l, index, model;
      for (i = 0, l = models.length; i < l; i++) {
        model = this.get(models[i]);
        if (!model) continue;
        delete this._byId[model.id];
        delete this._byId[model.cid];
        index = this.indexOf(model);
        this.models.splice(index, 1);
        this.length--;
        if (!options.silent) {
          options.index = index;
          model.trigger('remove', model, this, options);
        }
        this._removeReference(model);
      }
      return this;
    },

    // Add a model to the end of the collection.
    push: function(model, options) {
      model = this._prepareModel(model, options);
      this.add(model, _.extend({at: this.length}, options));
      return model;
    },

    // Remove a model from the end of the collection.
    pop: function(options) {
      var model = this.at(this.length - 1);
      this.remove(model, options);
      return model;
    },

    // Add a model to the beginning of the collection.
    unshift: function(model, options) {
      model = this._prepareModel(model, options);
      this.add(model, _.extend({at: 0}, options));
      return model;
    },

    // Remove a model from the beginning of the collection.
    shift: function(options) {
      var model = this.at(0);
      this.remove(model, options);
      return model;
    },

    // Slice out a sub-array of models from the collection.
    slice: function(begin, end) {
      return this.models.slice(begin, end);
    },

    // Get a model from the set by id.
    get: function(obj) {
      if (obj == null) return void 0;
      this._idAttr || (this._idAttr = this.model.prototype.idAttribute);
      return this._byId[obj.id || obj.cid || obj[this._idAttr] || obj];
    },

    // Get the model at the given index.
    at: function(index) {
      return this.models[index];
    },

    // Return models with matching attributes. Useful for simple cases of `filter`.
    where: function(attrs) {
      if (_.isEmpty(attrs)) return [];
      return this.filter(function(model) {
        for (var key in attrs) {
          if (attrs[key] !== model.get(key)) return false;
        }
        return true;
      });
    },

    // Force the collection to re-sort itself. You don't need to call this under
    // normal circumstances, as the set will maintain sort order as each item
    // is added.
    sort: function(options) {
      if (!this.comparator) {
        throw new Error('Cannot sort a set without a comparator');
      }
      options || (options = {});

      // Run sort based on type of `comparator`.
      if (_.isString(this.comparator) || this.comparator.length === 1) {
        this.models = this.sortBy(this.comparator, this);
      } else {
        this.models.sort(_.bind(this.comparator, this));
      }

      if (!options.silent) this.trigger('sort', this, options);
      return this;
    },

    // Pluck an attribute from each model in the collection.
    pluck: function(attr) {
      return _.invoke(this.models, 'get', attr);
    },

    // Smartly update a collection with a change set of models, adding,
    // removing, and merging as necessary.
    update: function(models, options) {
      options = _.extend({add: true, merge: true, remove: true}, options);
      if (options.parse) models = this.parse(models, options);
      var model, i, l, existing;
      var add = [], remove = [], modelMap = {};

      // Allow a single model (or no argument) to be passed.
      if (!_.isArray(models)) models = models ? [models] : [];

      // Proxy to `add` for this case, no need to iterate...
      if (options.add && !options.remove) return this.add(models, options);

      // Determine which models to add and merge, and which to remove.
      for (i = 0, l = models.length; i < l; i++) {
        model = models[i];
        existing = this.get(model);
        if (options.remove && existing) modelMap[existing.cid] = true;
        if ((options.add && !existing) || (options.merge && existing)) {
          add.push(model);
        }
      }
      if (options.remove) {
        for (i = 0, l = this.models.length; i < l; i++) {
          model = this.models[i];
          if (!modelMap[model.cid]) remove.push(model);
        }
      }

      // Remove models (if applicable) before we add and merge the rest.
      if (remove.length) this.remove(remove, options);
      if (add.length) this.add(add, options);
      return this;
    },

    // When you have more items than you want to add or remove individually,
    // you can reset the entire set with a new list of models, without firing
    // any `add` or `remove` events. Fires `reset` when finished.
    reset: function(models, options) {
      options || (options = {});
      if (options.parse) models = this.parse(models, options);
      for (var i = 0, l = this.models.length; i < l; i++) {
        this._removeReference(this.models[i]);
      }
      options.previousModels = this.models.slice();
      this._reset();
      if (models) this.add(models, _.extend({silent: true}, options));
      if (!options.silent) this.trigger('reset', this, options);
      return this;
    },

    // Fetch the default set of models for this collection, resetting the
    // collection when they arrive. If `update: true` is passed, the response
    // data will be passed through the `update` method instead of `reset`.
    fetch: function(options) {
      options = options ? _.clone(options) : {};
      if (options.parse === void 0) options.parse = true;
      var success = options.success;
      options.success = function(collection, resp, options) {
        var method = options.update ? 'update' : 'reset';
        collection[method](resp, options);
        if (success) success(collection, resp, options);
      };
      return this.sync('read', this, options);
    },

    // Create a new instance of a model in this collection. Add the model to the
    // collection immediately, unless `wait: true` is passed, in which case we
    // wait for the server to agree.
    create: function(model, options) {
      options = options ? _.clone(options) : {};
      if (!(model = this._prepareModel(model, options))) return false;
      if (!options.wait) this.add(model, options);
      var collection = this;
      var success = options.success;
      options.success = function(model, resp, options) {
        if (options.wait) collection.add(model, options);
        if (success) success(model, resp, options);
      };
      model.save(null, options);
      return model;
    },

    // **parse** converts a response into a list of models to be added to the
    // collection. The default implementation is just to pass it through.
    parse: function(resp, options) {
      return resp;
    },

    // Create a new collection with an identical list of models as this one.
    clone: function() {
      return new this.constructor(this.models);
    },

    // Reset all internal state. Called when the collection is reset.
    _reset: function() {
      this.length = 0;
      this.models.length = 0;
      this._byId  = {};
    },

    // Prepare a model or hash of attributes to be added to this collection.
    _prepareModel: function(attrs, options) {
      if (attrs instanceof Model) {
        if (!attrs.collection) attrs.collection = this;
        return attrs;
      }
      options || (options = {});
      options.collection = this;
      var model = new this.model(attrs, options);
      if (!model._validate(attrs, options)) return false;
      return model;
    },

    // Internal method to remove a model's ties to a collection.
    _removeReference: function(model) {
      if (this === model.collection) delete model.collection;
      model.off('all', this._onModelEvent, this);
    },

    // Internal method called every time a model in the set fires an event.
    // Sets need to update their indexes when models change ids. All other
    // events simply proxy through. "add" and "remove" events that originate
    // in other collections are ignored.
    _onModelEvent: function(event, model, collection, options) {
      if ((event === 'add' || event === 'remove') && collection !== this) return;
      if (event === 'destroy') this.remove(model, options);
      if (model && event === 'change:' + model.idAttribute) {
        delete this._byId[model.previous(model.idAttribute)];
        if (model.id != null) this._byId[model.id] = model;
      }
      this.trigger.apply(this, arguments);
    },

    sortedIndex: function (model, value, context) {
      value || (value = this.comparator);
      var iterator = _.isFunction(value) ? value : function(model) {
        return model.get(value);
      };
      return _.sortedIndex(this.models, model, iterator, context);
    }

  });

  // Underscore methods that we want to implement on the Collection.
  var methods = ['forEach', 'each', 'map', 'collect', 'reduce', 'foldl',
    'inject', 'reduceRight', 'foldr', 'find', 'detect', 'filter', 'select',
    'reject', 'every', 'all', 'some', 'any', 'include', 'contains', 'invoke',
    'max', 'min', 'toArray', 'size', 'first', 'head', 'take', 'initial', 'rest',
    'tail', 'drop', 'last', 'without', 'indexOf', 'shuffle', 'lastIndexOf',
    'isEmpty', 'chain'];

  // Mix in each Underscore method as a proxy to `Collection#models`.
  _.each(methods, function(method) {
    Collection.prototype[method] = function() {
      var args = slice.call(arguments);
      args.unshift(this.models);
      return _[method].apply(_, args);
    };
  });

  // Underscore methods that take a property name as an argument.
  var attributeMethods = ['groupBy', 'countBy', 'sortBy'];

  // Use attributes instead of properties.
  _.each(attributeMethods, function(method) {
    Collection.prototype[method] = function(value, context) {
      var iterator = _.isFunction(value) ? value : function(model) {
        return model.get(value);
      };
      return _[method](this.models, iterator, context);
    };
  });

  // Backbone.Router
  // ---------------

  // Routers map faux-URLs to actions, and fire events when routes are
  // matched. Creating a new one sets its `routes` hash, if not set statically.
  var Router = Backbone.Router = function(options) {
    options || (options = {});
    if (options.routes) this.routes = options.routes;
    this._bindRoutes();
    this.initialize.apply(this, arguments);
  };

  // Cached regular expressions for matching named param parts and splatted
  // parts of route strings.
  var optionalParam = /\((.*?)\)/g;
  var namedParam    = /(\(\?)?:\w+/g;
  var splatParam    = /\*\w+/g;
  var escapeRegExp  = /[\-{}\[\]+?.,\\\^$|#\s]/g;

  // Set up all inheritable **Backbone.Router** properties and methods.
  _.extend(Router.prototype, Events, {

    // Initialize is an empty function by default. Override it with your own
    // initialization logic.
    initialize: function(){},

    // Manually bind a single named route to a callback. For example:
    //
    //     this.route('search/:query/p:num', 'search', function(query, num) {
    //       ...
    //     });
    //
    route: function(route, name, callback) {
      if (!_.isRegExp(route)) route = this._routeToRegExp(route);
      if (!callback) callback = this[name];
      Backbone.history.route(route, _.bind(function(fragment) {
        var args = this._extractParameters(route, fragment);
        callback && callback.apply(this, args);
        this.trigger.apply(this, ['route:' + name].concat(args));
        this.trigger('route', name, args);
        Backbone.history.trigger('route', this, name, args);
      }, this));
      return this;
    },

    // Simple proxy to `Backbone.history` to save a fragment into the history.
    navigate: function(fragment, options) {
      Backbone.history.navigate(fragment, options);
      return this;
    },

    // Bind all defined routes to `Backbone.history`. We have to reverse the
    // order of the routes here to support behavior where the most general
    // routes can be defined at the bottom of the route map.
    _bindRoutes: function() {
      if (!this.routes) return;
      var route, routes = _.keys(this.routes);
      while ((route = routes.pop()) != null) {
        this.route(route, this.routes[route]);
      }
    },

    // Convert a route string into a regular expression, suitable for matching
    // against the current location hash.
    _routeToRegExp: function(route) {
      route = route.replace(escapeRegExp, '\\$&')
                   .replace(optionalParam, '(?:$1)?')
                   .replace(namedParam, function(match, optional){
                     return optional ? match : '([^\/]+)';
                   })
                   .replace(splatParam, '(.*?)');
      return new RegExp('^' + route + '$');
    },

    // Given a route, and a URL fragment that it matches, return the array of
    // extracted parameters.
    _extractParameters: function(route, fragment) {
      return route.exec(fragment).slice(1);
    }

  });

  // Backbone.History
  // ----------------

  // Handles cross-browser history management, based on URL fragments. If the
  // browser does not support `onhashchange`, falls back to polling.
  var History = Backbone.History = function() {
    this.handlers = [];
    _.bindAll(this, 'checkUrl');

    // Ensure that `History` can be used outside of the browser.
    if (typeof window !== 'undefined') {
      this.location = window.location;
      this.history = window.history;
    }
  };

  // Cached regex for stripping a leading hash/slash and trailing space.
  var routeStripper = /^[#\/]|\s+$/g;

  // Cached regex for stripping leading and trailing slashes.
  var rootStripper = /^\/+|\/+$/g;

  // Cached regex for detecting MSIE.
  var isExplorer = /msie [\w.]+/;

  // Cached regex for removing a trailing slash.
  var trailingSlash = /\/$/;

  // Has the history handling already been started?
  History.started = false;

  // Set up all inheritable **Backbone.History** properties and methods.
  _.extend(History.prototype, Events, {

    // The default interval to poll for hash changes, if necessary, is
    // twenty times a second.
    interval: 50,

    // Gets the true hash value. Cannot use location.hash directly due to bug
    // in Firefox where location.hash will always be decoded.
    getHash: function(window) {
      var match = (window || this).location.href.match(/#(.*)$/);
      return match ? match[1] : '';
    },

    // Get the cross-browser normalized URL fragment, either from the URL,
    // the hash, or the override.
    getFragment: function(fragment, forcePushState) {
      if (fragment == null) {
        if (this._hasPushState || !this._wantsHashChange || forcePushState) {
          fragment = this.location.pathname;
          var root = this.root.replace(trailingSlash, '');
          if (!fragment.indexOf(root)) fragment = fragment.substr(root.length);
        } else {
          fragment = this.getHash();
        }
      }
      return fragment.replace(routeStripper, '');
    },

    // Start the hash change handling, returning `true` if the current URL matches
    // an existing route, and `false` otherwise.
    start: function(options) {
      if (History.started) throw new Error("Backbone.history has already been started");
      History.started = true;

      // Figure out the initial configuration. Do we need an iframe?
      // Is pushState desired ... is it available?
      this.options          = _.extend({}, {root: '/'}, this.options, options);
      this.root             = this.options.root;
      this._wantsHashChange = this.options.hashChange !== false;
      this._wantsPushState  = !!this.options.pushState;
      this._hasPushState    = !!(this.options.pushState && this.history && this.history.pushState);
      var fragment          = this.getFragment();
      var docMode           = document.documentMode;
      var oldIE             = (isExplorer.exec(navigator.userAgent.toLowerCase()) && (!docMode || docMode <= 7));

      // Normalize root to always include a leading and trailing slash.
      this.root = ('/' + this.root + '/').replace(rootStripper, '/');

      if (oldIE && this._wantsHashChange) {
        this.iframe = Backbone.$('<iframe src="javascript:0" tabindex="-1" />').hide().appendTo('body')[0].contentWindow;
        this.navigate(fragment);
      }

      // Depending on whether we're using pushState or hashes, and whether
      // 'onhashchange' is supported, determine how we check the URL state.
      if (this._hasPushState) {
        Backbone.$(window).on('popstate', this.checkUrl);
      } else if (this._wantsHashChange && ('onhashchange' in window) && !oldIE) {
        Backbone.$(window).on('hashchange', this.checkUrl);
      } else if (this._wantsHashChange) {
        this._checkUrlInterval = setInterval(this.checkUrl, this.interval);
      }

      // Determine if we need to change the base url, for a pushState link
      // opened by a non-pushState browser.
      this.fragment = fragment;
      var loc = this.location;
      var atRoot = loc.pathname.replace(/[^\/]$/, '$&/') === this.root;

      // If we've started off with a route from a `pushState`-enabled browser,
      // but we're currently in a browser that doesn't support it...
      if (this._wantsHashChange && this._wantsPushState && !this._hasPushState && !atRoot) {
        this.fragment = this.getFragment(null, true);
        this.location.replace(this.root + this.location.search + '#' + this.fragment);
        // Return immediately as browser will do redirect to new url
        return true;

      // Or if we've started out with a hash-based route, but we're currently
      // in a browser where it could be `pushState`-based instead...
      } else if (this._wantsPushState && this._hasPushState && atRoot && loc.hash) {
        this.fragment = this.getHash().replace(routeStripper, '');
        this.history.replaceState({}, document.title, this.root + this.fragment + loc.search);
      }

      if (!this.options.silent) return this.loadUrl();
    },

    // Disable Backbone.history, perhaps temporarily. Not useful in a real app,
    // but possibly useful for unit testing Routers.
    stop: function() {
      Backbone.$(window).off('popstate', this.checkUrl).off('hashchange', this.checkUrl);
      clearInterval(this._checkUrlInterval);
      History.started = false;
    },

    // Add a route to be tested when the fragment changes. Routes added later
    // may override previous routes.
    route: function(route, callback) {
      this.handlers.unshift({route: route, callback: callback});
    },

    // Checks the current URL to see if it has changed, and if it has,
    // calls `loadUrl`, normalizing across the hidden iframe.
    checkUrl: function(e) {
      var current = this.getFragment();
      if (current === this.fragment && this.iframe) {
        current = this.getFragment(this.getHash(this.iframe));
      }
      if (current === this.fragment) return false;
      if (this.iframe) this.navigate(current);
      this.loadUrl() || this.loadUrl(this.getHash());
    },

    // Attempt to load the current URL fragment. If a route succeeds with a
    // match, returns `true`. If no defined routes matches the fragment,
    // returns `false`.
    loadUrl: function(fragmentOverride) {
      var fragment = this.fragment = this.getFragment(fragmentOverride);
      var matched = _.any(this.handlers, function(handler) {
        if (handler.route.test(fragment)) {
          handler.callback(fragment);
          return true;
        }
      });
      return matched;
    },

    // Save a fragment into the hash history, or replace the URL state if the
    // 'replace' option is passed. You are responsible for properly URL-encoding
    // the fragment in advance.
    //
    // The options object can contain `trigger: true` if you wish to have the
    // route callback be fired (not usually desirable), or `replace: true`, if
    // you wish to modify the current URL without adding an entry to the history.
    navigate: function(fragment, options) {
      if (!History.started) return false;
      if (!options || options === true) options = {trigger: options};
      fragment = this.getFragment(fragment || '');
      if (this.fragment === fragment) return;
      this.fragment = fragment;
      var url = this.root + fragment;

      // If pushState is available, we use it to set the fragment as a real URL.
      if (this._hasPushState) {
        this.history[options.replace ? 'replaceState' : 'pushState']({}, document.title, url);

      // If hash changes haven't been explicitly disabled, update the hash
      // fragment to store history.
      } else if (this._wantsHashChange) {
        this._updateHash(this.location, fragment, options.replace);
        if (this.iframe && (fragment !== this.getFragment(this.getHash(this.iframe)))) {
          // Opening and closing the iframe tricks IE7 and earlier to push a
          // history entry on hash-tag change.  When replace is true, we don't
          // want this.
          if(!options.replace) this.iframe.document.open().close();
          this._updateHash(this.iframe.location, fragment, options.replace);
        }

      // If you've told us that you explicitly don't want fallback hashchange-
      // based history, then `navigate` becomes a page refresh.
      } else {
        return this.location.assign(url);
      }
      if (options.trigger) this.loadUrl(fragment);
    },

    // Update the hash location, either replacing the current entry, or adding
    // a new one to the browser history.
    _updateHash: function(location, fragment, replace) {
      if (replace) {
        var href = location.href.replace(/(javascript:|#).*$/, '');
        location.replace(href + '#' + fragment);
      } else {
        // Some browsers require that `hash` contains a leading #.
        location.hash = '#' + fragment;
      }
    }

  });

  // Create the default Backbone.history.
  Backbone.history = new History;

  // Backbone.View
  // -------------

  // Creating a Backbone.View creates its initial element outside of the DOM,
  // if an existing element is not provided...
  var View = Backbone.View = function(options) {
    this.cid = _.uniqueId('view');
    this._configure(options || {});
    this._ensureElement();
    this.initialize.apply(this, arguments);
    this.delegateEvents();
  };

  // Cached regex to split keys for `delegate`.
  var delegateEventSplitter = /^(\S+)\s*(.*)$/;

  // List of view options to be merged as properties.
  var viewOptions = ['model', 'collection', 'el', 'id', 'attributes', 'className', 'tagName', 'events'];

  // Set up all inheritable **Backbone.View** properties and methods.
  _.extend(View.prototype, Events, {

    // The default `tagName` of a View's element is `"div"`.
    tagName: 'div',

    // jQuery delegate for element lookup, scoped to DOM elements within the
    // current view. This should be prefered to global lookups where possible.
    $: function(selector) {
      return this.$el.find(selector);
    },

    // Initialize is an empty function by default. Override it with your own
    // initialization logic.
    initialize: function(){},

    // **render** is the core function that your view should override, in order
    // to populate its element (`this.el`), with the appropriate HTML. The
    // convention is for **render** to always return `this`.
    render: function() {
      return this;
    },

    // Remove this view by taking the element out of the DOM, and removing any
    // applicable Backbone.Events listeners.
    remove: function() {
      this.$el.remove();
      this.stopListening();
      return this;
    },

    // Change the view's element (`this.el` property), including event
    // re-delegation.
    setElement: function(element, delegate) {
      if (this.$el) this.undelegateEvents();
      this.$el = element instanceof Backbone.$ ? element : Backbone.$(element);
      this.el = this.$el[0];
      if (delegate !== false) this.delegateEvents();
      return this;
    },

    // Set callbacks, where `this.events` is a hash of
    //
    // *{"event selector": "callback"}*
    //
    //     {
    //       'mousedown .title':  'edit',
    //       'click .button':     'save'
    //       'click .open':       function(e) { ... }
    //     }
    //
    // pairs. Callbacks will be bound to the view, with `this` set properly.
    // Uses event delegation for efficiency.
    // Omitting the selector binds the event to `this.el`.
    // This only works for delegate-able events: not `focus`, `blur`, and
    // not `change`, `submit`, and `reset` in Internet Explorer.
    delegateEvents: function(events) {
      if (!(events || (events = _.result(this, 'events')))) return;
      this.undelegateEvents();
      for (var key in events) {
        var method = events[key];
        if (!_.isFunction(method)) method = this[events[key]];
        if (!method) throw new Error('Method "' + events[key] + '" does not exist');
        var match = key.match(delegateEventSplitter);
        var eventName = match[1], selector = match[2];
        method = _.bind(method, this);
        eventName += '.delegateEvents' + this.cid;
        if (selector === '') {
          this.$el.on(eventName, method);
        } else {
          this.$el.on(eventName, selector, method);
        }
      }
    },

    // Clears all callbacks previously bound to the view with `delegateEvents`.
    // You usually don't need to use this, but may wish to if you have multiple
    // Backbone views attached to the same DOM element.
    undelegateEvents: function() {
      this.$el.off('.delegateEvents' + this.cid);
    },

    // Performs the initial configuration of a View with a set of options.
    // Keys with special meaning *(model, collection, id, className)*, are
    // attached directly to the view.
    _configure: function(options) {
      if (this.options) options = _.extend({}, _.result(this, 'options'), options);
      _.extend(this, _.pick(options, viewOptions));
      this.options = options;
    },

    // Ensure that the View has a DOM element to render into.
    // If `this.el` is a string, pass it through `$()`, take the first
    // matching element, and re-assign it to `el`. Otherwise, create
    // an element from the `id`, `className` and `tagName` properties.
    _ensureElement: function() {
      if (!this.el) {
        var attrs = _.extend({}, _.result(this, 'attributes'));
        if (this.id) attrs.id = _.result(this, 'id');
        if (this.className) attrs['class'] = _.result(this, 'className');
        var $el = Backbone.$('<' + _.result(this, 'tagName') + '>').attr(attrs);
        this.setElement($el, false);
      } else {
        this.setElement(_.result(this, 'el'), false);
      }
    }

  });

  // Backbone.sync
  // -------------

  // Map from CRUD to HTTP for our default `Backbone.sync` implementation.
  var methodMap = {
    'create': 'POST',
    'update': 'PUT',
    'patch':  'PATCH',
    'delete': 'DELETE',
    'read':   'GET'
  };

  // Override this function to change the manner in which Backbone persists
  // models to the server. You will be passed the type of request, and the
  // model in question. By default, makes a RESTful Ajax request
  // to the model's `url()`. Some possible customizations could be:
  //
  // * Use `setTimeout` to batch rapid-fire updates into a single request.
  // * Send up the models as XML instead of JSON.
  // * Persist models via WebSockets instead of Ajax.
  //
  // Turn on `Backbone.emulateHTTP` in order to send `PUT` and `DELETE` requests
  // as `POST`, with a `_method` parameter containing the true HTTP method,
  // as well as all requests with the body as `application/x-www-form-urlencoded`
  // instead of `application/json` with the model in a param named `model`.
  // Useful when interfacing with server-side languages like **PHP** that make
  // it difficult to read the body of `PUT` requests.
  Backbone.sync = function(method, model, options) {
    var type = methodMap[method];

    // Default options, unless specified.
    _.defaults(options || (options = {}), {
      emulateHTTP: Backbone.emulateHTTP,
      emulateJSON: Backbone.emulateJSON
    });

    // Default JSON-request options.
    var params = {type: type, dataType: 'json'};

    // Ensure that we have a URL.
    if (!options.url) {
      params.url = _.result(model, 'url') || urlError();
    }

    // Ensure that we have the appropriate request data.
    if (options.data == null && model && (method === 'create' || method === 'update' || method === 'patch')) {
      params.contentType = 'application/json';
      params.data = JSON.stringify(options.attrs || model.toJSON(options));
    }

    // For older servers, emulate JSON by encoding the request into an HTML-form.
    if (options.emulateJSON) {
      params.contentType = 'application/x-www-form-urlencoded';
      params.data = params.data ? {model: params.data} : {};
    }

    // For older servers, emulate HTTP by mimicking the HTTP method with `_method`
    // And an `X-HTTP-Method-Override` header.
    if (options.emulateHTTP && (type === 'PUT' || type === 'DELETE' || type === 'PATCH')) {
      params.type = 'POST';
      if (options.emulateJSON) params.data._method = type;
      var beforeSend = options.beforeSend;
      options.beforeSend = function(xhr) {
        xhr.setRequestHeader('X-HTTP-Method-Override', type);
        if (beforeSend) return beforeSend.apply(this, arguments);
      };
    }

    // Don't process data on a non-GET request.
    if (params.type !== 'GET' && !options.emulateJSON) {
      params.processData = false;
    }

    var success = options.success;
    options.success = function(resp) {
      if (success) success(model, resp, options);
      model.trigger('sync', model, resp, options);
    };

    var error = options.error;
    options.error = function(xhr) {
      if (error) error(model, xhr, options);
      model.trigger('error', model, xhr, options);
    };

    // Make the request, allowing the user to override any Ajax options.
    var xhr = options.xhr = Backbone.ajax(_.extend(params, options));
    model.trigger('request', model, xhr, options);
    return xhr;
  };

  // Set the default implementation of `Backbone.ajax` to proxy through to `$`.
  Backbone.ajax = function() {
    return Backbone.$.ajax.apply(Backbone.$, arguments);
  };

  // Helpers
  // -------

  // Helper function to correctly set up the prototype chain, for subclasses.
  // Similar to `goog.inherits`, but uses a hash of prototype properties and
  // class properties to be extended.
  var extend = function(protoProps, staticProps) {
    var parent = this;
    var child;

    // The constructor function for the new subclass is either defined by you
    // (the "constructor" property in your `extend` definition), or defaulted
    // by us to simply call the parent's constructor.
    if (protoProps && _.has(protoProps, 'constructor')) {
      child = protoProps.constructor;
    } else {
      child = function(){ return parent.apply(this, arguments); };
    }

    // Add static properties to the constructor function, if supplied.
    _.extend(child, parent, staticProps);

    // Set the prototype chain to inherit from `parent`, without calling
    // `parent`'s constructor function.
    var Surrogate = function(){ this.constructor = child; };
    Surrogate.prototype = parent.prototype;
    child.prototype = new Surrogate;

    // Add prototype properties (instance properties) to the subclass,
    // if supplied.
    if (protoProps) _.extend(child.prototype, protoProps);

    // Set a convenience property in case the parent's prototype is needed
    // later.
    child.__super__ = parent.prototype;

    return child;
  };

  // Set up inheritance for the model, collection, router, view and history.
  Model.extend = Collection.extend = Router.extend = View.extend = History.extend = extend;

  // Throw an error when a URL is needed, and none is supplied.
  var urlError = function() {
    throw new Error('A "url" property or function must be specified');
  };

}).call(this);/*
THIS SOFTWARE IS PROVIDED BY ANDREW M. TRICE ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ANDREW M. TRICE OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// WARNING: commented out because it breaks native scrolling
//document.addEventListener('touchmove', function (e) { e.preventDefault(); }, false);

!function () {
var SlidingView = function( sidebarId, bodyId ) {

	//window.slidingView = this;

	this.gestureStarted = false;
	this.bodyOffset = 0;

	this.sidebarWidth = 175;

	this.sidebar = $("#"+sidebarId);
	this.body = $("#"+bodyId);

	this.sidebar.addClass( "slidingview_sidebar" );
	this.body.addClass( "slidingview_body" );

	var self = this;
	$(window).resize( function(event){ self.resizeContent() } );
	$(this.parent).resize( function(event){ self.resizeContent() } );

	if ( "onorientationchange" in window ) {
		$(window).bind( "onorientationchange", function(event){ self.resizeContent() } )
	}
	this.resizeContent();
	this.setupEventHandlers();
}

SlidingView.prototype.setupEventHandlers = function() {

	this.touchSupported =  ('ontouchstart' in window);

	this.START_EVENT = this.touchSupported ? 'touchstart' : 'mousedown';
	this.MOVE_EVENT = this.touchSupported ? 'touchmove' : 'mousemove';
	this.END_EVENT = this.touchSupported ? 'touchend' : 'mouseup';

	var self = this;
	var func = function( event ){ self.onTouchStart(event), true };
	var body = this.body.get()[0];
	body.addEventListener( this.START_EVENT, func, false );
}

SlidingView.prototype.onTouchStart = function(event) {
	// console.log( event.type );

	this.gestureStartPosition = this.getTouchCoordinates( event );

	var self = this;
	this.touchMoveHandler = function( event ){ self.onTouchMove(event) };
	this.touchUpHandler = function( event ){ self.onTouchEnd(event) };

	this.body.get()[0].addEventListener( this.MOVE_EVENT, this.touchMoveHandler, false );
	this.body.get()[0].addEventListener( this.END_EVENT, this.touchUpHandler, false );
	this.body.stop();
}

SlidingView.prototype.onTouchMove = function(event) {
	var currentPosition = this.getTouchCoordinates( event );

	if ( this.gestureStarted ) {
		event.preventDefault();
		event.stopPropagation();
		this.updateBasedOnTouchPoints( currentPosition );
		return;
	}

	// calculate offsets to see if scroll direciton is vertical or horizontal
    var xOffset = Math.abs(currentPosition.x - this.gestureStartPosition.x);
    var yOffset = Math.abs(currentPosition.y - this.gestureStartPosition.y);

	// Dragging vertically - ignore this gesture
	if ( yOffset > xOffset ) return this.unbindEvents();

	//dragging horizontally - let's handle this
	this.gestureStarted = true;
	event.preventDefault();
	event.stopPropagation();
	this.updateBasedOnTouchPoints( currentPosition );
	return;
}

SlidingView.prototype.onTouchEnd = function(event) {
	if ( this.gestureStarted ) {
		this.snapToPosition();
	}
	this.gestureStarted = false;
	this.unbindEvents();
}



SlidingView.prototype.updateBasedOnTouchPoints = function( currentPosition ) {

	var deltaX = (currentPosition.x - this.gestureStartPosition.x);
	var targetX = this.bodyOffset + deltaX;

	targetX = Math.max( targetX, 0 );
	targetX = Math.min( targetX, this.sidebarWidth );

	this.bodyOffset = targetX;

	//console.log( targetX );
	//this.body.css("left", targetX );
	//console.log( this.body.css("left") );

	if ( this.body.css("left") != "0px" ) {
		this.body.css("left", "0px" );
	}
	this.body.css("-webkit-transform", "translate3d(" + targetX + "px,0,0)" );
	this.body.css("-moz-transform", "translate3d(" + targetX + "px,0,0)" );
	this.body.css("transform", "translate3d(" + targetX + "px,0,0)" );

	//console.log( this.body.css("-moz-transform"), targetX );


	/*if ( currentPosition != targetX ) {

		this.body.stop(true,false).animate({
				left:targetX,
				avoidTransforms:false,
				useTranslate3d: true
			}, 100);
	}*/

	this.sidebar.trigger( "slidingViewProgress", { current: targetX, max:this.sidebarWidth } );

	this.gestureStartPosition = currentPosition;
}

SlidingView.prototype.snapToPosition = function() {
	//this.body.css("-webkit-transform", "translate3d(0,0,0)" );
	this.body.css("left", "0px" );
	var currentPosition = this.bodyOffset;
	var halfWidth = this.sidebarWidth / 2;
	var targetX;
	if ( currentPosition < halfWidth ) {
		targetX = 0;
	}
	else {
		targetX = this.sidebarWidth;
	}
	this.bodyOffset = targetX;

	//console.log( currentPosition, halfWidth, targetX );
	if ( currentPosition != targetX ) {
		/*this.body.stop(true, false).animate({
				left:targetX,
				avoidTransforms:false,
				useTranslate3d: true
			}, 100);*/
		this.updateCSS(targetX);

	    this.sidebar.trigger( "slidingViewProgress", { current:targetX, max:this.sidebarWidth } );
	}
}

SlidingView.prototype.toggle = function() {
	if (this.isClosed())
		this.open();
	else
		this.close();
}

SlidingView.prototype.open = function() {
	this.updateCSS(this.sidebarWidth);
}

SlidingView.prototype.close = function() {
	this.updateCSS(0);
}

SlidingView.prototype.isClosed = function() {
	return Boolean(this.bodyOffset === 0)
}

SlidingView.prototype.isOpened = function() {
	return Boolean(this.bodyOffset !== 0)
}

SlidingView.prototype.updateCSS = function(targetX) {
	this.bodyOffset = targetX;
	this.body.css("-webkit-transform", "translate3d(" + targetX + "px,0,0)" );
	this.body.css("-moz-transform", "translate3d(" + targetX + "px,0,0)" );
	this.body.css("transform", "translate3d(" + targetX + "px,0,0)" );
}

// Remove touch events handlers
SlidingView.prototype.unbindEvents = function() {
	this.body.get()[0].removeEventListener( this.MOVE_EVENT, this.touchMoveHandler, false );
	this.body.get()[0].removeEventListener( this.END_EVENT, this.touchUpHandler, false );
}

// Returns x, y coordinates
SlidingView.prototype.getTouchCoordinates = function(event) {
	if ( this.touchSupported ) {
		var touchEvent = event.touches[0];
		return { x:touchEvent.pageX, y:touchEvent.pageY }
	}
	else {
		return { x:event.screenX, y:event.screenY };
	}
}

// Determine width of body, based on orientation
// Might not be needed for us
SlidingView.prototype.resizeContent = function() {

	var $window = $(window)
    var w = $window.width();
    var h = $window.height();

    this.body.width( w );
}

window.SlidingView = SlidingView;

}();

// Set caret position easily in jQuery
// Written by and Copyright of Luke Morton, 2011
// Licensed under MIT
(function ($) {
    // Behind the scenes method deals with browser
    // idiosyncrasies and such
    $.caretTo = function (el, index) {
        if (el.createTextRange) {
            var range = el.createTextRange();
            range.move("character", index);
            range.select();
        } else if (el.selectionStart != null) {
            el.focus();
            el.setSelectionRange(index, index);
        }
    };

    // The following methods are queued under fx for more
    // flexibility when combining with $.fn.delay() and
    // jQuery effects.

    // Set caret to a particular index
    $.fn.caretTo = function (index, offset) {
        return this.queue(function (next) {
            if (isNaN(index)) {
                var i = $(this).val().indexOf(index);

                if (offset === true) {
                    i += index.length;
                } else if (offset) {
                    i += offset;
                }

                $.caretTo(this, i);
            } else {
                $.caretTo(this, index);
            }

            next();
        });
    };

    // Set caret to beginning of an element
    $.fn.caretToStart = function () {
        return this.caretTo(0);
    };

    // Set caret to the end of an element
    $.fn.caretToEnd = function () {
        return this.queue(function (next) {
            $.caretTo(this, $(this).val().length);
            next();
        });
    };
}(jQuery));/*! Overthrow v.0.1.0. An overflow:auto polyfill for responsive design. (c) 2012: Scott Jehl, Filament Group, Inc. http://filamentgroup.github.com/Overthrow/license.txt */
(function( w, undefined ){

	var doc = w.document,
		docElem = doc.documentElement,
		classtext = "overthrow-enabled",

		// Touch events are used in the polyfill, and thus are a prerequisite
		canBeFilledWithPoly = "ontouchmove" in doc,

		// The following attempts to determine whether the browser has native overflow support
		// so we can enable it but not polyfill
		overflowProbablyAlreadyWorks =
			// Features-first. iOS5 overflow scrolling property check - no UA needed here. thanks Apple :)
			"WebkitOverflowScrolling" in docElem.style ||
			// Touch events aren't supported and screen width is greater than X
			// ...basically, this is a loose "desktop browser" check.
			// It may wrongly opt-in very large tablets with no touch support.
			( !canBeFilledWithPoly && w.screen.width > 1200 ) ||
			// Hang on to your hats.
			// Whitelist some popular, overflow-supporting mobile browsers for now and the future
			// These browsers are known to get overlow support right, but give us no way of detecting it.
			(function(){
				var ua = w.navigator.userAgent,
					// Webkit crosses platforms, and the browsers on our list run at least version 534
					webkit = ua.match( /AppleWebKit\/([0-9]+)/ ),
					wkversion = webkit && webkit[1],
					wkLte534 = webkit && wkversion >= 534;

				return (
					/* Android 3+ with webkit gte 534
					~: Mozilla/5.0 (Linux; U; Android 3.0; en-us; Xoom Build/HRI39) AppleWebKit/534.13 (KHTML, like Gecko) Version/4.0 Safari/534.13 */
					ua.match( /Android ([0-9]+)/ ) && RegExp.$1 >= 3 && wkLte534 ||
					/* Blackberry 7+ with webkit gte 534
					~: Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0 Mobile Safari/534.11+ */
					ua.match( / Version\/([0-9]+)/ ) && RegExp.$1 >= 0 && w.blackberry && wkLte534 ||
					/* Blackberry Playbook with webkit gte 534
					~: Mozilla/5.0 (PlayBook; U; RIM Tablet OS 1.0.0; en-US) AppleWebKit/534.8+ (KHTML, like Gecko) Version/0.0.1 Safari/534.8+ */
					ua.indexOf( /PlayBook/ ) > -1 && RegExp.$1 >= 0 && wkLte534 ||
					/* Firefox Mobile (Fennec) 4 and up
					~: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:2.1.1) Gecko/ Firefox/4.0.2pre Fennec/4.0. */
					ua.match( /Fennec\/([0-9]+)/ ) && RegExp.$1 >= 4 ||
					/* WebOS 3 and up (TouchPad too)
					~: Mozilla/5.0 (hp-tablet; Linux; hpwOS/3.0.0; U; en-US) AppleWebKit/534.6 (KHTML, like Gecko) wOSBrowser/233.48 Safari/534.6 TouchPad/1.0 */
					ua.match( /wOSBrowser\/([0-9]+)/ ) && RegExp.$1 >= 233 && wkLte534 ||
					/* Nokia Browser N8
					~: Mozilla/5.0 (Symbian/3; Series60/5.2 NokiaN8-00/012.002; Profile/MIDP-2.1 Configuration/CLDC-1.1 ) AppleWebKit/533.4 (KHTML, like Gecko) NokiaBrowser/7.3.0 Mobile Safari/533.4 3gpp-gba
					~: Note: the N9 doesn't have native overflow with one-finger touch. wtf */
					ua.match( /NokiaBrowser\/([0-9\.]+)/ ) && parseFloat(RegExp.$1) === 7.3 && webkit && wkversion >= 533
				);
			})(),

		// Easing can use any of Robert Penner's equations (http://www.robertpenner.com/easing_terms_of_use.html). By default, overthrow includes ease-out-cubic
		// arguments: t = current iteration, b = initial value, c = end value, d = total iterations
		// use w.overthrow.easing to provide a custom function externally, or pass an easing function as a callback to the toss method
		defaultEasing = function (t, b, c, d) {
			return c*((t=t/d-1)*t*t + 1) + b;
		},

		enabled = false,

		// Keeper of intervals
		timeKeeper,

		/* toss scrolls and element with easing

		// elem is the element to scroll
		// options hash:
			* left is the desired horizontal scroll. Default is "+0". For relative distances, pass a string with "+" or "-" in front.
			* top is the desired vertical scroll. Default is "+0". For relative distances, pass a string with "+" or "-" in front.
			* duration is the number of milliseconds the throw will take. Default is 100.
			* easing is an optional custom easing function. Default is w.overthrow.easing. Must follow the easing function signature
		*/
		toss = function( elem, options ){
			var i = 0,
				sLeft = elem.scrollLeft,
				sTop = elem.scrollTop,
				// Toss defaults
				o = {
					top: "+0",
					left: "+0",
					duration: 100,
					easing: w.overthrow.easing
				},
				endLeft, endTop;

			// Mixin based on predefined defaults
			if( options ){
				for( var j in o ){
					if( options[ j ] !== undefined ){
						o[ j ] = options[ j ];
					}
				}
			}

			// Convert relative values to ints
			// First the left val
			if( typeof o.left === "string" ){
				o.left = parseFloat( o.left );
				endLeft = o.left + sLeft;
			}
			else {
				endLeft = o.left;
				o.left = o.left - sLeft;
			}
			// Then the top val
			if( typeof o.top === "string" ){
				o.top = parseFloat( o.top );
				endTop = o.top + sTop;
			}
			else {
				endTop = o.top;
				o.top = o.top - sTop;
			}

			timeKeeper = setInterval(function(){
				if( i++ < o.duration ){
					elem.scrollLeft = o.easing( i, sLeft, o.left, o.duration );
					elem.scrollTop = o.easing( i, sTop, o.top, o.duration );
				}
				else{
					if( endLeft !== elem.scrollLeft ){
						elem.scrollLeft = endLeft;
					}
					if( endTop !== elem.scrollTop ){
						elem.scrollTop = endTop;
					}
					intercept();
				}
			}, 1 );

			// Return the values, post-mixin, with end values specified
			return { top: endTop, left: endLeft, duration: o.duration, easing: o.easing };
		},

		// find closest overthrow (elem or a parent)
		closest = function( target, ascend ){
			return !ascend && target.className && target.className.indexOf( "overthrow" ) > -1 && target || closest( target.parentNode );
		},

		// Intercept any throw in progress
		intercept = function(){
			clearInterval( timeKeeper );
		},

		// Enable and potentially polyfill overflow
		enable = function(){

			// If it's on,
			if( enabled ){
				return;
			}
			// It's on.
			enabled = true;

			// If overflowProbablyAlreadyWorks or at least the element canBeFilledWithPoly, add a class to cue CSS that assumes overflow scrolling will work (setting height on elements and such)
			if( overflowProbablyAlreadyWorks || canBeFilledWithPoly ){
				docElem.className += " " + classtext;
			}

			// Destroy everything later. If you want to.
			w.overthrow.forget = function(){
				// Strip the class name from docElem
				docElem.className = docElem.className.replace( classtext, "" );
				// Remove touch binding (check for method support since this part isn't qualified by touch support like the rest)
				if( doc.removeEventListener ){
					doc.removeEventListener( "touchstart", start, false );
				}
				// reset easing to default
				w.overthrow.easing = defaultEasing;

				// Let 'em know
				enabled = false;
			};

			// If overflowProbablyAlreadyWorks or it doesn't look like the browser canBeFilledWithPoly, our job is done here. Exit viewport left.
			if( overflowProbablyAlreadyWorks || !canBeFilledWithPoly ){
				return;
			}

			// Fill 'er up!
			// From here down, all logic is associated with touch scroll handling
				// elem references the overthrow element in use
			var elem,

				// The last several Y values are kept here
				lastTops = [],

				// The last several X values are kept here
				lastLefts = [],

				// lastDown will be true if the last scroll direction was down, false if it was up
				lastDown,

				// lastRight will be true if the last scroll direction was right, false if it was left
				lastRight,

				// For a new gesture, or change in direction, reset the values from last scroll
				resetVertTracking = function(){
					lastTops = [];
					lastDown = null;
				},

				resetHorTracking = function(){
					lastLefts = [];
					lastRight = null;
				},

				// After releasing touchend, throw the overthrow element, depending on momentum
				finishScroll = function(){
					// Come up with a distance and duration based on how
					// Multipliers are tweaked to a comfortable balance across platforms
					var top = ( lastTops[ 0 ] - lastTops[ lastTops.length -1 ] ) * 8,
						left = ( lastLefts[ 0 ] - lastLefts[ lastLefts.length -1 ] ) * 8,
						duration = Math.max( Math.abs( left ), Math.abs( top ) ) / 8;

					// Make top and left relative-style strings (positive vals need "+" prefix)
					top = ( top > 0 ? "+" : "" ) + top;
					left = ( left > 0 ? "+" : "" ) + left;

					// Make sure there's a significant amount of throw involved, otherwise, just stay still
					if( !isNaN( duration ) && duration > 0 && ( Math.abs( left ) > 80 || Math.abs( top ) > 80 ) ){
						toss( elem, { left: left, top: top, duration: duration } );
					}
				},

				// On webkit, touch events hardly trickle through textareas and inputs
				// Disabling CSS pointer events makes sure they do, but it also makes the controls innaccessible
				// Toggling pointer events at the right moments seems to do the trick
				// Thanks Thomas Bachem http://stackoverflow.com/a/5798681 for the following
				inputs,
				setPointers = function( val ){
					inputs = elem.querySelectorAll( "textarea, input" );
					for( var i = 0, il = inputs.length; i < il; i++ ) {
						inputs[ i ].style.pointerEvents = val;
					}
				},

				// For nested overthrows, changeScrollTarget restarts a touch event cycle on a parent or child overthrow
				changeScrollTarget = function( startEvent, ascend ){
					if( doc.createEvent ){
						var newTarget = ( !ascend || ascend === undefined ) && elem.parentNode || elem.touchchild || elem,
							tEnd;

						if( newTarget !== elem ){
							tEnd = doc.createEvent( "HTMLEvents" );
							tEnd.initEvent( "touchend", true, true );
							elem.dispatchEvent( tEnd );
							newTarget.touchchild = elem;
							elem = newTarget;
							newTarget.dispatchEvent( startEvent );
						}
					}
				},

				// Touchstart handler
				// On touchstart, touchmove and touchend are freshly bound, and all three share a bunch of vars set by touchstart
				// Touchend unbinds them again, until next time
				start = function( e ){

					// Stop any throw in progress
					intercept();

					// Reset the distance and direction tracking
					resetVertTracking();
					resetHorTracking();

					elem = closest( e.target );

					if( !elem || elem === docElem || e.touches.length > 1 ){
						return;
					}

					setPointers( "none" );
					var touchStartE = e,
						scrollT = elem.scrollTop,
						scrollL = elem.scrollLeft,
						height = elem.offsetHeight,
						width = elem.offsetWidth,
						startY = e.touches[ 0 ].pageY,
						startX = e.touches[ 0 ].pageX,
						scrollHeight = elem.scrollHeight,
						scrollWidth = elem.scrollWidth,

						// Touchmove handler
						move = function( e ){

							var ty = scrollT + startY - e.touches[ 0 ].pageY,
								tx = scrollL + startX - e.touches[ 0 ].pageX,
								down = ty >= ( lastTops.length ? lastTops[ 0 ] : 0 ),
								right = tx >= ( lastLefts.length ? lastLefts[ 0 ] : 0 );

							// If there's room to scroll the current container, prevent the default window scroll
							if( ( ty > 0 && ty < scrollHeight - height ) || ( tx > 0 && tx < scrollWidth - width ) ){
								e.preventDefault();
							}
							// This bubbling is dumb. Needs a rethink.
							else {
								changeScrollTarget( touchStartE );
							}

							// If down and lastDown are inequal, the y scroll has changed direction. Reset tracking.
							if( lastDown && down !== lastDown ){
								resetVertTracking();
							}

							// If right and lastRight are inequal, the x scroll has changed direction. Reset tracking.
							if( lastRight && right !== lastRight ){
								resetHorTracking();
							}

							// remember the last direction in which we were headed
							lastDown = down;
							lastRight = right;

							// set the container's scroll
							elem.scrollTop = ty;
							elem.scrollLeft = tx;

							lastTops.unshift( ty );
							lastLefts.unshift( tx );

							if( lastTops.length > 3 ){
								lastTops.pop();
							}
							if( lastLefts.length > 3 ){
								lastLefts.pop();
							}
						},

						// Touchend handler
						end = function( e ){
							// Apply momentum based easing for a graceful finish
							finishScroll();
							// Bring the pointers back
							setPointers( "auto" );
							setTimeout( function(){
								setPointers( "none" );
							}, 450 );
							elem.removeEventListener( "touchmove", move, false );
							elem.removeEventListener( "touchend", end, false );
						};

					elem.addEventListener( "touchmove", move, false );
					elem.addEventListener( "touchend", end, false );
				};

			// Bind to touch, handle move and end within
			doc.addEventListener( "touchstart", start, false );
		};

	// Expose overthrow API
	w.overthrow = {
		set: enable,
		forget: function(){},
		easing: defaultEasing,
		toss: toss,
		intercept: intercept,
		closest: closest,
		support: overflowProbablyAlreadyWorks ? "native" : canBeFilledWithPoly && "polyfilled" || "none"
	};

	// Auto-init
	enable();

})( this );/*
 * Embedly JQuery v2.2.0
 * ==============
 * This library allows you to easily embed objects on any page.
 */
(function(a){window.embedlyURLre=/(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;a.embedly=a.embedly||{};if(a.embedly.version){return}a.extend({embedly:function(k,q,n){var c=[];var p="http://api.embed.ly/";var d;q=q?q:{};d=a.extend({},a.embedly.defaults,q);if(!d.urlRe){d.urlRe=window.embedlyURLre}if(typeof k==="string"){k=new Array(k)}if(typeof n!=="undefined"){d.success=n}if(d.secure){p="https://api.embed.ly/"}if(!d.success){d.success=function(i,t){var r,s=a(t.node);if(!(i)){return null}if((r=d.method)==="replace"){return s.replaceWith(i.code)}else{if(r==="after"){return s.after(i.code)}else{if(r==="afterParent"){return s.parent().after(i.code)}else{if(r==="replaceParent"){return s.parent().replaceWith(i.code)}}}}}}if(!d.error){d.error=function(i,r){}}var m=function(i){return d.urlRe.test(i)};var o=function(r){var i="urls="+r;if(d.maxWidth){i+="&maxwidth="+d.maxWidth}else{if(typeof dimensions!=="undefined"){i+="&maxwidth="+dimensions.width}}if(d.maxHeight){i+="&maxheight="+d.maxHeight}if(d.chars){i+="&chars="+d.chars}if(d.words){i+="&words="+d.words}if(d.secure){i+="&secure=true"}if(d.frame){i+="&frame=true"}i+="&wmode="+d.wmode;if(typeof d.key==="string"){i+="&key="+d.key}if(typeof d.autoplay==="string"||typeof d.autoplay==="boolean"){i+="&autoplay="+d.autoplay}if(d.width){i+="&width="+d.width}return i};var j=function(){if(typeof d.key==="string"){if(d.endpoint.search(/objectify/i)>=0){return p+"2/objectify"}else{if(d.endpoint.search(/preview/i)>=0){return p+"1/preview"}}}return p+"1/oembed"};var b=function(){var i=[];if(d.addImageStyles){if(d.maxWidth){units=isNaN(parseInt(d.maxWidth,10))?"":"px";i.push("max-width: "+(d.maxWidth)+units)}if(d.maxHeight){units=isNaN(parseInt(d.maxHeight,10))?"":"px";i.push("max-height: "+(d.maxHeight)+units)}}return i.join(";")};var g=function(v,t){if(d.endpoint!=="oembed"){return d.success(v,t)}var w,s,r,y,u,i,x,z;if((w=v.type)==="photo"){y=v.title||"";s="<a href='"+t.url+"' target='_blank'><img style='"+b()+"' src='"+v.url+"' alt='"+y+"' /></a>"}else{if(w==="video"){s=v.html}else{if(w==="rich"){s=v.html}else{y=v.title||t.url;i=v.thumbnail_url?"<img src='"+v.thumbnail_url+"' class='thumb' style='"+b()+"'/>":"";z=v.description?'<div class="description">'+v.description+"</div>":"";x=v.provider_name?"<a href='"+v.provider_url+"' class='provider'>"+v.provider_name+"</a>":"";s=i+"<a href='"+t.url+"'>"+y+"</a>";s+=x;s+=z}}}if(d.wrapElement&&d.wrapElement==="div"&&a.browser.msie&&a.browser.version<9){d.wrapElement="span"}if(d.wrapElement){s="<"+d.wrapElement+' class="'+d.className+'">'+s+"</"+d.wrapElement+">"}v.code=s;if(typeof t.node!=="undefined"){a(t.node).data("oembed",v).trigger("embedly-oembed",[v])}return d.success(v,t)};var e=function(i){var t,v,u,s,r;u=a.map(i,function(x,w){if(w===0){if(x.node!==null){r=a(x.node);s={width:r.parent().width(),height:r.parent().height()}}}return encodeURIComponent(x.url)}).join(",");a.ajax({url:j(),dataType:"jsonp",data:o(u),success:function(w){return a.each(w,function(x,y){return y.type!=="error"?g(y,i[x]):d.error(i[x].node,y)})}})};a.each(k,function(s,r){var u=typeof d.elems!=="undefined"?d.elems[s]:null;if(typeof u!=="undefined"&&!m(r)){a(u).data("oembed",false)}var t={url:r,error_code:400,error_message:"HTTP 400: Bad Request",type:"error"};return(r&&m(r))?c.push({url:r,node:u}):d.error(u,t)});var l=[];var h=c.length;for(var f=0;(0<=h?f<h:f>h);f+=20){l=l.concat(e(c.slice(f,f+20)))}if(d.elems){return d.elems}else{return this}}});a.embedly.version="2.2.0";a.embedly.defaults={endpoint:"oembed",secure:false,frame:false,wmode:"opaque",method:"replace",addImageStyles:true,wrapElement:"div",className:"embed",elems:[]};a.fn.embedly=function(d,g){var e=typeof d!=="undefined"?d:{};if(typeof g!=="undefined"){d.success=g}var f=new Array();var c=new Array();this.each(function(){if(typeof a(this).attr("href")!=="undefined"){f.push(a(this).attr("href"));c.push(a(this))}else{a(this).find("a").each(function(){f.push(a(this).attr("href"));c.push(a(this))})}e.elems=c});var b=a.embedly(f,e);return this}})(jQuery);
// Generated by CoffeeScript 1.3.3
(function() {
  (function(c,a){window.mixpanel=a;var b,d,h,e;b=c.createElement("script");
b.type="text/javascript";b.async=!0;b.src=("https:"===c.location.protocol?"https:":"http:")+
'//cdn.mxpnl.com/libs/mixpanel-2.1.min.js';d=c.getElementsByTagName("script")[0];
d.parentNode.insertBefore(b,d);a._i=[];a.init=function(b,c,f){function d(a,b){
var c=b.split(".");2==c.length&&(a=a[c[0]],b=c[1]);a[b]=function(){a.push([b].concat(
Array.prototype.slice.call(arguments,0)))}}var g=a;"undefined"!==typeof f?g=a[f]=[]:
f="mixpanel";g.people=g.people||[];h=['disable','track','track_pageview','track_links',
'track_forms','register','register_once','unregister','identify','name_tag',
'set_config','people.identify','people.set','people.increment'];for(e=0;e<h.length;e++)d(g,h[e]);
a._i.push([b,c,f])};a.__SV=1.1;})(document,window.mixpanel||[]);
mixpanel.init("9d1aa9ff8a03b879d6ea48459c97ce5b");;

  (function(a){a.fn.longClick=function(b,c){var d;
c=c||500;a(this).on('touchstart',function(){d=setTimeout(function(){b()},c)});
a(this).on('touchend',function(){clearTimeout(d);});
a(this).on('touchmove',function(){clearTimeout(d);});
a(this).on('swipe',function(){clearTimeout(d);});
a('#main-body').on('touchmove',function(){clearTimeout(d);});
a('#main-body').on('swipe',function(){clearTimeout(d);});}})(jQuery);

  var AutocompleteFilterView, AutocompleteListView, AutocompleteView, DialogView, DoItView, EditNoteView, FakeDatabase, Fetch, Filter, FilterList, FilterListView, FilterView, Note, NoteList, NoteListView, NoteView, SelectFiltersView, Set, YAY_DEBUG,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  Kinvey.Sync.configure({
    conflict: Kinvey.Sync.serverAlwaysWins,
    start: function() {
      return console.log('STARTING TO SYNC');
    },
    success: function(status) {
      console.log('SUCCESS');
      return console.log(JSON.stringify(status));
    },
    error: function(e) {
      console.log('ERROR');
      return console.log(e);
    }
  });

  Kinvey.init({
    appKey: 'kid_PVtSim6Wi5',
    appSecret: 'c429fbc2a46d4ac4930f67ef7e4f8a8e'
  });

  Fetch = Fetch || {};

  if (typeof String.prototype.startsWith !== 'function') {
    String.prototype.startsWith = function(str) {
      return this.indexOf(str) === 0;
    };
  }

  String.prototype.regexIndexOf = function(regex, startpos) {
    var indexOf;
    indexOf = this.substring(startpos || 0).search(regex);
    if (indexOf >= 0) {
      return indexOf + (startpos || 0);
    } else {
      return indexOf;
    }
  };

  String.prototype.regexLastIndexOf = function(regex, startpos) {
    var lastIndexOf, nextStop, result, stringToWorkWith;
    regex = (regex.global ? regex : new RegExp(regex.source, "g" + (regex.ignoreCase ? "i" : "") + (regex.multiLine ? "m" : "")));
    if (typeof startpos === "undefined") {
      startpos = this.length;
    } else {
      if (startpos < 0) {
        startpos = 0;
      }
    }
    stringToWorkWith = this.substring(0, startpos + 1);
    lastIndexOf = -1;
    nextStop = 0;
    while ((result = regex.exec(stringToWorkWith)) != null) {
      lastIndexOf = result.index;
      regex.lastIndex = ++nextStop;
    }
    return lastIndexOf;
  };

  Date.prototype.sameDay = function(a) {
    return Boolean(this.toDateString() === a.toDateString());
  };

  Date.prototype.toISODate = function() {
    var addZero;
    addZero = function(n) {
      return (n < 0 || n > 9 ? '' : '0') + n;
    };
    return "" + (this.getFullYear()) + "-" + (addZero(this.getMonth() + 1)) + "-" + (addZero(this.getDate())) + "T" + (addZero(this.getHours())) + ":" + (addZero(this.getMinutes())) + ":" + (addZero(this.getSeconds())) + ".000Z";
  };

  Fetch.getCaretPosition = function(textArea) {
    var bm, sel, sleft;
    if (document.selection) {
      bm = document.selection.createRange().getBookmark();
      sel = textArea.createTextRange();
      sel.moveToBookmark(bm);
      sleft = textArea.createTextRange();
      sleft.collapse(true);
      sleft.setEndPoint("EndToStart", sel);
      return sleft.text.length + sel.text.length;
    }
    return textArea.selectionEnd;
  };

  Fetch.baseurl = 'http://www.fetchnotes.com';

  Fetch.prefixes = [Fetch.baseurl, 'fetch-sesh', 'fetch-last-updated'];

  Fetch.regexp = {
    tags: /#[\w]+/g,
    contacts: /@[\w]+/g,
    urls: /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig,
    emails: /([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4})/ig
  };

  Fetch.methodMap = {
    'create': 'POST',
    'update': 'POST',
    'delete': 'POST',
    'read': 'GET'
  };

  Fetch.monthMap = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

  Fetch.findTags = function(str) {
    return str.replace(Fetch.regexp.urls, '').match(Fetch.regexp.tags) || [];
  };

  Fetch.findContacts = function(str) {
    return str.replace(Fetch.regexp.emails, '').match(Fetch.regexp.contacts) || [];
  };

  Fetch.findEmails = function(str) {
    return str.match(Fetch.regexp.emails) || [];
  };

  Fetch.findUrls = function(str) {
    return str.match(Fetch.regexp.urls) || [];
  };

  Fetch.findEntities = function(text) {
    return {
      hashtags: Fetch.findTags(text),
      attags: Fetch.findContacts(text),
      emails: Fetch.findEmails(text),
      urls: Fetch.findUrls(text)
    };
  };

  Fetch.HTMLize = function(text) {
    var contact, i, line, lines, reg, tag, _i, _j, _k, _len, _len1, _len2, _ref, _ref1;
    if ((text === void 0) || ($.trim(text) === '')) {
      return '<p>&nbsp;</p>';
    }
    text = text.replace(/&/g, '&amp;').replace(/</g, "&lt;").replace(/>/g, '&gt;').replace(/\ \ /g, '&nbsp;&nbsp;');
    _ref = Fetch.findTags(text);
    for (_i = 0, _len = _ref.length; _i < _len; _i++) {
      tag = _ref[_i];
      reg = new RegExp(tag + '\\b', 'gi');
      text = text.replace(reg, "<span class=\"tag\">$&</span>");
    }
    _ref1 = Fetch.findContacts(text);
    for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
      contact = _ref1[_j];
      reg = new RegExp(contact + '\\b', 'gi');
      text = text.replace(reg, "<span class=\"contact\">$&</span>");
    }
    text = text.replace(/bitches/gi, '<span class="bitches">$&</span>');
    text = text.replace(Fetch.regexp.urls, "<a href='$1' target='_blank'>$1</a>");
    text = text.replace(Fetch.regexp.emails, "<a href='mailto:$1' target='_blank'>$1</a>");
    lines = text.split(/\n/);
    for (i = _k = 0, _len2 = lines.length; _k < _len2; i = ++_k) {
      line = lines[i];
      if ($.trim(line) === '') {
        line = '&nbsp;';
      }
      line = "<p>" + line + "</p>";
      lines[i] = line;
    }
    return lines.join('');
  };

  Fetch.fetchDate = function(milli) {
    milli || (milli = new Date().getTime());
    return new Date(milli).toISOString().replace('Z', '');
  };

  Fetch.stackTrace = function() {
    var s;
    try {
      return unusedVariable++;
    } catch (e) {
      s = e.stack;
      return console.log(s);
    }
  };

  Fetch.nukeCache = function() {
    var key, _i, _len, _ref, _results;
    _ref = Object.keys(localStorage).filter(function(str) {
      var prefix, result, _j, _len, _ref;
      result = false;
      _ref = Fetch.prefixes;
      for (_j = 0, _len = _ref.length; _j < _len; _j++) {
        prefix = _ref[_j];
        result || (result = str.startsWith(prefix));
      }
      console.log("" + str + ": " + result);
      return result;
    });
    _results = [];
    for (_i = 0, _len = _ref.length; _i < _len; _i++) {
      key = _ref[_i];
      _results.push(delete localStorage[key]);
    }
    return _results;
  };

  Fetch.redirect = function(url) {
    if (window.forge) {
      return forge.tools.getURL(url, function(qualifiedurl) {
        return window.location = qualifiedurl;
      });
    } else {
      return window.location = url;
    }
  };

  Fetch.ajax = window.forge ? window.forge.ajax : $.ajax;

  Fetch.isAndroid = (function() {
    return window.forge && forge.is.android();
  })();

  if (Fetch.isAndroid && !Fetch.androidButtons) {
    Fetch.backButton = {};
    Fetch.backButton.init = function() {
      forge.event.backPressed.preventDefault(function() {
        return console.log('no more default back button');
      }, function(error) {
        return console.log("Error initializing preventing default " + (JSON.stringify(error)));
      });
      return forge.event.backPressed.addListener(function(close) {
        if (Fetch.app != null) {
          return Fetch.backButton.mainApp(close);
        } else {
          return Fetch.backButton.loginScreen(close);
        }
      }, function(error) {
        return console.log("Error initializing button " + (JSON.stringify(error)));
      });
    };
    Fetch.backButton.mainApp = function(close) {
      if (Fetch.drawer.isOpened()) {
        return Fetch.drawer.close();
      } else if (Fetch.backButton.modal) {
        return Fetch.backButton.modal.hidePopUpMessage();
      } else if (bc.ui.pageStack.length > 1) {
        return Fetch.editNote.back();
      } else if ($('#search-notes').val()) {
        $('#search-notes').val('');
        return Fetch.app.search();
      } else {
        return close();
      }
    };
    Fetch.backButton.loginScreen = function(close) {
      if (bc.ui.pageStack.length > 2) {
        return Fetch.home.showPreviousSlide();
      } else if (bc.ui.pageStack.length > 1) {
        return Fetch.home.showTutorial();
      } else {
        return close();
      }
    };
    Fetch.menuButton = {};
    Fetch.menuButton.init = function() {
      return forge.event.menuPressed.addListener(function() {
        if (bc.ui.pageStack.length === 1) {
          return Fetch.drawer.toggle();
        }
      }, function(error) {
        return console.log("problem with menu button " + (JSON.stringify(error)));
      });
    };
    Fetch.androidButtons = [Fetch.menuButton, Fetch.backButton];
  }

  FakeDatabase = (function() {

    FakeDatabase.prototype.data = [];

    FakeDatabase.prototype.url = 'fetch-notes-fake-db';

    function FakeDatabase() {
      console.log('MAKE A FAKE DB');
      this.notes.url = this.url;
      this._load();
    }

    FakeDatabase.prototype._load = function() {
      return this.data = this.notes.data = this.hashtags.data = this.attags.data = bc.core.cache(this.url) || [];
    };

    FakeDatabase.prototype.notes = {
      _save: function() {
        return bc.core.cache(this.url, this.data);
      },
      create: function(model, options) {
        var m, _i, _len;
        options = options ? _.clone(options) : {};
        model.set('localID', Date.now());
        model = model.toJSON();
        model.dirty = Boolean(options.dirty);
        if (_.isArray(model)) {
          for (_i = 0, _len = model.length; _i < _len; _i++) {
            m = model[_i];
            this.create(m);
          }
          return;
        } else {
          console.log('adding note to db');
          this.data.push(model);
        }
        return this.call(options);
      },
      get: function(options) {
        var at, dirty, filters, hash, intersect, limit, model, results, search, skip, _i, _j, _k, _l, _len, _len1, _len2, _len3, _ref, _ref1, _ref2, _ref3;
        this.data = _.sortBy(this.data, function(n) {
          return -Date.parse(n.timestamp);
        });
        console.log('getting u some notes');
        options = options ? _.clone(options) : {};
        filters = [];
        if (options.hashtags && options.hashtags.length) {
          hash = [];
          _ref = this.data;
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            model = _ref[_i];
            intersect = _.intersection(model.entities.hashtags, options.hashtags);
            if (intersect.length === options.hashtags.length) {
              hash.push(model);
            }
          }
          filters.push(hash);
        }
        if (options.attags && options.attags.length) {
          at = [];
          _ref1 = this.data;
          for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
            model = _ref1[_j];
            intersect = _.intersection(model.entities.attags, options.attags);
            if (intersect.length === options.attags.length) {
              at.push(model);
            }
          }
          filters.push(at);
        }
        if (options.search && options.search.length) {
          search = [];
          _ref2 = this.data;
          for (_k = 0, _len2 = _ref2.length; _k < _len2; _k++) {
            model = _ref2[_k];
            if (model.text.indexOf(options.search) !== -1) {
              search.push(model);
            }
          }
          filters.push(search);
        }
        if (options.dirty) {
          dirty = [];
          _ref3 = this.data;
          for (_l = 0, _len3 = _ref3.length; _l < _len3; _l++) {
            model = _ref3[_l];
            if (model.dirty) {
              dirty.push(model);
            }
          }
          filters.push(dirty);
        }
        if (filters.length) {
          results = _.intersection.apply(_, filters);
        } else {
          results = this.data;
        }
        skip = options.skip ? options.skip : 0;
        limit = options.limit ? options.limit : 25;
        return this.call(results.slice(skip, skip + limit), options);
      },
      update: function(model, options) {
        console.log('updating note in db');
        this._remove(model);
        this.data.push(model);
        return this.call(options);
      },
      "delete": function(model, options) {
        console.log('deleting note in db');
        this._remove(model);
        return this.call(options);
      },
      clean: function(model, options) {
        return console.log('cleaning note');
      },
      _remove: function(model) {
        var i, note, _i, _len, _ref, _results;
        _ref = this.data;
        _results = [];
        for (i = _i = 0, _len = _ref.length; _i < _len; i = ++_i) {
          note = _ref[i];
          if (note.localID === model.get('localID')) {
            this.data.splice(i, 1);
            break;
          } else {
            _results.push(void 0);
          }
        }
        return _results;
      },
      call: function(resp, options) {
        console.log(resp);
        this._save();
        if (options && options.success) {
          return options.success(resp, options);
        }
      },
      _modelToObject: function(model) {
        return {
          dirty: model.get('dirty'),
          entities: model.get('entities'),
          localID: model.get('localID'),
          text: model.get('text'),
          timestamp: model.get('timestamp')
        };
      }
    };

    FakeDatabase.prototype.hashtags = {
      get: function(options) {
        var model, stuff, tag, _i, _j, _len, _len1, _ref, _ref1;
        stuff = new Set;
        _ref = this.data;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          model = _ref[_i];
          _ref1 = model.entities.hashtags;
          for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
            tag = _ref1[_j];
            stuff.add(tag);
          }
        }
        return this.call(stuff.get(), options);
      },
      call: function(resp, options) {
        if (options && options.success) {
          return options.success(resp, options);
        }
      }
    };

    FakeDatabase.prototype.attags = {
      get: function(options) {
        var model, stuff, tag, _i, _j, _len, _len1, _ref, _ref1;
        stuff = new Set;
        _ref = this.data;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          model = _ref[_i];
          _ref1 = model.entities.attags;
          for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
            tag = _ref1[_j];
            stuff.add(tag);
          }
        }
        return this.call(stuff.get(), options);
      },
      call: function(resp, options) {
        if (options && options.success) {
          return options.success(resp, options);
        }
      }
    };

    return FakeDatabase;

  })();

  Set = (function() {

    function Set() {
      this.data = {};
    }

    Set.prototype.add = function(item) {
      if (this.data.hasOwnProperty(item)) {
        return this.data[item] += 1;
      } else {
        return this.data[item] = 1;
      }
    };

    Set.prototype.get = function() {
      var item, results, _i, _len, _ref;
      results = [];
      _ref = Object.keys(this.data);
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        item = _ref[_i];
        results.push({
          name: item,
          count: this.data[item]
        });
      }
      return results;
    };

    return Set;

  })();

  Note = (function(_super) {

    __extends(Note, _super);

    Note.prototype.defaults = function() {
      return {
        text: '',
        timestamp: Fetch.fetchDate(),
        entities: {}
      };
    };

    function Note(attr, options) {
      if (attr.entities == null) {
        attr.entities = Fetch.findEntities(attr.text);
      }
      Note.__super__.constructor.call(this, attr, options);
    }

    Note.prototype.kinveyToBackbone = function(entity) {
      var text;
      text = entity.get('text');
      return {
        entity: entity,
        text: text,
        timestamp: entity.get('timestamp') || Fetch.fetchDate(),
        entities: entity.get('entities') || Fetch.findEntities(text),
        id: entity.get('_id')
      };
    };

    Note.prototype.backboneToKinvey = function(model) {
      return {
        text: model.get('text'),
        timestamp: model.get('timestamp'),
        entities: model.get('entities')
      };
    };

    Note.prototype.kinveyMethodMap = {
      create: 'save',
      update: 'save',
      "delete": 'destroy'
    };

    Note.prototype.sync = function(method, model, options) {
      var databaseOptions, kinveyData, kinveyMethod;
      console.log('NOTE SYNC');
      if (method === 'read') {
        throw {
          name: 'Method Error',
          message: 'Read method not supported on Note model.'
        };
        return;
      }
      kinveyMethod = model.kinveyMethodMap[method];
      databaseOptions = options ? _.clone(options) : {};
      databaseOptions.success = $.noop;
      databaseOptions.error = $.noop;
      databaseOptions.dirty = true;
      Fetch.db.notes[method](model, databaseOptions);
      kinveyData = model.backboneToKinvey(model);
      if (model.id != null) {
        kinveyData._id = model.id;
      }
      return new Kinvey.Entity(kinveyData, 'notes')[kinveyMethod]({
        success: function(entity) {
          console.log("note " + method + "d on Kinvey!");
          if (method === 'create') {
            model.id = entity.get('_id');
          }
          if (entity == null) {
            entity = model;
          }
          return Fetch.db.notes.clean(entity);
        },
        error: function(e) {
          return console.log(e);
        }
      });
    };

    return Note;

  })(Backbone.Model);

  Filter = (function(_super) {

    __extends(Filter, _super);

    function Filter() {
      return Filter.__super__.constructor.apply(this, arguments);
    }

    Filter.prototype.defaults = {
      name: '',
      count: null,
      selected: false
    };

    Filter.prototype.toggle = function(property) {
      var value;
      value = !this.get(property);
      return this.set(property, value);
    };

    Filter.prototype.sync = function() {
      return {};
    };

    return Filter;

  })(Backbone.Model);

  NoteList = (function(_super) {

    __extends(NoteList, _super);

    function NoteList() {
      return NoteList.__super__.constructor.apply(this, arguments);
    }

    NoteList.prototype.model = Note;

    NoteList.prototype.CHUNK_SIZE = 25;

    NoteList.prototype.initialize = function(models, options) {
      var _this = this;
      this.collection = new Kinvey.Collection('notes');
      this.throttledHandleFilter = _.debounce(this.handleFilter, 500);
      this.tags = new FilterList([], {
        filterName: 'hashtags',
        collection: this.collection
      });
      this.contacts = new FilterList([], {
        filterName: 'attags',
        collection: this.collection
      });
      this.tags.on('filter', this.handleFilter, this);
      this.contacts.on('filter', this.handleFilter, this);
      this.on('add', this._addNoteFilters, this);
      this.on('remove', this._removeNoteFilters, this);
      this.on('change:text', function(model) {
        var entities;
        model.set('entities', Fetch.findEntities(model.get('text')));
        entities = model.previous('entities');
        _this.tags.removeFilters(entities.hashtags);
        _this.contacts.removeFilters(entities.attags);
        return _this._addNoteFilters(model);
      }, this);
      return this.on('destroy', this.handleDestroy, this);
    };

    NoteList.prototype._get = function(model, attribute) {
      return model.get('entities')[attribute];
    };

    NoteList.prototype._addNoteFilters = function(model) {
      this.tags.addFilters(this._get(model, 'hashtags'));
      return this.contacts.addFilters(this._get(model, 'attags'));
    };

    NoteList.prototype._removeNoteFilters = function(model) {
      this.tags.removeFilters(this._get(model, 'hashtags'));
      return this.contacts.removeFilters(this._get(model, 'attags'));
    };

    NoteList.prototype.comparator = function(note) {
      return -Date.parse(note.get('timestamp'));
    };

    NoteList.prototype.search = function(term) {
      this.searchTerm = term;
      return this.throttledHandleFilter();
    };

    NoteList.prototype.throttledHandleFilter = null;

    NoteList.prototype.handleFilter = function() {
      return this.filter({
        hashtags: this.tags.selected,
        attags: this.contacts.selected,
        search: this.searchTerm
      });
    };

    NoteList.prototype.filter = function(options) {
      return this.fetch(options);
    };

    NoteList.prototype.getNext = function() {
      return this.fetch({
        limit: this.CHUNK_SIZE,
        skip: this.length,
        remove: false,
        update: true,
        silent: true,
        success: function(collection, resp, options) {
          return collection.trigger('update');
        }
      });
    };

    NoteList.prototype.handleDestroy = function(model, collection, options) {
      if (model.isNew()) {
        Fetch.db.notes["delete"](model);
      }
      if (collection.length === 0) {
        return collection.handleFilter();
      }
    };

    NoteList.prototype.sync = function(method, model, options) {
      var success,
        _this = this;
      console.log("LIST SYNC");
      if (method !== 'read') {
        throw {
          name: 'Method Error',
          message: 'Only the read method is support on NoteList'
        };
        return;
      }
      options = options ? _.clone(options) : {};
      success = options.success;
      options.success = function(resp, options) {
        if (success) {
          return success(_this, resp, options);
        }
      };
      options.error = $.noop;
      return Fetch.db.notes.get(options);
    };

    NoteList.prototype.harmonize = function(options) {
      return this.collection.fetch({
        success: function(serverList) {
          return Fetch.db.notes.get({
            dirty: true,
            success: function(dbList) {
              if (dbList.length) {

              } else {

              }
            },
            error: function(e) {}
          });
        },
        error: function(e) {}
      });
    };

    return NoteList;

  })(Backbone.Collection);

  FilterList = (function(_super) {

    __extends(FilterList, _super);

    function FilterList() {
      return FilterList.__super__.constructor.apply(this, arguments);
    }

    FilterList.prototype.model = Filter;

    FilterList.prototype.initialize = function(models, options) {
      this.selected = [];
      this.name = options.filterName;
      return this.on('change:selected', this.changeSelected, this);
    };

    FilterList.prototype.sync = function(method, model, options) {
      var success,
        _this = this;
      if (method !== 'read') {
        throw {
          name: 'Method Error',
          message: 'Only the read method is support on FilterList'
        };
        return;
      }
      console.log('FILTERS');
      success = options.success;
      options.success = function(resp, options) {
        if (success) {
          return success(_this, resp, options);
        }
      };
      return Fetch.db[this.name].get(options);
    };

    FilterList.prototype.addFilters = function(filters) {
      var count, filter, model, _i, _len, _results;
      _results = [];
      for (_i = 0, _len = filters.length; _i < _len; _i++) {
        filter = filters[_i];
        model = this._getModel({
          name: filter
        });
        if (model) {
          count = model.get('count');
          _results.push(model.set('count', count + 1));
        } else {
          _results.push(this.create({
            name: filter,
            count: 1
          }));
        }
      }
      return _results;
    };

    FilterList.prototype.removeFilters = function(filters) {
      var count, filter, model, _i, _len, _results;
      _results = [];
      for (_i = 0, _len = filters.length; _i < _len; _i++) {
        filter = filters[_i];
        model = this._getModel({
          name: filter
        });
        count = model.get('count');
        if (count === 1) {
          _results.push(model.destroy());
        } else {
          _results.push(model.set('count', count - 1));
        }
      }
      return _results;
    };

    FilterList.prototype._getModel = function(attrs) {
      return this.where(attrs)[0];
    };

    FilterList.prototype.changeSelected = function(model, val, options) {
      this.selected = this.selectedNames();
      return this.trigger('filter');
    };

    FilterList.prototype.comparator = function(filter) {
      return filter.get('name');
    };

    FilterList.prototype.selectedFilters = function() {
      return this.where({
        'selected': true
      });
    };

    FilterList.prototype.selectedNames = function() {
      return _.map(this.selectedFilters(), function(f) {
        return f.get('name');
      });
    };

    FilterList.prototype.namesStartingWith = function(word) {
      word = word.toLowerCase();
      return this.filter(function(f) {
        return f.get('name').toLowerCase().startsWith(word);
      });
    };

    FilterList.prototype.top = function() {
      return this.first(5);
    };

    return FilterList;

  })(Backbone.Collection);

  NoteView = (function(_super) {

    __extends(NoteView, _super);

    function NoteView() {
      this.contextMenu = __bind(this.contextMenu, this);
      return NoteView.__super__.constructor.apply(this, arguments);
    }

    NoteView.prototype.tagName = 'li';

    NoteView.prototype.template = _.template($('#note-template').html());

    NoteView.prototype.events = {
      'tap': 'tapped',
      'swipe': 'swiped',
      'tap .delete': 'delete'
    };

    NoteView.prototype.initialize = function() {
      this.list = this.options.list;
      if (!this.model.get('html')) {
        this.updateHTML();
      }
      this.listenTo(this.model, 'change:text', this.updateHTML);
      this.listenTo(this.model, 'change_visible', this.handleVisibility);
      this.listenTo(this.model, 'change', this.render);
      this.listenTo(this.model, 'destroy', this.remove);
      if (window.forge && forge.is.android()) {
        return $(this.el).longClick(this.contextMenu, 500);
      }
    };

    NoteView.prototype.contextMenu = function() {
      var items, text,
        _this = this;
      text = this.model.get('text');
      items = ['Delete Note'];
      items = items.concat(Fetch.findEmails(text));
      items = items.concat(Fetch.findUrls(text));
      if (!Fetch.drawer.isOpened()) {
        return forge.internal.call('contextmenu.show', {
          items: items
        }, function(result) {
          if (result === 'Delete Note') {
            return _this["delete"]();
          } else if (Fetch.findUrls(result).length > 0) {
            return window.location = result;
          } else if (Fetch.findEmails(result).length > 0) {
            return window.location = "mailto:" + result;
          }
        });
      }
    };

    NoteView.prototype.render = function() {
      this.$el.html(this.template({
        html: this.model.get('html'),
        timestamp: this.displayTimestamp(this.model.get('timestamp'))
      }));
      this.deleteButton = this.$('.delete');
      return this;
    };

    NoteView.prototype.displayHTML = function(txt) {
      var characterLimit, firstLinebreak, index;
      characterLimit = 60;
      firstLinebreak = txt.indexOf('\n');
      if (firstLinebreak !== -1) {
        txt = txt.slice(0, firstLinebreak);
      }
      if (txt.length < characterLimit) {
        return Fetch.HTMLize(txt);
      }
      txt = txt.slice(0, characterLimit);
      index = txt.lastIndexOf(' ');
      return Fetch.HTMLize("" + (txt.slice(0, index)) + "...");
    };

    NoteView.prototype.displayTimestamp = function(UTC) {
      var hours, leadingZero, mins, now, suffix, time;
      if (UTC[UTC.length - 7] === '.') {
        UTC = UTC.slice(0, -3);
      }
      time = new Date("" + UTC + "Z");
      now = new Date();
      if (time.sameDay(now)) {
        mins = time.getMinutes();
        hours = time.getHours();
        leadingZero = mins < 10 ? '0' : '';
        suffix = hours < 12 ? 'a' : 'p';
        if (suffix === 'p') {
          hours -= 12;
        }
        if (hours === 0) {
          hours += 12;
        }
        return "" + hours + ":" + leadingZero + mins + suffix;
      }
      return "" + (time.getDate()) + " " + Fetch.monthMap[time.getMonth()];
    };

    NoteView.prototype.updateHTML = function() {
      return this.model.set({
        html: this.displayHTML(this.model.get('text'))
      });
    };

    NoteView.prototype.tapped = function() {
      if (!this.list.deleting) {
        return this.viewNote();
      }
    };

    NoteView.prototype.swiped = function(e, direction) {
      if (direction === 'swipeLeft' && Fetch.drawer.isClosed() && !this.list.deleting) {
        this.showDelete();
        return $(document).one(bc.events.start, $.proxy(this.registerHideDelete, this));
      }
    };

    NoteView.prototype.registerHideDelete = function() {
      return $(document).one(bc.events.end, $.proxy(this.hideDelete, this));
    };

    NoteView.prototype.viewNote = function() {
      Fetch.editNote = new EditNoteView({
        model: this.model
      });
      Fetch.drawer.close();
      return bc.ui.forwardPage($("#edit-note"));
    };

    NoteView.prototype.showDelete = function() {
      this.deleteButton.show();
      return this.list.deleting = true;
    };

    NoteView.prototype.hideDelete = function() {
      this.deleteButton.hide();
      return this.list.deleting = false;
    };

    NoteView.prototype["delete"] = function() {
      return this.model.destroy();
    };

    return NoteView;

  })(Backbone.View);

  FilterView = (function(_super) {

    __extends(FilterView, _super);

    function FilterView() {
      return FilterView.__super__.constructor.apply(this, arguments);
    }

    FilterView.prototype.tagName = 'li';

    FilterView.prototype.className = 'filter';

    FilterView.prototype.template = _.template($('#filter-template').html());

    FilterView.prototype.events = {
      'tap': 'select'
    };

    FilterView.prototype.initialize = function() {
      this.model.on('change', this.render, this);
      return this.model.on('destroy', this.remove, this);
    };

    FilterView.prototype.render = function() {
      this.$el.html(this.template({
        name: this.display(this.model.get('name'))
      }));
      this.$el.toggleClass('selected', this.model.get('selected'));
      return this;
    };

    FilterView.prototype.display = function(name) {
      var characterCount;
      characterCount = 25;
      return name.substring(name[0] === '@' || name[0] === '#' ? 1 : 0).slice(0, characterCount);
    };

    FilterView.prototype.select = function() {
      this.model.toggle('selected');
      return mixpanel.track('filtered', {
        hashtags: Fetch.notes.tags.selected,
        attags: Fetch.notes.contacts.selected
      });
    };

    return FilterView;

  })(Backbone.View);

  AutocompleteFilterView = (function(_super) {

    __extends(AutocompleteFilterView, _super);

    function AutocompleteFilterView() {
      return AutocompleteFilterView.__super__.constructor.apply(this, arguments);
    }

    AutocompleteFilterView.prototype.initialize = function(options) {
      return this.parent = options.parent;
    };

    AutocompleteFilterView.prototype.select = function() {
      return this.parent.trigger('select', this.model.get('name'));
    };

    return AutocompleteFilterView;

  })(FilterView);

  AutocompleteListView = (function(_super) {

    __extends(AutocompleteListView, _super);

    function AutocompleteListView() {
      return AutocompleteListView.__super__.constructor.apply(this, arguments);
    }

    AutocompleteListView.prototype.add = function(filter) {
      var view;
      view = new AutocompleteFilterView({
        model: filter,
        parent: this
      });
      return this.$el.append(view.render().el);
    };

    AutocompleteListView.prototype.display = function(list) {
      var filter, _i, _len, _results;
      this.empty();
      _results = [];
      for (_i = 0, _len = list.length; _i < _len; _i++) {
        filter = list[_i];
        _results.push(this.add(filter));
      }
      return _results;
    };

    AutocompleteListView.prototype.empty = function() {
      return this.$el.html('');
    };

    return AutocompleteListView;

  })(Backbone.View);

  AutocompleteView = (function(_super) {

    __extends(AutocompleteView, _super);

    function AutocompleteView() {
      return AutocompleteView.__super__.constructor.apply(this, arguments);
    }

    AutocompleteView.prototype.initialize = function(options) {
      this.textarea = options.textarea;
      this.list = options.autocompletelist;
      this.collections = options.collections;
      this.whitespace = new RegExp(/(\s)/);
      this.list.on('select', this.autocomplete, this);
      this.textarea.on('keyup', $.proxy(this.cursorMoved, this));
      return this.textarea.on('tap', $.proxy(this.cursorMoved, this));
    };

    AutocompleteView.prototype.autocomplete = function(word) {
      var afterWord, beforeWord, cursor, cushion, indices, text;
      text = this.textarea.val();
      cursor = this.caretPosition();
      indices = this.indicesOfWordAtIndex(text, cursor);
      beforeWord = text.substr(0, indices.beginning);
      afterWord = text.substr(indices.end, text.length);
      cushion = afterWord && afterWord[0].search(this.whitespace) === 0 ? '' : ' ';
      this.textarea.val(beforeWord + word + cushion + afterWord);
      this.textarea.caretTo(indices.beginning + word.length + cushion.length);
      this.textarea.focus();
      return this.cursorMoved();
    };

    AutocompleteView.prototype.insertCharacter = function(character) {
      var cursor, text;
      cursor = this.caretPosition();
      text = this.textarea.val();
      if (text.length === 0) {
        this.textarea.val(character).caretTo(1).focus();
        this.cursorMoved();
        return false;
      }
      character = this.applyCushion(character, cursor, text);
      this.textarea.val(text.substr(0, cursor) + character + text.substr(cursor, text.length));
      this.textarea.caretTo(cursor + character.length);
      this.textarea.focus();
      this.cursorMoved();
      return false;
    };

    AutocompleteView.prototype.cursorMoved = function() {
      var collection, cursor, firstLetter, word;
      cursor = this.caretPosition();
      word = this.wordAtIndex(this.textarea.val(), cursor);
      firstLetter = word[0];
      if (this.collections.hasOwnProperty(firstLetter)) {
        collection = this.collections[firstLetter];
        if (word.length === 1) {
          this.list.display(collection.top());
        } else {
          this.list.display(collection.namesStartingWith(word));
        }
        return this.trigger('autocompleting');
      } else {
        return this.finish();
      }
    };

    AutocompleteView.prototype.finish = function() {
      this.list.empty();
      return this.trigger('done');
    };

    AutocompleteView.prototype.indicesOfWordAtIndex = function(string, index) {
      var beginning, end, firstHalf, secondHalf;
      if (!string[index - 1] || string[index - 1].match(this.whitespace)) {
        return null;
      }
      firstHalf = string.substr(0, index);
      secondHalf = string.substr(index, string.length);
      beginning = firstHalf.regexLastIndexOf(this.whitespace) + 1;
      end = secondHalf.regexIndexOf(this.whitespace);
      if (end === -1) {
        end = string.length;
      } else {
        end += firstHalf.length;
      }
      return {
        beginning: beginning,
        end: end
      };
    };

    AutocompleteView.prototype.wordAtIndex = function(string, index) {
      var indices;
      indices = this.indicesOfWordAtIndex(string, index);
      if (indices) {
        return string.substr(indices.beginning, indices.end - indices.beginning);
      } else {
        return '';
      }
    };

    AutocompleteView.prototype.caretPosition = function() {
      return Fetch.getCaretPosition(this.textarea.get(0));
    };

    AutocompleteView.prototype.applyCushion = function(character, cursor, text) {
      var previousCharacter;
      if (cursor === 0) {
        return character;
      }
      previousCharacter = text[cursor - 1];
      if (previousCharacter.regexIndexOf(this.whitespace) !== 0) {
        character = ' ' + character;
      }
      return character;
    };

    return AutocompleteView;

  })(Backbone.View);

  DoItView = (function(_super) {

    __extends(DoItView, _super);

    function DoItView() {
      return DoItView.__super__.constructor.apply(this, arguments);
    }

    DoItView.prototype.template = _.template($('#do-it-template').html());

    DoItView.prototype.events = {
      'tap': 'tapped'
    };

    DoItView.prototype.bookTags = ['#books', '#book', '#read', '#toread', '#2read'];

    DoItView.prototype.musicTags = ['#music', '#listen', '#songs'];

    DoItView.prototype.moviesTags = ['#watch', '#movie', '#movies'];

    DoItView.prototype.groceryTags = ['#groceries', '#grocery', '#food'];

    DoItView.prototype.initialize = function() {
      var firstUrl, noteTags, noteUrls, text;
      $.embedly.defaults['key'] = 'd1e33a72bce84f1eb2f35a68c3d7dd40';
      text = this.model.get('text');
      noteTags = Fetch.findTags(text).map(function(tag) {
        return tag.toLowerCase();
      });
      noteUrls = Fetch.findUrls(text);
      if (noteUrls.length > 0) {
        firstUrl = noteUrls[0];
        $.embedly(firstUrl, {}, $.proxy(this.embedlySuccess, this));
        return;
      }
      if (this.findRelevantTags(this.bookTags, noteTags)) {
        this.findBooks(text);
        return;
      }
      if (this.findRelevantTags(this.musicTags, noteTags)) {
        this.findMusic(text);
        return;
      }
      if (this.findRelevantTags(this.moviesTags, noteTags)) {
        this.findMovies(text);
        return;
      }
      if (this.findRelevantTags(this.groceryTags, noteTags)) {
        this.findGroceries(text);
      }
    };

    DoItView.prototype.findRelevantTags = function(masterList, noteTags) {
      return _.any(masterList, function(tag) {
        return _.contains(noteTags, tag);
      });
    };

    DoItView.prototype.render = function(content) {
      this.$el.html(this.template(content));
      return this.contentURL = content.url;
    };

    DoItView.prototype.findBooks = function(query) {
      return this.findHelper(query, 'Books', this.successBooks);
    };

    DoItView.prototype.successBooks = function(xml) {
      var author, authors, firstItem, result, _i, _len, _ref;
      firstItem = $(xml).find('Item').first();
      console.log(xml);
      authors = [];
      _ref = firstItem.find('Author');
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        author = _ref[_i];
        authors.push($(author).text());
      }
      authors = authors.length > 0 ? "by " + (authors.join(' & ')) : '';
      result = {
        subtitle: authors,
        image: firstItem.find('SmallImage').find('URL').first().text(),
        title: firstItem.find('Title').text() || '',
        url: firstItem.find('DetailPageURL').text() || ''
      };
      if (result.title && result.url) {
        return this.render(result);
      }
    };

    DoItView.prototype.findMusic = function(query) {
      return this.findHelper(query, 'Music', this.successMusic);
    };

    DoItView.prototype.successMusic = function(xml) {
      var artist, artists, firstItem, result, _i, _len, _ref;
      firstItem = $(xml).find('Item').first();
      console.log(xml);
      artists = [];
      _ref = firstItem.find('Artist');
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        artist = _ref[_i];
        artists.push($(artist).text());
      }
      artists = artists.length > 0 ? "by " + (artists.join(' & ')) : '';
      result = {
        subtitle: artists,
        image: firstItem.find('SmallImage').find('URL').first().text(),
        title: firstItem.find('Title').text() || '',
        url: firstItem.find('DetailPageURL').text() || ''
      };
      if (result.title && result.url) {
        return this.render(result);
      }
    };

    DoItView.prototype.findMovies = function(query) {
      return this.findHelper(query, 'DVD', this.successMovies);
    };

    DoItView.prototype.successMovies = function(xml) {
      var actor, firstItem, result, topActor;
      firstItem = $(xml).find('Item').first();
      console.log(xml);
      topActor = firstItem.find('Actor').first().text();
      actor = topActor ? "starring " + topActor : '';
      result = {
        subtitle: actor,
        image: firstItem.find('SmallImage').find('URL').first().text(),
        title: firstItem.find('Title').text() || '',
        url: firstItem.find('DetailPageURL').text() || ''
      };
      if (result.title && result.url) {
        return this.render(result);
      }
    };

    DoItView.prototype.findGroceries = function(query) {
      return this.findHelper(query, 'Grocery', this.successGroceries);
    };

    DoItView.prototype.successGroceries = function(xml) {
      var firstItem, result;
      firstItem = $(xml).find('Item').first();
      console.log(xml);
      result = {
        subtitle: '',
        image: firstItem.find('SmallImage').find('URL').first().text(),
        title: firstItem.find('Title').text() || '',
        url: firstItem.find('DetailPageURL').text() || ''
      };
      if (result.title && result.url) {
        return this.render(result);
      }
    };

    DoItView.prototype.embedlySuccess = function(data) {
      switch (data.type) {
        case 'video':
          return this.embedlyVideo(data);
        case 'link':
          return this.embedlyLink(data);
        case 'photo':
          return this.embedlyPhoto(data);
        case 'rich':
          return this.embedlyRich(data);
        default:
          return console.log(data.type);
      }
    };

    DoItView.prototype.embedlyLink = function(data) {
      console.log(data);
      this.template = _.template($('#embedly-link-template').html());
      return this.render({
        title: data.title || '',
        subtitle: data.description || '',
        image: data.thumbnail_url || '',
        url: data.url || ''
      });
    };

    DoItView.prototype.embedlyVideo = function(data) {
      var height, src, width;
      width = $('#view-note-wrapper').width();
      height = width / data.width * data.height;
      src = this.getSrc(data.html);
      this.template = _.template($('#embedly-media-template').html());
      return this.render({
        title: data.title || '',
        subtitle: '',
        iframe: "<iframe src='" + src + "' width='" + width + "' height='" + height + "' frameborder='0' webkitAllowFullScreen mozallowfullscreen allowFullScreen></iframe>",
        url: src || ''
      });
    };

    DoItView.prototype.embedlyPhoto = function(data) {
      var height, src, width;
      console.log(data);
      width = $('#view-note-wrapper').width();
      height = width / data.width * data.height;
      src = data.url;
      this.template = _.template($('#embedly-media-template').html());
      return this.render({
        title: data.provider_name || '',
        subtitle: '',
        iframe: "<img src='" + src + "' width='" + width + "' height='" + height + "' />",
        url: src || ''
      });
    };

    DoItView.prototype.embedlyRich = function(data) {
      var height, html, src, width;
      console.log(data);
      width = $('#view-note-wrapper').width();
      height = data.height;
      src = this.getSrc(data.html);
      html = data.html.replace(/height="[^"]*"/g, "height=\"" + height + "\"").replace(/width="[^"]*"/g, "width=\"" + width + "\"");
      this.template = _.template($('#embedly-media-template').html());
      return this.render({
        title: data.title || '',
        subtitle: data.description || '',
        iframe: html || '',
        url: src || ''
      });
    };

    DoItView.prototype.getSrc = function(str) {
      return str.match(/src="[^"]*"/g)[0].slice(5, -1);
    };

    DoItView.prototype.findHelper = function(query, index, success) {
      var params;
      params = {
        SearchIndex: index,
        Keywords: this.keywordize(query)
      };
      return this.amazonRequest(_.extend(this.amazonDefaults, params), success);
    };

    DoItView.prototype.keywordize = function(query) {
      var words;
      words = _.compact(query.replace(Fetch.regexp.tags, '').replace(Fetch.regexp.contacts, '').replace(/- via/g, '').replace(Fetch.regexp.urls, '').split(' '));
      return words.join('+');
    };

    DoItView.prototype.amazonHost = 'ecs.amazonaws.com';

    DoItView.prototype.amazonSecret = 'eh4gfA7hxrTNBbL3ivDOKH7gCwJCKFFBI8yJA1PH';

    DoItView.prototype.amazonDefaults = {
      Service: 'AWSECommerceService',
      Version: '2011-08-01',
      AssociateTag: 'fetchnotes-20',
      Operation: 'ItemSearch',
      AWSAccessKeyId: 'AKIAJAJFQJ2DFMWUJI2Q',
      ResponseGroup: 'Images,Small'
    };

    DoItView.prototype.amazonTime = function() {
      var gmt, time;
      time = new Date();
      gmt = new Date(time.getTime() + (time.getTimezoneOffset() * 60000));
      return gmt.toISODate();
    };

    DoItView.prototype.amazonRequest = function(params, success) {
      var scopedSuccess, signedUrl;
      signedUrl = this.amazonURL(params);
      scopedSuccess = $.proxy(success, this);
      return Fetch.ajax({
        url: signedUrl,
        type: 'GET',
        success: scopedSuccess,
        error: function(xhr, ajaxOptions, thrownError) {
          return console.log(xhr);
        }
      });
    };

    DoItView.prototype.amazonURL = function(params) {
      var canonicalQuery, key, pairs, signature, signedUrl, stringToSign, _i, _len, _ref;
      params.Timestamp = this.amazonTime();
      pairs = [];
      _ref = Object.keys(params);
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        key = _ref[_i];
        pairs.push("" + key + "=" + params[key]);
      }
      pairs = this.encodeNameValuePairs(pairs);
      pairs.sort();
      canonicalQuery = pairs.join('&');
      stringToSign = "GET\n" + this.amazonHost + "\n/onca/xml\n" + canonicalQuery;
      signature = this.amazonSign(this.amazonSecret, stringToSign);
      return signedUrl = "http://" + this.amazonHost + "/onca/xml?" + canonicalQuery + "&Signature=" + signature;
    };

    DoItView.prototype.amazonSign = function(secret, message) {
      var b64hash, i, ihash, imsg, ipad, messageBytes, ohash, omsg, opad, secretBytes;
      messageBytes = str2binb(message);
      secretBytes = str2binb(secret);
      if (secretBytes.length > 16) {
        secretBytes = core_sha256(secretBytes, secret.length * chrsz);
      }
      ipad = Array(16);
      opad = Array(16);
      i = 0;
      while (i < 16) {
        ipad[i] = secretBytes[i] ^ 0x36363636;
        opad[i] = secretBytes[i] ^ 0x5C5C5C5C;
        i++;
      }
      imsg = ipad.concat(messageBytes);
      ihash = core_sha256(imsg, 512 + message.length * chrsz);
      omsg = opad.concat(ihash);
      ohash = core_sha256(omsg, 512 + 256);
      b64hash = binb2b64(ohash);
      return encodeURIComponent(b64hash);
    };

    DoItView.prototype.encodeNameValuePairs = function(pairs) {
      var i, index, name, pair, value;
      i = 0;
      while (i < pairs.length) {
        name = "";
        value = "";
        pair = pairs[i];
        index = pair.indexOf("=");
        if (index === -1) {
          name = pair;
        } else if (index === 0) {
          value = pair;
        } else {
          name = pair.substring(0, index);
          if (index < pair.length - 1) {
            value = pair.substring(index + 1);
          }
        }
        name = encodeURIComponent(decodeURIComponent(name));
        value = value.replace(/\+/g, "%20");
        value = encodeURIComponent(decodeURIComponent(value));
        pairs[i] = name + "=" + value;
        i++;
      }
      return pairs;
    };

    DoItView.prototype.tapped = function() {
      if (window.forge != null) {
        return forge.tabs.open(this.contentURL);
      } else {
        return alert(this.contentURL);
      }
    };

    return DoItView;

  })(Backbone.View);

  DialogView = (function(_super) {

    __extends(DialogView, _super);

    function DialogView() {
      return DialogView.__super__.constructor.apply(this, arguments);
    }

    DialogView.prototype.initialize = function() {
      if (Fetch.isAndroid) {
        this.initAndroid();
      }
      this.showPopUpMessage(this.createPopUpHeader("we love feedback!"), this.createPopUpContent("<p id='emailParagraph'>Find a bug or feature you'd like to see? Don't be shy, email us here & we'll get on it!</p>          <p>Has Fetchnotes made it to your homescreen? If so, we'd love a review!</p>"), 250, 300);
      return $(window).on('resize', $.proxy(this.handleResize, this));
    };

    DialogView.prototype.handleResize = function() {
      if (this.modalWindowElement) {
        this.modalWindowElement.style.left = (window.innerWidth - this.modalWindowElement.offsetWidth) / 2 + "px";
        return this.modalWindowElement.style.top = (window.innerHeight - this.modalWindowElement.offsetHeight) / 2 + "px";
      }
    };

    DialogView.prototype.createPopUpHeader = function(title) {
      this.modalWindowHeader = document.createElement("div");
      this.modalWindowHeader.className = "modalWindowHeader";
      this.modalWindowHeader.innerHTML = "<p>" + title + "</p>";
      return this.modalWindowHeader;
    };

    DialogView.prototype.initAndroid = function() {
      var oldHide, oldShow,
        _this = this;
      oldShow = this.showPopUpMessage;
      oldHide = this.hidePopUpMessage;
      this.showPopUpMessage = function(arg0, arg1, arg2, arg3) {
        Fetch.backButton.modal = _this;
        return oldShow.call(_this, arg0, arg1, arg2, arg3);
      };
      return this.hidePopUpMessage = function() {
        Fetch.backButton.modal = false;
        return oldHide.call(_this);
      };
    };

    DialogView.prototype.createPopUpContent = function(msg) {
      var closeBtn, emailBtn, rateBtn,
        _this = this;
      this.modalWindowContent = document.createElement("div");
      this.modalWindowContent.className = "modalWindowContent";
      this.modalWindowContent.innerHTML = "<p style='text-align:center; margin-top:10px;'>" + msg + "</p>";
      emailBtn = document.createElement("div");
      emailBtn.className = "emailBtn actionBtn";
      emailBtn.innerHTML = "<p>email us</p>";
      emailBtn.addEventListener(bc.events.end, function() {
        return _this.emailFetchnotes();
      }, false);
      rateBtn = document.createElement("div");
      rateBtn.className = "rateBtn actionBtn";
      rateBtn.innerHTML = "<p>feed a hungry puppy</p>        <p><span id='smaller'</span>(rate this version in the store)</p>";
      rateBtn.addEventListener(bc.events.end, function() {
        return _this.launchAppStore();
      }, false);
      closeBtn = document.createElement("div");
      closeBtn.className = "closeBtn";
      closeBtn.innerHTML = "<p>x</p>";
      closeBtn.addEventListener(bc.events.end, function() {
        return _this.hidePopUpMessage();
      }, false);
      this.modalWindowContent.appendChild(rateBtn);
      this.modalWindowContent.appendChild(emailBtn);
      this.modalWindowContent.appendChild(closeBtn);
      return this.modalWindowContent;
    };

    DialogView.prototype.showPopUpMessage = function(modalWindowHeader, modalWindowContent, width, height) {
      var _this = this;
      this.overlayElement = document.createElement("div");
      this.overlayElement.className = "modalOverlay";
      this.modalWindowElement = document.createElement("div");
      this.modalWindowElement.className = "modalWindow";
      this.modalWindowElement.style.width = width + "px";
      this.modalWindowElement.style.height = height + "px";
      this.modalWindowElement.style.left = (window.innerWidth - width) / 2 + "px";
      this.modalWindowElement.style.top = (window.innerHeight - height) / 2 + "px";
      this.modalWindowElement.appendChild(modalWindowHeader);
      this.modalWindowElement.appendChild(modalWindowContent);
      document.body.appendChild(this.overlayElement);
      document.body.appendChild(this.modalWindowElement);
      return setTimeout(function() {
        _this.modalWindowElement.style.opacity = 1;
        _this.overlayElement.style.opacity = 0.4;
        return _this.overlayElement.addEventListener(bc.events.end, _this.hidePopUpMessage, false);
      }, 300);
    };

    DialogView.prototype.hidePopUpMessage = function() {
      var _this = this;
      this.modalWindowElement.style.opacity = 0;
      this.overlayElement.style.opacity = 0;
      this.overlayElement.removeEventListener(bc.events.end, this.hidePopUpMessage, false);
      return setTimeout(function() {
        document.body.removeChild(_this.overlayElement);
        return document.body.removeChild(_this.modalWindowElement);
      }, 400);
    };

    DialogView.prototype.launchAppStore = function() {
      if (Fetch.isAndroid) {
        window.open('https://play.google.com/store/apps/details?id=com.fetchnotes.notes&feature=nav_result#?t=W251bGwsMSwyLDNd');
      } else {
        window.open("https://itunes.apple.com/us/app/fetchnotes/id515765678?mt=8&uo=4");
      }
      return this.hidePopUpMessage();
    };

    DialogView.prototype.emailFetchnotes = function() {
      window.open('mailto:support@fetchnotes.com');
      return this.hidePopUpMessage();
    };

    return DialogView;

  })(Backbone.View);

  YAY_DEBUG = false;

  EditNoteView = (function(_super) {

    __extends(EditNoteView, _super);

    function EditNoteView() {
      return EditNoteView.__super__.constructor.apply(this, arguments);
    }

    EditNoteView.prototype.el = $('#edit-note');

    EditNoteView.prototype.template = _.template($('#edit-note-template').html());

    EditNoteView.prototype.events = {
      'tap .back-button': 'back',
      'tap .save-button': 'saveNote',
      'tap .delete-button': 'deleteNote',
      'tap #view-note-wrapper': 'editMode',
      'tap #select-tags': 'selectTags',
      'tap #select-contacts': 'selectContacts',
      'focus #edit-note-text': 'scrollUp'
    };

    EditNoteView.prototype.initialize = function() {
      var list;
      this.newNote = Boolean(!this.model);
      this.elem = $('#edit-note-content');
      $('#edit-note-scroller').height($(window).height() - Fetch.headerHeight);
      this.render();
      if (!this.newNote) {
        mixpanel.track('view_note', {
          _id: this.model.get('id')
        });
      }
      if (Fetch.isAndroid) {
        this.touchfocus.call(this.textarea);
      }
      if (!this.newNote) {
        this.doit = new DoItView({
          el: $('#do-it-wrapper'),
          model: this.model
        });
      }
      list = new AutocompleteListView({
        el: $('#autocomplete-list')
      });
      this.autocomplete = new AutocompleteView({
        textarea: this.textarea,
        autocompletelist: list,
        collections: {
          '#': Fetch.notes.tags,
          '@': Fetch.notes.contacts
        }
      });
      this.autocomplete.on('done', $.proxy(this.doneAutocompleting, this));
      return this.autocomplete.on('autocompleting', $.proxy(this.startAutocompleting, this));
    };

    EditNoteView.prototype.render = function() {
      var data, filterNames, fullhtml, text;
      if (this.newNote) {
        filterNames = _.union(Fetch.notes.tags.selected, Fetch.notes.contacts.selected);
        text = filterNames.length > 0 ? filterNames.join(' ') + ' ' : '';
        fullhtml = '';
      } else {
        text = this.model.get('text');
        fullhtml = Fetch.HTMLize(text);
      }
      data = {
        text: text,
        fullhtml: fullhtml
      };
      this.elem.html(this.template(data));
      this.textarea = $('#edit-note-text');
      this.editNoteWrapper = $('#edit-note-wrapper');
      this.autocompleteButtonWrapper = $('#autocomplete-button-wrapper');
      this.backButton = $('#edit-note-back-button');
      this.deleteButton = $('#edit-note-delete-button');
      this.cancelButton = $('#edit-note-cancel-button');
      this.saveButton = $('#edit-note-save-button');
      if (this.newNote) {
        this.editMode();
      }
      return this;
    };

    EditNoteView.prototype.saveNote = function() {
      var text;
      text = this.textarea.val().trim();
      if (this.model) {
        this.model.save({
          text: text
        });
      } else if (text) {
        Fetch.notes.create({
          text: text
        });
      }
      return this.back();
    };

    EditNoteView.prototype.deleteNote = function() {
      this.model.destroy({
        save: {
          local: true,
          remote: true
        }
      });
      return this.back();
    };

    EditNoteView.prototype.back = function() {
      this.textarea.blur();
      bc.ui.backPage();
      return this.kill();
    };

    EditNoteView.prototype.editMode = function() {
      $('#view-note-wrapper').hide();
      $('#do-it-wrapper').hide();
      this.editNoteWrapper.show();
      $('#autocomplete-wrapper').show();
      this.textarea.caretToEnd().focus();
      this.backButton.hide();
      this.deleteButton.hide();
      this.cancelButton.show();
      return this.saveButton.show();
    };

    EditNoteView.prototype.scrollUp = function() {
      return window.scrollTo(0, 0);
    };

    EditNoteView.prototype.kill = function() {
      var $el;
      this.backButton.show();
      this.deleteButton.show();
      this.cancelButton.hide();
      this.saveButton.hide();
      this.elem.html('');
      $el = $(this.el);
      return $el.die().unbind('mousedown').unbind('touchstart');
    };

    EditNoteView.prototype.selectTags = function() {
      if (YAY_DEBUG) {
        console.log('select tags!');
      }
      return this.autocomplete.insertCharacter('#');
    };

    EditNoteView.prototype.selectContacts = function() {
      if (YAY_DEBUG) {
        console.log('select contacts!');
      }
      return this.autocomplete.insertCharacter('@');
    };

    EditNoteView.prototype.startAutocompleting = function() {
      this.editNoteWrapper.height('50');
      return this.autocompleteButtonWrapper.hide();
    };

    EditNoteView.prototype.doneAutocompleting = function() {
      this.editNoteWrapper.height('95');
      return this.autocompleteButtonWrapper.show();
    };

    EditNoteView.prototype.touchfocus = function() {
      var x, y,
        _this = this;
      if (window.forge) {
        y = this.position().top + this.height() / 2;
        x = this.position().left + this.width();
        return forge.internal.call('events.touch', {
          x: x,
          y: y
        }, function() {
          var dontFocus;
          dontFocus = ['edit-note-text', 'edit-note-back-button', 'edit-note-delete-button', 'edit-note-cancel-button', 'edit-note-save-button'];
          $('body').on('click', function(e) {
            if (YAY_DEBUG) {
              console.log("clicked! " + e.timeStamp);
            }
            if (!_.contains(dontFocus, e.target.id)) {
              return _this.focus();
            }
          });
          $('body').on('tap', function(e) {
            return console.log("tapped! " + e.timeStamp);
          });
          return $('#edit-note-text').on('blur', function(e) {
            return console.log("blurred! " + e.timeStamp);
          });
        }, function() {
          if (YAY_DEBUG) {
            return console.log('oh noes error');
          }
        });
      }
    };

    return EditNoteView;

  })(Backbone.View);

  SelectFiltersView = (function(_super) {

    __extends(SelectFiltersView, _super);

    function SelectFiltersView() {
      return SelectFiltersView.__super__.constructor.apply(this, arguments);
    }

    SelectFiltersView.prototype.el = $('#select-filters');

    SelectFiltersView.prototype.events = {
      'tap .back-button': 'back',
      'tap .save-button': 'done'
    };

    SelectFiltersView.prototype.initialize = function() {
      this.elem = '#select-filters-list';
      return this.render();
    };

    SelectFiltersView.prototype.render = function() {
      var filter, list, view, _i, _len, _ref, _results;
      list = $(this.elem);
      _ref = this.model;
      _results = [];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        filter = _ref[_i];
        view = new AutocompleteFilterView({
          model: filter
        });
        _results.push(list.append(view.render().el));
      }
      return _results;
    };

    SelectFiltersView.prototype.done = function() {
      return this.back();
    };

    SelectFiltersView.prototype.back = function() {
      bc.ui.backPage();
      return this.kill();
    };

    SelectFiltersView.prototype.kill = function() {
      var $el;
      $(this.elem).html('');
      $el = $(this.el);
      $el.die();
      $el.unbind('mousedown');
      return $el.unbind('touchstart');
    };

    return SelectFiltersView;

  })(Backbone.View);

  FilterListView = (function(_super) {

    __extends(FilterListView, _super);

    function FilterListView() {
      return FilterListView.__super__.constructor.apply(this, arguments);
    }

    FilterListView.prototype.initialize = function() {
      this.model.on('add', this.add, this);
      this.model.on('reset', this.empty, this);
      return this.model.fetch();
    };

    FilterListView.prototype.add = function(filter) {
      var index, previous, previousView, view;
      view = new FilterView({
        model: filter
      });
      filter.set('view', view);
      index = this.model.indexOf(filter);
      previous = this.model.at(index - 1);
      previousView = previous && previous.get('view');
      if (index === 0 || !previous || !previousView) {
        return this.$el.prepend(view.render().el);
      } else {
        return $(previousView.el).after(view.render().el);
      }
    };

    FilterListView.prototype.empty = function() {
      var _this = this;
      this.$el.html('');
      return this.model.each(function(f) {
        return _this.add(f);
      });
    };

    return FilterListView;

  })(Backbone.View);

  NoteListView = (function(_super) {

    __extends(NoteListView, _super);

    function NoteListView() {
      return NoteListView.__super__.constructor.apply(this, arguments);
    }

    NoteListView.prototype.initialize = function() {
      this.rendered = {};
      this.queued = {};
      this.model.on('add', this.add, this);
      this.model.on('reset', this.addAll, this);
      this.model.on('update', this.addMore, this);
      return this.model.fetch();
    };

    NoteListView.prototype.add = function(note) {
      var view;
      if (this.rendered.hasOwnProperty(note.cid)) {
        return;
      }
      view = new NoteView({
        model: note,
        list: this
      });
      return this.insertView(view);
    };

    NoteListView.prototype.insertView = function(view) {
      var index, previous, previousView;
      console.log("inserting: " + (view.model.get('text').slice(0, 20)));
      this.model.sort({
        silent: true
      });
      index = this.model.indexOf(view.model);
      previous = this.model.at(index - 1);
      previousView = previous && this.rendered[previous.cid];
      if (index === 0 || !previous || !previousView) {
        this.$el.prepend(view.render().el);
      } else {
        previousView.$el.after(view.render().el);
      }
      this.rendered[view.model.cid] = view;
      return delete this.queued[view.model.cid];
    };

    NoteListView.prototype.reinsert = function(view) {
      var model;
      model = view.model;
      if (this.queued.hasOwnProperty(model.cid)) {
        return;
      }
      this.queued[model.cid] = model;
      view.remove();
      delete this.rendered[model.cid];
      return this.add(model);
    };

    NoteListView.prototype.addAll = function() {
      this.$el.html('');
      this.rendered = {};
      return this.model.each(this.add, this);
    };

    NoteListView.prototype.addMore = function() {
      var _this = this;
      return this.model.each(function(note) {
        return _this.add(note);
      });
    };

    NoteListView.prototype.addChunk = function() {
      return this.model.getNext();
    };

    return NoteListView;

  })(Backbone.View);

  Fetch.AppView = (function(_super) {

    __extends(AppView, _super);

    function AppView() {
      return AppView.__super__.constructor.apply(this, arguments);
    }

    AppView.prototype.el = $('#fetchnotes');

    AppView.prototype.template = _.template($('#app-template').html());

    AppView.prototype.events = {
      'keyup #search-notes': 'search',
      'tap #add-note-button': 'newNote',
      'tap #drawer-button': 'toggleDrawer',
      'tap #list-end': 'showMore',
      'tap #feedback': 'showDialogView',
      'tap #logout': 'signOut'
    };

    AppView.prototype.initialize = function() {
      var button, _i, _len, _ref, _results;
      this.render();
      Fetch.headerHeight = $('header').first().height();
      this.sidebar.height($(window).height());
      this.scroller.height($(window).height() - Fetch.headerHeight);
      $(window).resize($.proxy(this.updateScrollersHeight, this));
      $('#username').html('@' + Fetch.user.attr.username);
      Fetch.db = new FakeDatabase;
      Fetch.notes = new NoteList([], {
        collectionName: 'notes'
      });
      Fetch.tagsList = new FilterListView({
        el: $('#tag-list'),
        model: Fetch.notes.tags
      });
      Fetch.contactsList = new FilterListView({
        el: $('#contact-list'),
        model: Fetch.notes.contacts
      });
      Fetch.NotesView = new NoteListView({
        el: $('#note-list'),
        model: Fetch.notes
      });
      if (window.forge) {
        forge.event.appResumed.addListener(function() {
          return mixpanel.track('app_loaded');
        });
      }
      this.tSearch = _.throttle(this.tSearch, 500);
      if (Fetch.isAndroid) {
        _ref = Fetch.androidButtons;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          button = _ref[_i];
          _results.push(button.init());
        }
        return _results;
      }
    };

    AppView.prototype.render = function() {
      $('#main-content').append(this.template({}));
      this.sidebar = $('#main-sidebar');
      this.scroller = $('#main-scroller');
      return this.input = $('#search-notes');
    };

    AppView.prototype.mpTimer = null;

    AppView.prototype.mpSearch = function(numresults, charlength) {
      if (this.searchTimer) {
        clearTimeout(this.searchTimer);
      }
      return this.searchTimer = setTimeout(function() {
        if (charlength) {
          return mixpanel.track('search', {
            results: numresults,
            length: charlength
          });
        }
      }, 500);
    };

    AppView.prototype.search = function(e) {
      var value;
      value = this.input.val();
      return Fetch.notes.search(value);
    };

    AppView.prototype.showMore = function() {
      return Fetch.notes.getNext();
    };

    AppView.prototype.newNote = function() {
      bc.ui.forwardPage($('#edit-note'), {
        transitionTime: 0
      });
      Fetch.editNote = new EditNoteView;
      Fetch.editNote.scrollUp();
      return false;
    };

    AppView.prototype.toggleDrawer = function() {
      return Fetch.drawer.toggle();
    };

    AppView.prototype.updateScrollersHeight = function() {
      this.sidebar.height($(window).height());
      return this.scroller.height($(window).height() - Fetch.headerHeight);
    };

    AppView.prototype.showDialogView = function() {
      Fetch.drawer.close();
      return new DialogView;
    };

    AppView.prototype.signOut = function() {
      return Fetch.user.logout({
        success: function() {
          return Kinvey.Store.Cached.clear({
            success: function() {
              var thing, thingsToClear, thingsToDelete, _i, _j, _len, _len1;
              thingsToDelete = ['app', 'sesh', 'url', 'drawer', 'sidebar', 'app', 'notes', 'tags', 'contacts', 'NotesView'];
              thingsToClear = ['#main-content', '#tag-list', '#contact-list'];
              Fetch.drawer.close();
              for (_i = 0, _len = thingsToDelete.length; _i < _len; _i++) {
                thing = thingsToDelete[_i];
                delete Fetch[thing];
              }
              for (_j = 0, _len1 = thingsToClear.length; _j < _len1; _j++) {
                thing = thingsToClear[_j];
                $(thing).html('');
              }
              alert('logout, biytach');
              return Fetch.redirect('login.html');
            },
            error: function(e) {
              return alert(e);
            }
          });
        },
        error: function(e) {
          return alert(e);
        }
      });
    };

    return AppView;

  })(Backbone.View);

  window.Fetch = Fetch;

  $(bc).on('viewfocus', function() {
    Fetch.user = Kinvey.getCurrentUser();
    if (!(Fetch.user != null)) {
      return Fetch.redirect('login.html');
    } else if (!(Fetch.app != null)) {
      Fetch.url = "" + Fetch.baseurl + "/authors/" + Fetch.user.attr.username;
      Fetch.drawer = new SlidingView('main-sidebar', 'main-body');
      Fetch.app = new Fetch.AppView;
      mixpanel.track('app_loaded');
      if (window.forge) {
        return forge.launchimage.hide();
      }
    }
  });

}).call(this);

