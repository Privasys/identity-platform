// Minimal QR Code generator (byte mode), adapted from Project Nayuki's
// QR Code generator (MIT License). Produces an SVG string for a text payload.
// Self-contained, no dependencies.
var PrivasysQR = (function () {
  "use strict";

  // ECC levels: ordinal used for table lookup, formatBits used on the symbol.
  var ECC = {
    L: { ordinal: 0, formatBits: 1 },
    M: { ordinal: 1, formatBits: 0 },
    Q: { ordinal: 2, formatBits: 3 },
    H: { ordinal: 3, formatBits: 2 }
  };

  var ECC_CODEWORDS_PER_BLOCK = [
    [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
  ];
  var NUM_ERROR_CORRECTION_BLOCKS = [
    [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
  ];

  function toUtf8(str) {
    if (typeof TextEncoder !== "undefined") return Array.prototype.slice.call(new TextEncoder().encode(str));
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 128) out.push(c);
      else if (c < 2048) out.push(192 | (c >> 6), 128 | (c & 63));
      else out.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63));
    }
    return out;
  }

  function getNumRawDataModules(ver) {
    var result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var numAlign = Math.floor(ver / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (ver >= 7) result -= 36;
    }
    return result;
  }
  function getNumDataCodewords(ver, ecl) {
    return Math.floor(getNumRawDataModules(ver) / 8) -
      ECC_CODEWORDS_PER_BLOCK[ecl.ordinal][ver] * NUM_ERROR_CORRECTION_BLOCKS[ecl.ordinal][ver];
  }
  function getAlignmentPatternPositions(ver) {
    if (ver === 1) return [];
    var numAlign = Math.floor(ver / 7) + 2;
    var step = (ver === 32) ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
    var result = [6];
    for (var pos = ver * 4 + 10; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
    return result;
  }

  // Reed-Solomon over GF(2^8) with QR's primitive polynomial 0x11D.
  function rsMultiply(x, y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11D);
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xFF;
  }
  function rsComputeDivisor(degree) {
    var result = [];
    for (var i = 0; i < degree - 1; i++) result.push(0);
    result.push(1);
    var root = 1;
    for (var i = 0; i < degree; i++) {
      for (var j = 0; j < result.length; j++) {
        result[j] = rsMultiply(result[j], root);
        if (j + 1 < result.length) result[j] ^= result[j + 1];
      }
      root = rsMultiply(root, 0x02);
    }
    return result;
  }
  function rsComputeRemainder(data, divisor) {
    var result = divisor.map(function () { return 0; });
    for (var k = 0; k < data.length; k++) {
      var factor = data[k] ^ result.shift();
      result.push(0);
      for (var i = 0; i < divisor.length; i++) result[i] ^= rsMultiply(divisor[i], factor);
    }
    return result;
  }

  function appendBits(val, len, bb) {
    for (var i = len - 1; i >= 0; i--) bb.push((val >>> i) & 1);
  }

  function QrCode(version, ecl, dataCodewords, forceMask) {
    this.version = version;
    this.ecl = ecl;
    this.size = version * 4 + 17;
    var i, row = [];
    for (i = 0; i < this.size; i++) row.push(false);
    this.modules = [];
    this.isFunction = [];
    for (i = 0; i < this.size; i++) { this.modules.push(row.slice()); this.isFunction.push(row.slice()); }

    this.drawFunctionPatterns();
    var allCodewords = this.addEccAndInterleave(dataCodewords);
    this.drawCodewords(allCodewords);

    var mask;
    if (forceMask != null && forceMask >= 0) {
      mask = forceMask;
    } else {
      var minPenalty = Infinity;
      mask = 0;
      for (i = 0; i < 8; i++) {
        this.applyMask(i);
        this.drawFormatBits(i);
        var penalty = this.getPenaltyScore();
        if (penalty < minPenalty) { mask = i; minPenalty = penalty; }
        this.applyMask(i); // undo
      }
    }
    this.mask = mask;
    this.applyMask(mask);
    this.drawFormatBits(mask);
    this.isFunction = null;
  }

  QrCode.prototype.getModule = function (x, y) { return this.modules[y][x]; };
  QrCode.prototype.setFunctionModule = function (x, y, isDark) {
    this.modules[y][x] = isDark; this.isFunction[y][x] = true;
  };

  QrCode.prototype.drawFunctionPatterns = function () {
    var i, size = this.size;
    for (i = 0; i < size; i++) {
      this.setFunctionModule(6, i, i % 2 === 0);
      this.setFunctionModule(i, 6, i % 2 === 0);
    }
    this.drawFinderPattern(3, 3);
    this.drawFinderPattern(size - 4, 3);
    this.drawFinderPattern(3, size - 4);

    var alignPos = getAlignmentPatternPositions(this.version);
    var numAlign = alignPos.length;
    for (i = 0; i < numAlign; i++) {
      for (var j = 0; j < numAlign; j++) {
        if (!((i === 0 && j === 0) || (i === 0 && j === numAlign - 1) || (i === numAlign - 1 && j === 0)))
          this.drawAlignmentPattern(alignPos[i], alignPos[j]);
      }
    }
    this.drawFormatBits(0);
    this.drawVersion();
  };

  QrCode.prototype.drawFormatBits = function (mask) {
    var data = (this.ecl.formatBits << 3) | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ 0x5412;
    var i2;
    for (i2 = 0; i2 <= 5; i2++) this.setFunctionModule(8, i2, getBit(bits, i2));
    this.setFunctionModule(8, 7, getBit(bits, 6));
    this.setFunctionModule(8, 8, getBit(bits, 7));
    this.setFunctionModule(7, 8, getBit(bits, 8));
    for (i2 = 9; i2 < 15; i2++) this.setFunctionModule(14 - i2, 8, getBit(bits, i2));

    var size = this.size;
    for (i2 = 0; i2 < 8; i2++) this.setFunctionModule(size - 1 - i2, 8, getBit(bits, i2));
    for (i2 = 8; i2 < 15; i2++) this.setFunctionModule(8, size - 15 + i2, getBit(bits, i2));
    this.setFunctionModule(8, size - 8, true);
  };

  QrCode.prototype.drawVersion = function () {
    if (this.version < 7) return;
    var rem = this.version;
    for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
    var bits = (this.version << 12) | rem;
    for (i = 0; i < 18; i++) {
      var bit = getBit(bits, i);
      var a = this.size - 11 + (i % 3), b = Math.floor(i / 3);
      this.setFunctionModule(a, b, bit);
      this.setFunctionModule(b, a, bit);
    }
  };

  QrCode.prototype.drawFinderPattern = function (x, y) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) {
        var dist = Math.max(Math.abs(dx), Math.abs(dy));
        var xx = x + dx, yy = y + dy;
        if (0 <= xx && xx < this.size && 0 <= yy && yy < this.size)
          this.setFunctionModule(xx, yy, dist !== 2 && dist !== 4);
      }
    }
  };

  QrCode.prototype.drawAlignmentPattern = function (x, y) {
    for (var dy = -2; dy <= 2; dy++)
      for (var dx = -2; dx <= 2; dx++)
        this.setFunctionModule(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  };

  QrCode.prototype.addEccAndInterleave = function (data) {
    var ver = this.version, ecl = this.ecl;
    var numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecl.ordinal][ver];
    var blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecl.ordinal][ver];
    var rawCodewords = Math.floor(getNumRawDataModules(ver) / 8);
    var numShortBlocks = numBlocks - rawCodewords % numBlocks;
    var shortBlockLen = Math.floor(rawCodewords / numBlocks);

    var blocks = [];
    var rsDiv = rsComputeDivisor(blockEccLen);
    var k = 0;
    for (var i = 0; i < numBlocks; i++) {
      var datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
      var dat = data.slice(k, k + datLen);
      k += datLen;
      var ecc = rsComputeRemainder(dat, rsDiv);
      if (i < numShortBlocks) dat.push(0);
      blocks.push(dat.concat(ecc));
    }

    var result = [];
    for (var j = 0; j < blocks[0].length; j++) {
      for (var bi = 0; bi < blocks.length; bi++) {
        if (j !== shortBlockLen - blockEccLen || bi >= numShortBlocks)
          result.push(blocks[bi][j]);
      }
    }
    return result;
  };

  QrCode.prototype.drawCodewords = function (data) {
    var size = this.size, i = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        for (var jj = 0; jj < 2; jj++) {
          var x = right - jj;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  };

  QrCode.prototype.applyMask = function (mask) {
    for (var y = 0; y < this.size; y++) {
      for (var x = 0; x < this.size; x++) {
        var invert;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = (x * y) % 2 + (x * y) % 3 === 0; break;
          case 6: invert = ((x * y) % 2 + (x * y) % 3) % 2 === 0; break;
          case 7: invert = ((x + y) % 2 + (x * y) % 3) % 2 === 0; break;
        }
        if (!this.isFunction[y][x] && invert) this.modules[y][x] = !this.modules[y][x];
      }
    }
  };

  QrCode.prototype.getPenaltyScore = function () {
    var size = this.size, result = 0, x, y;
    var modules = this.modules;
    // Adjacent modules in rows/columns
    for (y = 0; y < size; y++) {
      var runColor = false, runX = 0;
      var runHistory = [0, 0, 0, 0, 0, 0, 0];
      for (x = 0; x < size; x++) {
        if (modules[y][x] === runColor) {
          runX++;
          if (runX === 5) result += 3;
          else if (runX > 5) result++;
        } else {
          this.finderPenaltyAddHistory(runX, runHistory);
          if (!runColor) result += this.finderPenaltyCountPatterns(runHistory) * 40;
          runColor = modules[y][x]; runX = 1;
        }
      }
      result += this.finderPenaltyTerminateAndCount(runColor, runX, runHistory) * 40;
    }
    for (x = 0; x < size; x++) {
      var runColorV = false, runY = 0;
      var runHistoryV = [0, 0, 0, 0, 0, 0, 0];
      for (y = 0; y < size; y++) {
        if (modules[y][x] === runColorV) {
          runY++;
          if (runY === 5) result += 3;
          else if (runY > 5) result++;
        } else {
          this.finderPenaltyAddHistory(runY, runHistoryV);
          if (!runColorV) result += this.finderPenaltyCountPatterns(runHistoryV) * 40;
          runColorV = modules[y][x]; runY = 1;
        }
      }
      result += this.finderPenaltyTerminateAndCount(runColorV, runY, runHistoryV) * 40;
    }
    // 2x2 blocks
    for (y = 0; y < size - 1; y++) {
      for (x = 0; x < size - 1; x++) {
        var c = modules[y][x];
        if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) result += 3;
      }
    }
    // Balance of dark/light
    var dark = 0;
    for (y = 0; y < size; y++) for (x = 0; x < size; x++) if (modules[y][x]) dark++;
    var total = size * size;
    var k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * 10;
    return result;
  };

  QrCode.prototype.finderPenaltyCountPatterns = function (runHistory) {
    var n = runHistory[1];
    var core = n > 0 && runHistory[2] === n && runHistory[3] === n * 3 && runHistory[4] === n && runHistory[5] === n;
    return (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0) +
           (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0);
  };
  QrCode.prototype.finderPenaltyTerminateAndCount = function (currentRunColor, currentRunLength, runHistory) {
    if (currentRunColor) {
      this.finderPenaltyAddHistory(currentRunLength, runHistory);
      currentRunLength = 0;
    }
    currentRunLength += this.size;
    this.finderPenaltyAddHistory(currentRunLength, runHistory);
    return this.finderPenaltyCountPatterns(runHistory);
  };
  QrCode.prototype.finderPenaltyAddHistory = function (currentRunLength, runHistory) {
    if (runHistory[0] === 0) currentRunLength += this.size;
    runHistory.pop();
    runHistory.unshift(currentRunLength);
  };

  function getBit(x, i) { return ((x >>> i) & 1) !== 0; }

  function encodeText(text, ecl, forceMask) {
    var bytes = toUtf8(text);
    var dataLen = bytes.length;
    var version;
    for (version = 1; ; version++) {
      var capacityBits = getNumDataCodewords(version, ecl) * 8;
      var ccBits = version < 10 ? 8 : 16;
      var usedBits = 4 + ccBits + 8 * dataLen;
      if (usedBits <= capacityBits) break;
      if (version >= 40) throw new Error("Data too long");
    }
    var capacityBits2 = getNumDataCodewords(version, ecl) * 8;
    var ccBits2 = version < 10 ? 8 : 16;
    var bb = [];
    appendBits(0x4, 4, bb);
    appendBits(dataLen, ccBits2, bb);
    for (var i = 0; i < bytes.length; i++) appendBits(bytes[i], 8, bb);
    appendBits(0, Math.min(4, capacityBits2 - bb.length), bb);
    appendBits(0, (8 - bb.length % 8) % 8, bb);
    for (var padByte = 0xEC; bb.length < capacityBits2; padByte ^= 0xEC ^ 0x11) appendBits(padByte, 8, bb);
    var dataCodewords = [];
    for (i = 0; i < bb.length / 8; i++) dataCodewords.push(0);
    for (i = 0; i < bb.length; i++) dataCodewords[i >>> 3] |= bb[i] << (7 - (i & 7));
    return new QrCode(version, ecl, dataCodewords, forceMask);
  }

  // The Privasys mark on a white rounded tile, laid over the centre of the
  // code: 24% of its side, quiet zone excluded. Codes that carry it are made
  // at level H (up to 30% recovered), so the modules under it are read back
  // from the rest.
  function logoSvg(x, y, side) {
    var inset = side * 0.14, mark = side - inset * 2;
    return '<g shape-rendering="geometricPrecision">' +
      '<rect x="' + x + '" y="' + y + '" width="' + side + '" height="' + side + '" rx="' + (side * 0.18) + '" fill="#fff"/>' +
      '<svg x="' + (x + inset) + '" y="' + (y + inset) + '" width="' + mark + '" height="' + mark + '" viewBox="0 0 500 500">' +
      '<defs><linearGradient id="qrpg" y2="1"><stop offset="21%" stop-color="#34E89E"/><stop offset="42%" stop-color="#12B06E"/></linearGradient>' +
      '<linearGradient id="qrpb" x1="1" y1="1" x2="0" y2="0"><stop offset="21%" stop-color="#00BCF2"/><stop offset="42%" stop-color="#00A0EB"/></linearGradient></defs>' +
      '<path d="M100 0H450L0 450V100A100 100 0 0 1 100 0Z" fill="url(#qrpg)"/>' +
      '<path d="M500 50V400A100 100 0 0 1 400 500H50L500 50Z" fill="url(#qrpb)"/>' +
      '<polygon fill="#fff" points="0,500 50,500 500,50 500,0"/></svg></g>';
  }

  function toSvg(qr, border, light, dark, logo) {
    var parts = [];
    for (var y = 0; y < qr.size; y++)
      for (var x = 0; x < qr.size; x++)
        if (qr.getModule(x, y)) parts.push("M" + (x + border) + "," + (y + border) + "h1v1h-1z");
    var dim = qr.size + border * 2;
    var side = qr.size * 0.24, at = border + (qr.size - side) / 2;
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + dim + ' ' + dim +
      '" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="' + light +
      '"/><path d="' + parts.join(" ") + '" fill="' + dark + '"/>' +
      (logo ? logoSvg(at, at, side) : '') + '</svg>';
  }

  return {
    ECC: ECC,
    encode: encodeText,
    svg: function (text, opts) {
      opts = opts || {};
      var ecl = ECC[opts.ecc || "M"];
      var qr = encodeText(text, ecl);
      // A logo covers modules, which only level H is sure to recover.
      return toSvg(qr, opts.border == null ? 4 : opts.border, opts.light || "#ffffff", opts.dark || "#000000",
        !!opts.logo && ecl === ECC.H);
    }
  };
})();
