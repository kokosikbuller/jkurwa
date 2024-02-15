const fs = require("fs");
// const jksreader = require("jksreader");

const complain = require("./complain");
const Priv = require("../models/Priv");
const Certificate = require("../models/Certificate");

function reader(buf, pos) {
  return { buf: buf, pos: pos || 0 };
}

function U32(inst) {
  var ret = inst.buf.readUInt32BE(inst.pos);
  inst.pos += 4;
  return ret;
}
function U16(inst) {
  var ret = inst.buf.readUInt16BE(inst.pos);
  inst.pos += 2;
  return ret;
}
function BIN(inst, len) {
  var ret = inst.buf.slice(inst.pos, inst.pos + len);
  inst.pos += len;
  return ret;
}
function STR(inst, len) {
  return BIN(inst, len).toString();
}

function readCert(_jks) {
  var type = STR(_jks, U16(_jks));
  var data = BIN(_jks, U32(_jks));
  return { type: type, data: data };
}

function readKey(_jks) {
  var name = STR(_jks, U16(_jks));
  U32(_jks); // skip timestamp high
  U32(_jks); // skip timestamp low
  var key_data = BIN(_jks, U32(_jks)).slice(0x18); // drop header

  var chain = U32(_jks);
  var certs = [];
  for (var j = 0; j < chain; j++) {
    var cert = readCert(_jks);
    if (cert.type === "X.509") {
      certs.push(cert.data);
    }
  }
  return { key: key_data, certs: certs, name: name };
}

var MAGIC_JKS = 0xfeedfeed;
function parse(jks) {
  var _jks = reader(jks);
  var magic = U32(_jks);
  if (magic !== MAGIC_JKS) {
    return null;
  }
  var version = U32(_jks);
  if (version !== 2) {
    return null;
  }
  var entries = U32(_jks);
  var material = [];
  for (var i = 0; i < entries; i++) {
    var tag = U32(_jks);
    if (tag === 1) {
      material.push(readKey(_jks));
    }
    if (tag === 2) {
      material.push(readCert(_jks));
    }
  }
  return {
    format: "jks",
    material: material,
  };
}

function loadJks(ret, store, password) {
  // if (!password) {
  //   throw new Error("JKS file format requires password to be opened");
  // }
  // for (let part of store.material) {
  //   const buf = jksreader.decode(part.key, password.toString());
  //   if (!buf) {
  //     throw new Error("Cant load key from store, check password");
  //   }
  //   const rawStore = Priv.from_asn1(buf, true);
  //   for (let cert of part.certs) {
  //     ret.push({ cert: Certificate.from_pem(cert) });
  //   }
  //   for (let priv of rawStore.keys) {
  //     ret.push({ priv });
  //   }
  // }
  // return ret;
}

function load(keyinfo, algo) {
  let ret = [];
  if (keyinfo.priv && keyinfo.priv.type === "Priv") {
    ret.push({ priv: keyinfo.priv });
  }
  if (keyinfo.cert && keyinfo.cert.format === "x509") {
    ret.push({ cert: keyinfo.cert });
  }
  if (keyinfo.privPem) {
    ret.push({ priv: Priv.from_pem(keyinfo.privPem) });
  }
  if (keyinfo.certPem) {
    ret.push({ cert: Certificate.from_pem(keyinfo.certPem) });
  }

  let keyBuffers = keyinfo.keyBuffers || [];
  if (keyinfo.privPath) {
    complain("keyinfo.privPath is deprecated and would be removed");
    let keyPaths =
      typeof keyinfo.privPath === "string"
        ? [keyinfo.privPath]
        : keyinfo.privPath || [];

    keyBuffers = [
      ...keyBuffers,
      ...keyPaths.map((path) => fs.readFileSync(path)),
    ];
  }
  let certBuffers = keyinfo.certBuffers || [];
  if (keyinfo.certPath) {
    complain("keyinfo.certPath is deprecated and would be removed");
    let certPaths =
      typeof keyinfo.certPath === "string"
        ? [keyinfo.certPath]
        : keyinfo.certPath || [];
    certBuffers = [
      ...certBuffers,
      ...certPaths.map((path) => fs.readFileSync(path)),
    ];
  }

  keyBuffers.forEach((buf) => {
    // detect garbage in file header (meeedok)
    const content = buf[0] === 0x51 ? buf.slice(6) : buf;
    // const jksStore = jksreader.parse(content);
    const jksStore = parse(content);
    if (jksStore) {
      return loadJks(ret, jksStore, keyinfo.password);
    }
    let store;
    try {
      store = Priv.from_protected(content, keyinfo.password, algo);
    } catch (ignore) {
      throw new Error("Cant load key from store");
    }
    store.keys.forEach((priv) => ret.push({ priv }));
    store.certs.forEach((cert) =>
      ret.push({ cert: Certificate.from_asn1(cert) })
    );
  });

  certBuffers.forEach((cert) => ret.push({ cert: Certificate.from_pem(cert) }));
  return ret;
}
module.exports = load;
module.exports.loadJks = loadJks;
