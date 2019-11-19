import {
  isEqualUint8,
  bytesToInt,
  bytesToHex,
  numberToPadToLengthDevidedBy
} from '../utils';
import { findByKey, isSimpleType } from './utils';
import {
  decryptAES,
  getEncryptionParams
} from '../crypto';
import MTProtoSchema from './MTProtoSchema.json';
import TLSchema from './TLSchema.json';

const nonAuthKeyID = new Uint8Array([0,0,0,0,0,0,0,0]);
export const parseMessage = async (msg, authKey = null) => {
  const authKeyID = msg.subarray(0, 8);
  const data =
    (isEqualUint8(authKeyID, nonAuthKeyID))
    ? await parseUnencryptedMessage(msg)
    : await parseEncryptedMessage(msg, authKey);
  return data;
};

const parseUnencryptedMessage = async (msg) => {
  const res = {
    auth_key_id: bytesToHex(msg.subarray(0, 8)),
    message_id: bytesToHex(msg.subarray(8, 16)),
    length: bytesToInt(msg.subarray(16, 20))
  };
  res.data = await parseUnencryptedPayload(msg.subarray(20));
  return res;
};

const parseEncryptedMessage = async (msg, authKey) => {
  const res = {
    auth_key_id: bytesToHex(msg.subarray(0, 8)),
    msg_key: msg.subarray(8, 24),
    encrypted_data: msg.subarray(24)
  };
  const { aes_key, aes_iv } = await getEncryptionParams({
    authKey,
    inputMsgKey: res.msg_key,
    isOutgoingMsg: false
  });
  const decrypted = await decryptAES(res.encrypted_data, aes_key, aes_iv);

  res.message = {
    salt: decrypted.subarray(0, 8),
    session_id: decrypted.subarray(8, 16),
    msg_id: bytesToHex(decrypted.subarray(16, 24)),
    seq_no: bytesToInt(decrypted.subarray(24, 28)),
    message_data_length: bytesToInt(decrypted.subarray(28, 32)),
  };
  res.message.data = await parseUnencryptedPayload(
    decrypted.subarray(32, 32 + res.message.message_data_length)
  );

  return res;
};

export const parseUnencryptedPayload = async (payload) => {
  const typeId = bytesToInt(payload.subarray(0, 4));
  const type = getShcemaType(typeId);
  const [res,] = parseConstructor({
    bytes: payload,
    offset: 0,
    type
  });
  return res;
};

const parseConstructor = ({ bytes, offset, typeName, type }) => {
  if (typeName === "Object") {
    const typeId = bytesToInt(bytes.subarray(offset, offset + 4));
    type = getShcemaType(typeId);
  }
  if (!typeName && type) {
    typeName = type.type;
  }
  // If this is not a bare type, skip 4 bytes for identifier
  if (typeName[0] === typeName[0].toUpperCase() && typeName[0] !== "%") {
    offset += 4;
  }
  // If this bare type has % in front, remove it
  if (typeName[0] === "%") {
    typeName = typeName.slice(1);
  }
  // If this is a vector, parse it as vector
  if (typeName.slice(0, 6).toLowerCase() === "vector") {
    return parseVector(bytes, offset, typeName);
  }
  // If this is a simple value, parse it
  if (isSimpleType(typeName)) {
    return parseSimpleType(typeName, bytes, offset);
  }

  // Now we have a constructor, recurse on it's params
  type = (type) ? type : getShcemaType(typeName);
  const params = {};
  for(let i = 0; i < type.params.length; i++) {
    const p = type.params[i];
    const [value, newOffset] = parseConstructor({bytes, offset, typeName: p.type});
    params[p.name] = value;
    offset = newOffset;
  }
  return [Object.assign({}, type, { params }), offset];
};

const getShcemaType = (nameOrId) => {
  if (typeof nameOrId === "string") {
    nameOrId = nameOrId[0].toUpperCase() + nameOrId.slice(1);
    let res = MTProtoSchema.constructors.find(findByKey('type', nameOrId));
    if (res) return res;
    res = TLSchema.constructors.find(findByKey('type', nameOrId));
    if (res) return res;

    throw(`Couldn't parse a type with name ${nameOrId}`);
  } else {
    nameOrId = nameOrId.toString();
    let res = MTProtoSchema.constructors.find(findByKey('id', nameOrId));
    if (res) return res;
    res = TLSchema.constructors.find(findByKey('id', nameOrId));
    if (res) return res;

    throw(`Couldn't parse a type with id ${nameOrId}`);
  }
};

const parseSimpleType = (name, bytes, offset) => {
  let res;
  switch(name) {
    case "int":
      res = bytesToInt(bytes.subarray(offset, offset + 4));
      return [res, offset + 4];
    case "long":
      res = bytes.subarray(offset, offset + 8);
      return [res, offset + 8];
    case "double":
      res = bytes.subarray(offset, offset + 8);
      return [res, offset + 8];
    case "string":
      return unserializeString(bytes, offset);
    case "bytes":
      return unserializeString(bytes, offset);
    case "int128":
      res = bytes.slice(offset, offset + 16);
      return [res, offset + 16];
    case "int256":
      res = bytes.slice(offset, offset + 32);
      return [res, offset + 32];
    default:
      throw(`Failed to parse type: ${name}`);
  }
};

const parseVector = (bytes, offset, typeName) => {
  // Get the type of the array element
  const t = typeName.slice(7, -1);

  const len = bytesToInt(bytes.subarray(offset, offset + 4));
  offset += 4;

  const res = [];
  for (let i = 0; i < len; i++) {
    const [item, newOffset] = parseConstructor({bytes, offset, typeName: t});
    res.push(item);
    offset = newOffset;
  }
  return [res, offset];
};

const unserializeString = (bytes, offset) => {
  const len = bytes[offset];
  let totalLen = 0;
  let content;
  if (len === 254) {
    const realLen = bytes[offset + 1] * 1 + bytes[offset + 2] * 256 + bytes[offset + 3] * 4096;
    totalLen = 4 + realLen;
    content = bytes.slice(offset + 4, offset + totalLen);
  } else {
    totalLen = 1 + len;
    content = bytes.slice(offset + 1, offset + totalLen);
  }
  totalLen += numberToPadToLengthDevidedBy(4, totalLen);
  return [content, offset + totalLen];
};
