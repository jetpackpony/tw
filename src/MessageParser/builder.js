import {
  isEqualUint8,
  bytesToInt,
  intToBytes,
  bytesToHex,
  hexToBytes,
  concatUint8,
  numberToPadToLengthDevidedBy,
} from '../utils';
import { findByKey, isSimpleType, isBareType } from './utils';
import {
  encryptAES,
  getEncryptionParams,
  getRandomBytes
} from '../crypto';
import MTProtoSchema from './MTProtoSchema.json';
import TLSchema from './TLSchema.json';

export const buildUnencryptedMessage = async (msg, message_id) => {
  const buffer = [];
  buffer.push(new Uint8Array([0,0,0,0,0,0,0,0]));
  buffer.push(hexToBytes(message_id, true));
  const payload = await buildMessagePayload(msg);
  buffer.push(intToBytes(payload.length));
  buffer.push(payload);

  return concatUint8(buffer);
};

export const buildEncryptedMessage = async (msg, params) => {
  const payload = await buildMessagePayload(msg);
  const body = await buildMessageBodyToEncrypt(payload, params);
  const { msg_key, encrypted } = await encryptMessageBody(body, params.authKey);

  return concatUint8([params.auth_key_id, msg_key, encrypted]);
};

export const buildMessageBodyToEncrypt = async (
  payload,
  {
    salt,
    session_id,
    message_id,
    seq_no
  }
) => {
  let buffer = [];
  buffer.push(salt);
  buffer.push(session_id);
  buffer.push(hexToBytes(message_id, true));
  buffer.push(intToBytes(seq_no));
  buffer.push(intToBytes(payload.length));
  buffer.push(payload);
  buffer = concatUint8(buffer);
  
  const numToPad = numberToPadToLengthDevidedBy(16, buffer.length, 12);
  const padding = await getRandomBytes(numToPad);

  return concatUint8([buffer, padding]);
};

const encryptMessageBody = async (body, authKey) => {
  const { msg_key, aes_key, aes_iv } = await getEncryptionParams({
    authKey: authKey,
    messageBytes: body,
    isOutgoingMsg: true
  });

  const encrypted = await encryptAES(body, aes_key, aes_iv);

  return { msg_key, encrypted };
};

export const buildMessagePayload = async (msg, typeName) => {
  let buffer = [];

  if (!msg.method && !msg.predicate) {
    throw(`Couldn't deal with the message: '${JSON.stringify(msg)}'`);
  }

  const type =
    (msg.method)
      ? getSchemaTypeForMethod(msg.method)
      : getSchemaTypeForConstructor(msg.predicate);

  // If this is not a bare type, add type id
  if (!typeName || !isBareType(typeName)) {
    buffer.push(intToBytes(type.id));
  }
  
  buffer = buffer.concat(
    type.params.map((p) => {
      const value = msg.params[p.name];

      // is simple type
      if (isSimpleType(p.type)) {
        return serializeSimpleType(p.type, value);
      }

      // is Object for message and gzipped
      if (p.type === "Object") {
        return value;
      }

      // is vector
      if (p.type.slice(0, 6).toLowerCase() === "vector") {
        return serializeVector(p.type, value);
      }

      // else is another constructor
      return buildMessagePayload(value);
    })
  );

  return concatUint8(buffer);
};

const getSchemaTypeForMethod = (methodName) => {
  let res = MTProtoSchema.methods.find(findByKey('method', methodName));
  if (res) return res;
  res = TLSchema.methods.find(findByKey('method', methodName));
  if (res) return res;

  throw (`Couldn't parse a method with name ${methodName}`);
};

const getSchemaTypeForConstructor = (predicate) => {
  let res = MTProtoSchema.constructors.find(findByKey('predicate', predicate));
  if (res) return res;
  res = TLSchema.constructors.find(findByKey('predicate', predicate));
  if (res) return res;

  throw (`Couldn't parse a predicate with name ${predicate}`);
};

const serializeSimpleType = (typeName, value) => {
  switch(typeName) {
    case "int":
      return intToBytes(value);
    case "long":
    case "double":
    case "int128":
    case "int256":
      return value;
    case "string":
    case "bytes":
      return serializeString(value);
    default:
      throw(`Failed to parse type: ${typeName}`);
  }
};

const serializeVector = (typeName, values) => {
  let buffer = [];
  if (!isBareType(typeName)) {
    buffer.push(intToBytes(481674261));
  }
  buffer.push(intToBytes(values.length));

  // Get the type of the array element
  const t = typeName.slice(7, -1);

  buffer = buffer.concat(
    values.map((val) => {
      // is simple type
      if (isSimpleType(t)) {
        return serializeSimpleType(t, val);
      }

      // is Object for message and gzipped
      if (p.type === "Object") {
        return val;
      }

      // is vector
      if (t.slice(0, 6).toLowerCase() === "vector") {
        return serializeVector(t, val);
      }

      // else is another constructor
      return buildMessagePayload(value);
    })
  );

  return concatUint8(buffer);
};

const serializeString = (bytes) => {
  const len = bytes.length;
  let header = [];
  if (len <= 253) {
    header.push(len);
  } else {
    header.push(254);
    header.push(len & 0xff);
    header.push((len >> 8) & 0xff);
    header.push((len >> 16) & 0xff);
  }
  const padNum = numberToPadToLengthDevidedBy(4, (header.length + bytes.length));
  let padding = (new Array(padNum)).fill(0);
  const buf = new ArrayBuffer(header.length + bytes.length + padding.length);
  const uint8 = new Uint8Array(buf);
  uint8.set(header, 0);
  uint8.set(bytes, header.length);
  uint8.set(padding, header.length + bytes.length);
  return uint8;
};
