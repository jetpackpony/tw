
const simpleTypes = ["int", "long", "double", "string", "bytes", "int128", "int256"];
export const isSimpleType = (name) => {
  return simpleTypes.includes(name);
};

export const findByKey = (key, value) => (c) => c[key] === value;


export const isBareType =
  (typeName) => (
    typeName[0] !== typeName[0].toUpperCase() || typeName[0] === "%"
  );