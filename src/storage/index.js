export const setItem = (name, value) => {
  return localStorage.setItem(name, value);
};

export const getItem = (name) => {
  return localStorage.getItem(name);
};
