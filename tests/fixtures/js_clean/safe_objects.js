// Safe Object Operations

// Safe 1: Object.create(null) has no prototype chain
const cleanDict = Object.create(null);
cleanDict["data"] = 123;

// Safe 2: Safe merge with explicit key validation against prototype pollution
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      target[key] = source[key];
    }
  }
}

// Safe 3: ES6 Map
const map = new Map();
map.set("__proto__", "value");
