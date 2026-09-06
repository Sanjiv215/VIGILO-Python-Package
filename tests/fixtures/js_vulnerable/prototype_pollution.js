// VIGILO-JS-004: Prototype Pollution

function unsafeAssignProto(target, payload) {
  // Finding 1: Direct __proto__ assignment
  target.__proto__ = payload;
}

function elevatePermissions(userObj) {
  // Finding 2: Direct constructor.prototype assignment
  userObj.constructor.prototype.isAdmin = true;
}

function deepMerge(target, source) {
  // Finding 3: Unguarded nested property assignment loop
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key][source[key]] = true;
    }
  }
}
