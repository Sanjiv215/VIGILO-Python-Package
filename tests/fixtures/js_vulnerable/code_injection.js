// VIGILO-JS-002: Code Injection Vulnerabilities

function runFormula(userFormula, a, b) {
  // Finding 1: eval() with user-controlled formula
  const result = eval(userFormula);
  return result;
}

function createCustomTransformer(dynamicBody) {
  // Finding 2: new Function constructor with dynamic body
  const transformer = new Function("x", "y", dynamicBody);
  return transformer(10, 20);
}

function scheduleJob(handlerName, delay) {
  // Finding 3: string-based timer expression triggers implicit eval
  setTimeout("processJob('" + handlerName + "')", delay);
}
