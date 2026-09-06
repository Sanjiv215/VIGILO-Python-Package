// Safe Code Execution & Timer Fixtures

// Safe 1: eval of constant static arithmetic expression
const staticMath = eval("2 + 2");

// Safe 2: new Function with static string body
const staticCalc = new Function("return 42;");

// Safe 3: setTimeout with callback function reference
function onTick() {
  console.log("Tick");
}
setTimeout(onTick, 1000);

// Safe 4: setInterval with inline arrow function
setInterval(() => {
  console.log("Heartbeat");
}, 5000);
