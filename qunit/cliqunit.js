QUnit = require("./qunit");
QUnit.extend(global, QUnit);
QUnit.log((function() {
  var lastTestName;
  return function(details) {
    var currentTestName = QUnit.config.current.testName;
    if (currentTestName != lastTestName) {
      console.log(currentTestName);
      lastTestName = currentTestName;
    }
    console.log(" ", (details.result ? "PASS" : "FAIL") + ":", details.message);
  }
})());

