const { execSync } = require('child_process');
const assert = require('assert');

console.log('Running tests for jev-sec-audit...\n');

// Test 1: Clean package.json
try {
  const output = execSync('node index.js test-clean.json').toString();
  assert.match(output, /No threats detected/);
  console.log('✅ Test 1 Passed: Clean package is marked as clean (Exit Code 0).');
} catch (err) {
  console.error('❌ Test 1 Failed: Clean package threw an error or exited with code 1.');
  console.error(err.stdout ? err.stdout.toString() : err);
  process.exit(1);
}

// Test 2: Malicious package.json
try {
  execSync('node index.js test-malicious.json');
  console.error('❌ Test 2 Failed: Malicious package did not throw an error (Exit Code 0).');
  process.exit(1);
} catch (err) {
  const output = err.stdout.toString();
  
  try {
    assert.match(output, /Found 4 potential security risks/);
    assert.match(output, /Typosquatting/);
    assert.match(output, /Malicious Payload/);
    console.log('✅ Test 2 Passed: Malicious package is correctly flagged (Exit Code 1).');
  } catch (assertionErr) {
    console.error('❌ Test 2 Failed: Malicious package returned code 1, but output was incorrect.');
    console.error(assertionErr);
    process.exit(1);
  }
}

console.log('\nAll tests passed successfully! 🎉');
