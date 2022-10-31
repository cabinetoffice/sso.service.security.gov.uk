var fs = require('fs');
module.exports = {
  files: './index.min.js',
  from: 'XCF_REPLACE',
  to: fs.readFileSync('../../.cf-key', 'utf8').trim()
};
