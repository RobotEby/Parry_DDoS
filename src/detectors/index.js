'use strict';

const { SQLInjectionDetector } = require('./sql');
const { XSSDetector } = require('./xss');
const { NoSQLDetector } = require('./nosql');

module.exports = { SQLInjectionDetector, XSSDetector, NoSQLDetector };
