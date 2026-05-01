/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: [
    "**/src/test/**/*.test.ts",
    "**/src/test/**/*.test.js",
    "**/test-fixtures/**/*.test.js",
  ],
  moduleNameMapper: {
    "^vscode$": "<rootDir>/src/test/__mocks__/vscode.ts",
  },
};

