module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleNameMapper: {
    '@nitric/node-jwt': '<rootDir>/src',
    '^@/(.*)$': '<rootDir>/src/$1',
  },
};
