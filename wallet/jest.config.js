/** @type {import('jest').Config} */
module.exports = {
    testMatch: ['**/__tests__/**/*.test.ts'],
    transform: {
        '^.+\\.[jt]sx?$': ['babel-jest', { presets: ['babel-preset-expo'] }],
    },
    transformIgnorePatterns: [
        'node_modules/(?!(expo|@expo|expo-modules-core|react-native|@react-native|@noble)/)',
    ],
    moduleNameMapper: {
        '^@/(.*)$': '<rootDir>/src/$1',
        // A native module shipped as ES modules, which Jest cannot load.
        '^expo-local-authentication$': '<rootDir>/jest/expo-local-authentication.js',
        '^@noble/hashes/(.*)\\.js$': '<rootDir>/node_modules/@noble/hashes/$1.js',
    },
    modulePaths: ['<rootDir>'],
    roots: ['<rootDir>/src', '<rootDir>/modules'],
    testEnvironmentOptions: {
        customExportConditions: ['node', 'require', 'default'],
    },
};
