// @ts-check

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    eslint.configs.recommended,
    tseslint.configs.recommended,

    {
        rules: {
            "no-unused-vars": "warn",
            "@typescript-eslint/no-unused-vars": "warn",
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/no-wrapper-object-types": "warn",
            "prefer-const": "warn",
            "no-undef": "warn",
            "@typescript-eslint/no-require-imports": "warn",
            "@typescript-eslint/no-unused-expressions": "warn",
        }
    }

);