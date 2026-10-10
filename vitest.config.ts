import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.ts', 'tests/**/*.spec.tsx'],
    // CSS modules load for the settings card tests. The default environment stays Node;
    // interaction tests opt into jsdom with a per-file @vitest-environment docblock.
    css: {
      modules: {
        classNameStrategy: 'non-scoped',
      },
    },
  },
})
