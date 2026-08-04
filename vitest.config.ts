import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    pool: 'forks',
    poolOptions: {
      forks: {
        minForks: 1,
        maxForks: 2,
      },
    },
  },
});
