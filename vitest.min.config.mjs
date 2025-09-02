export default {
  test: {
    environment: 'node',
    globals: true,
  },
  coverage: {
    provider: 'v8',
    reporter: ['text'],
    enabled: false,
  },
};
