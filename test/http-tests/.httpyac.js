/* eslint-disable */
module.exports = {
  environments: {
    $shared: {
      host: "https://localhost:7097",
    },
    $default: {
      user: "admin",
      email: "somebody@domain.com",
      password: "pA$$w0rd12",
    },
    dev: {
      user: "mario",
      password: "123456",
    },
    prod: {
      user: "mario",
      password: "password$ecure123",
    },
  },
  request: {
    https: {
      rejectUnauthorized: false,
    },
  },
};
