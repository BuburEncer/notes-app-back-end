const Jwt = require("@hapi/jwt");
const InvariantError = require("../../exception/InvariantError");

const TokenManager = {
  generateAccessToken: (payload) => Jwt.token.generate(payload, process.env.ACCESS_TOKEN_KEY),
  generateRefreshToken: (payload) => Jwt.token.generate(payload, process.env.REFRESH_TOKEN_KEY),
  verifyRefreshToken: (token) => {
    try {
      const artifacts = Jwt.token.decode(token);
      Jwt.token.verify(artifacts, process.env.REFRESH_TOKEN_KEY);
      const { payload } = artifacts.decoded;
      return payload;
    } catch (error) {
      throw InvariantError("Refresh token tidak valid");
    }
  },
};

module.exports = TokenManager;
