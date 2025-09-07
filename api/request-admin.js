const jwt = require("jsonwebtoken");
const { randomUUID } = require("crypto");

const MAX_SECONDS = 5 * 60; // 5 minutes

module.exports = (req, res) => {
  const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
  const user = (req.query && req.query.user) ? String(req.query.user) : "demo";

  const now = Math.floor(Date.now() / 1000);
  const exp = now + MAX_SECONDS;

  const token = jwt.sign(
    {
      sub: user,               // who
      roles: ["admin"],        // what
      jti: randomUUID(),       // unique id
      iat: now,
      exp                      // auto-expire
    },
    SECRET,
    { algorithm: "HS256" }
  );

  // Set HttpOnly cookie for safety
  const cookie = [
    `auth=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${MAX_SECONDS}`
  ].join("; ");

  res.setHeader("Set-Cookie", cookie);
  res.status(200).json({ ok: true, user, expiresAt: exp * 1000 });
};
