const jwt = require("jsonwebtoken");

function parseCookie(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(";").forEach(part => {
    const [k, v] = part.trim().split("=");
    if (k && v !== undefined) out[k] = decodeURIComponent(v);
  });
  return out;
}

module.exports = (req, res) => {
  const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
  const cookies = parseCookie(req.headers.cookie || "");
  const token = cookies["auth"];
  if (!token) return res.status(200).json({ user: null, roles: [], expiresAt: null });

  try {
    const decoded = jwt.verify(token, SECRET, { algorithms: ["HS256"] });
    res.status(200).json({
      user: decoded.sub || null,
      roles: decoded.roles || [],
      expiresAt: (decoded.exp || 0) * 1000
    });
  } catch {
    // expired or invalid → clear cookie
    res.setHeader(
      "Set-Cookie",
      "auth=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
    );
    res.status(200).json({ user: null, roles: [], expiresAt: null });
  }
};
