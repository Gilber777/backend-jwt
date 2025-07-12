const jwt = require("jsonwebtoken");

function verificarToken(req, res, next) {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).json({ error: "Acceso denegado. Token no proporcionado" });
  }

  try {
    const tokenLimpio = token.replace("Bearer ", ""); // Por si viene con "Bearer ..."
    const verificado = jwt.verify(tokenLimpio, process.env.JWT_SECRET);
    req.usuario = verificado; // Añade el usuario al request para que lo puedas usar después
    next();
  } catch (err) {
    res.status(400).json({ error: "Token inválido" });
  }
}

module.exports = verificarToken;
