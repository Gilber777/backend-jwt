/*******************************
 * 🌱 CONFIGURACIÓN INICIAL
 *******************************/
require("dotenv").config(); // Carga las variables de entorno desde .env

/*******************************
 * 📦 IMPORTACIÓN DE DEPENDENCIAS
 *******************************/
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

/*******************************
 * 📁 ARCHIVOS LOCALES
 *******************************/
const Usuario = require("./models/Usuario");
const db = require("./db");
const verificarToken = require("./middleware/verificarToken");

/*******************************
 * 🔌 CONEXIÓN A MONGODB
 *******************************/
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch((error) => console.error("❌ Error al conectar a MongoDB:", error));

/*******************************
 * 🚀 INICIALIZACIÓN DE EXPRESS
 *******************************/
const app = express();
const PORT = process.env.PORT || 3000;

/*******************************
 * 🛡️ MIDDLEWARES GLOBALES
 *******************************/
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/*******************************
 * 🧪 RUTA DE PRUEBA
 *******************************/
app.get("/", (req, res) => {
  res.send("Servidor funcionando correctamente con dotenv, cors y body-parser.");
});

/********************************************************
 * 🔒 RUTA PROTEGIDA (requiere token JWT en el header)
 ********************************************************/
app.get("/perfil", verificarToken, (req, res) => {
  res.json({
    mensaje: "Acceso autorizado al perfil",
    usuario: req.usuario,
  });
});

/********************************************************
 * 👤 REGISTRO DE USUARIOS EN MONGODB (POST)
 ********************************************************/
app.post("/usuarios-mongo", [
  body("nombre").notEmpty().withMessage("El nombre es obligatorio"),
  body("correo").isEmail().withMessage("Correo inválido"),
  body("contraseña").isLength({ min: 8 }).withMessage("La contraseña debe tener al menos 8 caracteres")
], async (req, res) => {
  const errores = validationResult(req);
  if (!errores.isEmpty()) return res.status(400).json({ errores: errores.array() });

  try {
    const { nombre, correo, contraseña } = req.body;

    // Verificamos si ya existe el correo
    const existeUsuario = await Usuario.findOne({ correo });
    if (existeUsuario) return res.status(400).json({ error: "El correo ya está registrado" });

    // Encriptamos la contraseña
    const salt = await bcrypt.genSalt(10);
    const contraseñaCifrada = await bcrypt.hash(contraseña, salt);

    // Creamos y guardamos el nuevo usuario
    const nuevoUsuario = new Usuario({ nombre, correo, contraseña: contraseñaCifrada });
    const usuarioGuardado = await nuevoUsuario.save();

    res.status(201).json({
      mensaje: "Usuario registrado correctamente",
      usuario: {
        id: usuarioGuardado._id,
        nombre: usuarioGuardado.nombre,
        correo: usuarioGuardado.correo
      }
    });
  } catch (err) {
    console.error("❌ Error al registrar usuario:", err);
    res.status(500).json({ error: "Error del servidor" });
  }
});

/********************************************************
 * 🔐 LOGIN DE USUARIOS (POST) Y GENERACIÓN DE TOKEN (JWT)
 ********************************************************/
app.post("/login", [
  body("correo").isEmail().withMessage("Correo inválido"),
  body("contraseña").notEmpty().withMessage("La contraseña es obligatoria")
], async (req, res) => {
  const errores = validationResult(req);
  if (!errores.isEmpty()) return res.status(400).json({ errores: errores.array() });

  try {
    const { correo, contraseña } = req.body;

    const usuario = await Usuario.findOne({ correo });
    if (!usuario) return res.status(404).json({ error: "Usuario no encontrado" });

    const coincide = await bcrypt.compare(contraseña, usuario.contraseña);
    if (!coincide) return res.status(401).json({ error: "Contraseña incorrecta" });

    // Generamos el token
    const token = jwt.sign(
      { id: usuario._id, nombre: usuario.nombre },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ mensaje: "Login exitoso", token });
  } catch (err) {
    console.error("❌ Error en login:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

/********************************************************
 * 📄 OBTENER TODOS LOS USUARIOS (GET)
 ********************************************************/
app.get("/usuarios-mongo", async (req, res) => {
  try {
    const usuarios = await Usuario.find();
    res.json(usuarios);
  } catch (err) {
    console.error("❌ Error al obtener usuarios:", err);
    res.status(500).json({ error: "Error al obtener usuarios desde MongoDB" });
  }
});

/********************************************************
 * 📄 ACTUALIZAR USUARIO (PUT)
 * Protegida con JWT
 ********************************************************/
app.put("/usuarios-mongo/:id", verificarToken, [
  body("nombre").notEmpty().withMessage("El nombre es obligatorio"),
  body("correo").isEmail().withMessage("Correo inválido")
], async (req, res) => {
  const errores = validationResult(req);
  if (!errores.isEmpty()) return res.status(400).json({ errores: errores.array() });

  try {
    const { id } = req.params;
    const { nombre, correo } = req.body;

    const usuarioActualizado = await Usuario.findByIdAndUpdate(
      id,
      { nombre, correo },
      { new: true }
    );

    if (!usuarioActualizado) { return res.status(404).json({ error: "Usuario no encontrado" });
  }

    res.json({
      mensaje: "Usuario actualizado correctamente",
      usuario: usuarioActualizado
    });
  } catch (err) {
    console.error("❌ Error al actualizar usuario:", err);
    res.status(500).json({ error: "Error al actualizar usuario" });
  }
});

/********************************************************
 * 🗑️ ELIMINAR USUARIO (DELETE)
 * PROTEGIDO CON JWT
 ********************************************************/
app.delete("/usuarios-mongo/:id", verificarToken, async (req, res) => {
  try {
    const { id } = req.params;

    const usuarioEliminado = await Usuario.findByIdAndDelete(id);
    if (!usuarioEliminado) return res.status(404).json({ error: "Usuario no encontrado" });

    res.json({
      mensaje: "Usuario eliminado correctamente",
      usuario: usuarioEliminado
    });
  } catch (err) {
    console.error("❌ Error al eliminar usuario:", err);
    res.status(500).json({ error: "Error al eliminar usuario" });
  }
});

/********************************************************
 * ✉️ MENSAJES SQLITE - GUARDAR (POST)
 ********************************************************/
app.post("/mensaje-sqlite", verificarToken, (req, res) => {
  const { texto } = req.body;
  db.run("INSERT INTO mensajes (texto) VALUES (?)", [texto], function (err) {
    if (err) return res.status(500).json({ error: "Error al guardar mensaje" });
    res.json({ id: this.lastID, texto });
  });
});

/********************************************************
 * ✉️ MENSAJES SQLITE - LISTAR (GET)
 ********************************************************/
app.get("/mensajes-sqlite", verificarToken, (req, res) => {
  db.all("SELECT * FROM mensajes", (err, rows) => {
    if (err) return res.status(500).json({ error: "Error al obtener mensajes" });
    res.json(rows);
  });
});

/********************************************************
 * 🚀 INICIAR SERVIDOR
 ********************************************************/
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${PORT}`);
});
