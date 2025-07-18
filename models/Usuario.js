const mongoose = require("mongoose");

const usuarioSchema = new mongoose.Schema({
  nombre: {
    type: String,
    required: true,
  },
  correo: {
    type: String,
    required: true,
    unique: true
  },
  password: { 
    type: String, 
    required: true,
  },
  creado_en: {
    type: Date,
    default: Date.now,
  }

});

module.exports = mongoose.model("Usuario", usuarioSchema);

//Colocaremos campos para que se introduzcan: Nombre, correo y contraceña:
