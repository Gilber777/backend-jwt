const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./data.db"); // Archivo Local (el mismo archivo en el que estamos)

// Crear tabla si no existe
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS mensajes (id INTEGER PRIMARY KEY AUTOINCREMENT, texto TEXT)");
});

module.exports = db;