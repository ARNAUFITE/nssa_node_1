const sqlite3 = require('sqlite3').verbose();

// Abre una base de datos SQLite en el archivo `mydb.db` en el directorio actual.
// Si el archivo no existe, SQLite intentará crearlo.
const db = new sqlite3.Database('./mydb.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log('Connected to the mydb.db SQLite database.');
    //initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    // Crea una tabla de usuarios si no existe
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, hash TEXT)", (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      } else {
        console.log('Table users is ready.');
      }
    });
    console.log("aa")

    // Inserta un usuario de ejemplo - Solo para demostración. Recuerda nunca almacenar contraseñas en texto plano.
     //db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['walrus', '6904d16d932829417bef2fbcfb8f13ba89911152b90f6dd373501237888964eb']);
  });
}

// No olvides cerrar la base de datos cuando ya no la necesites
// db.close((err) => {
//   if (err) {
//     console.error(err.message);
//   }
//   console.log('Closed the database connection.');
// });
