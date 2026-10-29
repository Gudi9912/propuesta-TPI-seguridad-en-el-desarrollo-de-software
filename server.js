const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());

const MAX_FALLOS = 3;
const VENTANA_MS = 5 * 60 * 1000;
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

// Usuarios de prueba (contraseñas guardadas como hash)
const usuarios = { admin: sha("Clave123!"), ana: sha("Ana2026#") };

// Qué datos forman la clave de bloqueo en cada nivel
// El nivel 1 no bloquea nunca, por eso no tiene criterios.
// El nivel 5 usa los mismos criterios que el 4 para el bloqueo por
// identidad, y además suma un bloqueo global (ver estadoGlobal).
const CRITERIOS = {
  2: ["username"],
  3: ["username", "ip"],
  4: ["username", "ip", "userAgent"],
  5: ["username", "ip", "userAgent"],
};

// clave hasheada -> { fallos: [timestamps], hasta: timestamp de fin de bloqueo }
// La IP y el user agent NUNCA se guardan en claro: solo el hash de la combinación.
const estado = new Map();

// Solo para el nivel 5: cuenta los fallos de un usuario sin importar
// desde qué IP o user agent vinieron, para detectar un ataque que
// rota esos datos para evadir el bloqueo por identidad.
const MAX_FALLOS_GLOBAL = 30;
const estadoGlobal = new Map(); // username -> { fallosTotal, hasta }

function handlerLogin(nivel) {
  return (req, res) => {
    const b = req.body || {};
    const username = String(b.username ?? "").trim();
    const password = String(b.password ?? "");
    if (!username || !password) {
      return res.status(400).json({ ok: false, msg: "Faltan username o password." });
    }

    // Nivel 1: sin ningún bloqueo, se puede intentar infinitas veces
    if (nivel === 1) {
      const ok = usuarios[username] !== undefined && usuarios[username] === sha(password);
      return ok
        ? res.status(200).json({ ok: true, msg: `Ingreso correcto. Bienvenido, ${username}.` })
        : res.status(401).json({ ok: false, msg: "Credenciales incorrectas. (Nivel 1: sin bloqueo, puedes intentar todas las veces que quieras.)" });
    }

    // ip y userAgent vienen en el JSON (Postman). Si no vienen, se usan los de la conexión.
    const datos = {
      username,
      ip: String(b.ip ?? req.ip),
      userAgent: String(b.userAgent ?? req.get("user-agent") ?? ""),
    };
    const clave = sha(nivel + "|" + CRITERIOS[nivel].map((k) => datos[k]).join("|"));
    const ahora = Date.now();

    // Nivel 5: antes de mirar el bloqueo por identidad, chequea si la
    // cuenta ya está bloqueada a nivel global (por muchos fallos en total).
    let g;
    if (nivel === 5) {
      g = estadoGlobal.get(username);
      if (!g) estadoGlobal.set(username, (g = { fallosTotal: 0, hasta: 0 }));
      if (g.hasta && ahora >= g.hasta) { g.hasta = 0; g.fallosTotal = 0; }
      if (g.hasta > ahora) {
        const seg = Math.ceil((g.hasta - ahora) / 1000);
        res.set("Retry-After", String(seg));
        return res.status(429).json({
          ok: false,
          msg: "Cuenta bloqueada: se detectaron muchos intentos fallidos en total, desde distintos orígenes (posible ataque distribuido).",
          restanteSegundos: seg,
        });
      }
    }

    let e = estado.get(clave);
    if (!e) estado.set(clave, (e = { fallos: [], hasta: 0 }));

    // Pasaron los 5 minutos: se libera
    if (e.hasta && ahora >= e.hasta) { e.hasta = 0; e.fallos = []; }

    if (e.hasta > ahora) {
      const seg = Math.ceil((e.hasta - ahora) / 1000);
      res.set("Retry-After", String(seg));
      return res.status(429).json({ ok: false, msg: "Cuenta bloqueada.", restanteSegundos: seg });
    }

    e.fallos = e.fallos.filter((t) => ahora - t < VENTANA_MS);

    const okPass = usuarios[username] !== undefined && usuarios[username] === sha(password);
    if (okPass) {
      e.fallos = [];
      if (nivel === 5) g.fallosTotal = 0; // un ingreso correcto reinicia el contador global
      return res.status(200).json({ ok: true, msg: `Ingreso correcto. Bienvenido, ${username}.` });
    }

    e.fallos.push(ahora);
    if (nivel === 5) {
      g.fallosTotal++;
      if (g.fallosTotal >= MAX_FALLOS_GLOBAL) {
        g.hasta = ahora + VENTANA_MS;
        res.set("Retry-After", String(VENTANA_MS / 1000));
        return res.status(429).json({
          ok: false,
          msg: `Se alcanzaron ${MAX_FALLOS_GLOBAL} intentos fallidos en total: cuenta bloqueada por 5 minutos (posible ataque distribuido).`,
          restanteSegundos: VENTANA_MS / 1000,
        });
      }
    }
    if (e.fallos.length >= MAX_FALLOS) {
      e.hasta = ahora + VENTANA_MS;
      res.set("Retry-After", String(VENTANA_MS / 1000));
      return res.status(429).json({
        ok: false,
        msg: "Tercer intento fallido: bloqueado por 5 minutos.",
        restanteSegundos: VENTANA_MS / 1000,
      });
    }
    return res.status(401).json({
      ok: false,
      msg: `Credenciales incorrectas. Intentos fallidos: ${e.fallos.length} de ${MAX_FALLOS}.`,
    });
  };
}

app.post("/login/nivel1", handlerLogin(1));
app.post("/login/nivel4", handlerLogin(4));
app.post("/login/nivel5", handlerLogin(5));
app.post("/login/nivel2", handlerLogin(2));
app.post("/login/nivel3", handlerLogin(3));

// Solo para demostraciones: borra todos los bloqueos y contadores
app.post("/demo/reset", (_req, res) => {
  estado.clear();
  estadoGlobal.clear();
  res.json({ ok: true, msg: "Bloqueos reiniciados." });
});

app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

// Limpieza de registros vencidos
setInterval(() => {
  const ahora = Date.now();
  for (const [k, e] of estado) {
    const vivos = e.fallos.some((t) => ahora - t < VENTANA_MS);
    if (!vivos && e.hasta <= ahora) estado.delete(k);
  }
}, 60 * 1000).unref();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));
