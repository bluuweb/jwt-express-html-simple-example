require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

// simple database
const { results } = require("./data/usuarios");

// habilitar req.body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// archivos estáticos
app.use(express.static(__dirname + "/public"));

// middleware auth
const requireAuth = (req, res, next) => {
    const { authorization } = req.headers;
    const token = authorization.split(" ")[1];

    if (!token) return res.status(403).json({ msg: "no existe el token" });
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        next();
    } catch (error) {
        // console.log(error);
        if (error.message === "jwt expired") {
            return res.status(403).json({ msg: "expirado token" });
        }
        return res.status(401).json({ msg: "token no válido" });
    }
};

// acceso user
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    const user = results.find((item) => item.email === email);
    if (!user) return res.status(404).json({ msg: "no existe el usuario" });

    if (password !== user.password)
        return res.status(403).json({ msg: "contraseña incorrecta" });

    const payload = {
        email: email,
        uid: 1,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: 60 });

    return res.json({ token });
});

// render perfil.html
app.get("/perfil", (req, res) => {
    res.sendFile(__dirname + "/public/perfil.html");
});

// información protegida
app.post("/perfil", requireAuth, (req, res) => {
    res.json({ msg: "ruta protegida", user: req.user });
});

// server
app.listen(5000, console.log("andando ❤"));
