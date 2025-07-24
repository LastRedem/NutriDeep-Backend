require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;

// Rate limiter para login: max 5 intentos en 10 minutos por IP
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutos
  max: 5,
  message: {
    success: false,
    message: 'Demasiados intentos, intenta de nuevo más tarde'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Cambiar a true si usas HTTPS en producción
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 1 día
  }
}));

// Login con rate limiter
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (username === process.env.ADMIN_USER) {
    try {
      const match = await bcrypt.compare(password, process.env.ADMIN_PASS_HASH);
      if (match) {
        req.session.user = username;
        console.log(`Login exitoso: ${username} desde IP ${req.ip}`);
        return res.json({ success: true });
      } else {
        console.log(`Login fallido (contraseña): ${username} desde IP ${req.ip}`);
      }
    } catch (error) {
      console.error('Error en bcrypt.compare:', error);
    }
  } else {
    console.log(`Login fallido (usuario): ${username} desde IP ${req.ip}`);
  }

  res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

function authMiddleware(req, res, next) {
  if (req.session && req.session.user === process.env.ADMIN_USER) {
    next();
  } else {
    res.status(401).json({ error: 'No autorizado' });
  }
}

app.post('/api/chat', authMiddleware, async (req, res) => {
  const userMessage = req.body.message;
  if (!userMessage) return res.status(400).json({ error: 'Falta mensaje' });

  try {
    const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
      model: 'llama-3.3-70b-versatile',
      messages: [
        { 
          role: 'system', 
          content: `Eres un nutricionista profesional que da consejos saludables y personalizados. Responde en formato Markdown, usando:
- Negritas para puntos importantes,
- Saltos de línea,
- Listas numeradas o con viñetas
para facilitar la lectura.` 
        },
        { role: 'user', content: userMessage }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    const botReply = response.data.choices?.[0]?.message?.content || 'Sin respuesta';
    res.json({ reply: botReply });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Error en la API' });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
