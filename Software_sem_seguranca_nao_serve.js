const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Mock de usuários
const users = [
  { "username": "user", "password": "123456", "id": 123, "email": "user@dominio.com", "perfil": "user" },
  { "username": "admin", "password": "123456789", "id": 124, "email": "admin@dominio.com", "perfil": "admin" },
  { "username": "colab", "password": "123", "id": 125, "email": "colab@dominio.com", "perfil": "user" },
];

// Segredo para JWT
const jwtSecret = "supersecretkey";

// Função para geração do token JWT
function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      perfil: user.perfil,
    },
    jwtSecret,
    { expiresIn: '1h' }
  );
}

// Middleware para validação do token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Token não fornecido' });

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido ou expirado' });
    req.user = user;
    next();
  });
}

// Endpoint de login
app.post('/api/auth/login', (req, res) => {
  const credentials = req.body;

  const user = users.find(
    u => u.username === credentials.username && u.password === credentials.password
  );

  if (!user) return res.status(401).json({ message: 'Credenciais inválidas' });

  const token = generateToken(user);
  res.json({ token });
});

// Recuperação de dados do usuário logado
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Endpoint para listar usuários (apenas para administradores)
app.get('/api/users', authenticateToken, (req, res) => {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ message: 'Acesso proibido' });
  }
  res.json({ users });
});

// Endpoint para busca de contratos com validação de SQL Injection
app.get('/api/contracts', authenticateToken, (req, res) => {
  const { empresa, inicio } = req.query;

  if (!empresa || !inicio) {
    return res.status(400).json({ message: 'Parâmetros obrigatórios ausentes' });
  }

  // Validação contra injeção
  const sanitizedEmpresa = empresa.replace(/['"]/g, '');
  const sanitizedInicio = inicio.replace(/['"]/g, '');

  const query = `SELECT * FROM contracts WHERE empresa = '${sanitizedEmpresa}' AND data_inicio = '${sanitizedInicio}'`;
  console.log('Query simulada:', query);

  // Retorna resultado mockado
  res.json({ contracts: [] });
});

// Servidor escutando
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
