// src/routes/user_routes.ts
import express from 'express';
import { registerCtrl, loginCtrl, googleAuthCtrl, googleAuthCallback } from '../auth/auth_controller.js';
import { verifyToken, generateToken } from '../../utils/jwt.handle.js'; // Importar funciones de manejo de JWT
import User from '../users/user_models.js';

const router = express.Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     AuthRegister:
 *       type: object
 *       required:
 *         - name
 *         - password
 *         - email
 *       properties:
 *         name:
 *           type: string
 *           description: El nombre completo del usuario
 *         password:
 *           type: string
 *           description: La contraseña del usuario
 *         age:
 *           type: integer
 *           description: La edad del usuario
 *           default: 0
 *         email:
 *           type: string
 *           description: El correo electrónico del usuario
 *       example:
 *         name: Usuario Ejemplo
 *         password: contraseña123
 *         age: 30
 *         email: usuario@example.com
 *     AuthLogin:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: El email del usuario
 *         password:
 *           type: string
 *           description: La contraseña del usuario
 *       example:
 *         email: usuario@ejemplo.com
 *         password: contraseña123
 */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Registra un nuevo usuario
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AuthRegister'
 *     responses:
 *       200:
 *         description: Usuario registrado exitosamente
 *       400:
 *         description: Error en la solicitud
 */
router.post('/auth/register', registerCtrl);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Inicia sesión un usuario
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AuthLogin'
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso
 *       400:
 *         description: Error en la solicitud
 */
router.post('/auth/login', loginCtrl);
/**
 * @swagger
 * /api/auth/google:
 *   get:
 *     summary: Redirige al usuario a Google para autenticarse
 *     tags: [Auth]
 *     responses:
 *       302:
 *         description: Redirección a Google para autenticación
 */
router.get('/auth/google', googleAuthCtrl);

/**
 * @swagger
 * /api/auth/google/callback:
 *   get:
 *     summary: Callback de Google OAuth
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Autenticación exitosa, redirige al frontend con el token
 *       400:
 *         description: Error en la autenticación
 */
router.get('/auth/google/callback', googleAuthCallback);

router.post('/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token es requerido' });
    }

    try {
        const decoded = verifyToken(refreshToken); // Verificar el refresh token

        // Verificar si el token decodificado es un objeto JwtPayload
        if (typeof decoded !== 'object' || !('email' in decoded)) {
            return res.status(403).json({ message: 'Refresh token inválido' });
        }

        const user = await User.findOne({ email: decoded.email });
        console.log('Stored refreshToken:', user?.refreshToken);
        console.log('Provided refreshToken:', refreshToken);
        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ message: 'Refresh token inválido' });
        }

        // Generar un nuevo access token
        const newAccessToken = generateToken(user.email);

        return res.json({ token: newAccessToken });
    } catch (error) {
        return res.status(403).json({ message: 'Refresh token inválido o expirado' });
    }
});
router.post('/auth/logout', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (user) {
            user.refreshToken = null; // Eliminar el refresh token
            await user.save();
        }
        return res.status(200).json({ message: 'Logout exitoso' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al cerrar sesión' });
    }
});

export default router;
