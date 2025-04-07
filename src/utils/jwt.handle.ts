import pkg from 'jsonwebtoken';
import jwt, { JwtPayload } from 'jsonwebtoken';
const { sign, verify } = pkg; //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || 'token.010101010101';

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateToken = (email: string, additionalData: object = {}) => {
    const payload = {
        email,
        ...additionalData // Añadir datos adicionales al payload
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }); // Token válido por 1 hora
};
const verifyToken = (token: string): JwtPayload | string => {
    return jwt.verify(token, JWT_SECRET);
};
const generateRefreshToken = (email: string) => {
    const refreshToken = sign({ email }, JWT_SECRET, { expiresIn: '1m' }); // Refresh token válido por 7 días
    return refreshToken;
};

export { generateToken, verifyToken, generateRefreshToken };
