const express = require('express');
const joi = require('joi');
const sql = require('mssql');
const bcrypt = require('bcrypt'); //þifreleme 
const passport = require('passport');
const { body, validationResult } = require('express-validator');

const app = express();

// MSSQL Server baðlantý ayarlarý
const sqlConfig = {
    user: 'kullanici_adi',
    password: 'sifre',
    server: 'localhost',
    database: 'veritabani_adi',
    options: {
        trustedConnection: true, 
        encrypt: true // SSL baðlantýsý için true, yerel sunucuda false
    }
};

// Joi validasyon þemalarý
const userSchema = joi.object({
    username: joi.string().min(3).required(),
    email: joi.string().email().required(),
    password: joi.string().min(6).required()
});

// Kullanýcý kontrolü
const kullanici_kontrol = async (req, res, next) => {
    const { username, email } = req.body;
    try {
        const pool = await sql.connect(sqlConfig);
        const result = await pool.request()
            .input('username', sql.NVarChar, username)
            .input('email', sql.NVarChar, email)
            .query('SELECT * FROM kullanicilar WHERE username = @username OR email = @email');
        if (result.recordset.length > 0) {
            return res.status(400).json({ error: 'Kullanýcý adý veya e-posta zaten kullanýlýyor' });
        }
        next();
    } catch (err) {
        console.error('SQL sorgusu hatasý:', err);
        res.status(500).json({ error: 'Sunucu hatasý' });
    }
};

// Kullanýcýlar için endpoint'ler
app.get('/api/users', async (req, res) => {
    try {
        const pool = await sql.connect(sqlConfig);
        const result = await pool.request().query('SELECT * FROM kullanicilar');
        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgusu hatasý:', err);
        res.status(500).json({ error: 'Sunucu hatasý' });
    }
});

app.post('/api/users', [
    body('username').isLength({ min: 3 }).withMessage('Kullanýcý adý en az 3 karakter olmalýdýr'),
    body('email').isEmail().withMessage('Geçersiz e-posta adresi'),
    body('password').isLength({ min: 6 }).withMessage('Parola en az 6 karakter olmalýdýr')
], kullanici_kontrol, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const pool = await sql.connect(sqlConfig);
        const result = await pool
            .request()
            .input('username', sql.NVarChar, username)
            .input('email', sql.NVarChar, email)
            .input('password', sql.NVarChar, hashedPassword)
            .query('INSERT INTO kullanicilar (username, email, password) VALUES (@username, @email, @password)');
        res.json({ success: true, message: 'Kullanýcý baþarýyla eklendi' });
    } catch (err) {
        console.error('SQL sorgusu hatasý:', err);
        res.status(500).json({ error: 'Sunucu hatasý' });
    }
});

// Güvenli endpoint için kimlik doðrulama
app.get('/secure-endpoint', passport.authenticate('jwt', { session: false }), (req, res) => {
    // Kullanýcý kimlik doðrulamasý baþarýlý ise buraya gelir
});

// Hata iþleme
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Sunucu hatasý' });
});

// Loglama
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url} - ${req.ip}`);
    next();
});

app.listen(3000, () => {
    console.log('Sunucu http://localhost:3000 adresinde çalýþýyor');
});
