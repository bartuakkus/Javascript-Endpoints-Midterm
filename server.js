const express = require('express');
const joi = require('joi');
const sql = require('mssql');
const bcrypt = require('bcrypt'); //�ifreleme 
const passport = require('passport');
const { body, validationResult } = require('express-validator');

const app = express();

// MSSQL Server ba�lant� ayarlar�
const sqlConfig = {
    user: 'kullanici_adi',
    password: 'sifre',
    server: 'localhost',
    database: 'veritabani_adi',
    options: {
        trustedConnection: true, 
        encrypt: true // SSL ba�lant�s� i�in true, yerel sunucuda false
    }
};

// Joi validasyon �emalar�
const userSchema = joi.object({
    username: joi.string().min(3).required(),
    email: joi.string().email().required(),
    password: joi.string().min(6).required()
});

// Kullan�c� kontrol�
const kullanici_kontrol = async (req, res, next) => {
    const { username, email } = req.body;
    try {
        const pool = await sql.connect(sqlConfig);
        const result = await pool.request()
            .input('username', sql.NVarChar, username)
            .input('email', sql.NVarChar, email)
            .query('SELECT * FROM kullanicilar WHERE username = @username OR email = @email');
        if (result.recordset.length > 0) {
            return res.status(400).json({ error: 'Kullan�c� ad� veya e-posta zaten kullan�l�yor' });
        }
        next();
    } catch (err) {
        console.error('SQL sorgusu hatas�:', err);
        res.status(500).json({ error: 'Sunucu hatas�' });
    }
};

// Kullan�c�lar i�in endpoint'ler
app.get('/api/users', async (req, res) => {
    try {
        const pool = await sql.connect(sqlConfig);
        const result = await pool.request().query('SELECT * FROM kullanicilar');
        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgusu hatas�:', err);
        res.status(500).json({ error: 'Sunucu hatas�' });
    }
});

app.post('/api/users', [
    body('username').isLength({ min: 3 }).withMessage('Kullan�c� ad� en az 3 karakter olmal�d�r'),
    body('email').isEmail().withMessage('Ge�ersiz e-posta adresi'),
    body('password').isLength({ min: 6 }).withMessage('Parola en az 6 karakter olmal�d�r')
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
        res.json({ success: true, message: 'Kullan�c� ba�ar�yla eklendi' });
    } catch (err) {
        console.error('SQL sorgusu hatas�:', err);
        res.status(500).json({ error: 'Sunucu hatas�' });
    }
});

// G�venli endpoint i�in kimlik do�rulama
app.get('/secure-endpoint', passport.authenticate('jwt', { session: false }), (req, res) => {
    // Kullan�c� kimlik do�rulamas� ba�ar�l� ise buraya gelir
});

// Hata i�leme
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Sunucu hatas�' });
});

// Loglama
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url} - ${req.ip}`);
    next();
});

app.listen(3000, () => {
    console.log('Sunucu http://localhost:3000 adresinde �al���yor');
});
