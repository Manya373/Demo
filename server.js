// server.js
require('dotenv').config();

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const sendOtpEmail = require('./mailer');
const sql = require('./db'); // <-- Supabase Postgres connection

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Parse JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// OTP storage in memory: email -> { otp, expiresAt }
const otps = {};

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: load user by email from Supabase
async function getUserByEmail(email) {
  const [user] = await sql`
    select id,
           email,
           password_hash,
           name,
           phone,
           age,
           age_group,
           dob,
           country,
           state,
           city,
           pincode,
           role,
           work_tags
    from users
    where email = ${email}
  `;
  return user;
}

// ---------- OTP sender (email-only) ----------
app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required for OTP' });
  }

  const otp = generateOtp();
  otps[email] = {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
  };

  try {
    await sendOtpEmail(email, otp);
    console.log('Email OTP sent to', email, '=>', otp);
    return res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error('Error sending email OTP:', err);
    return res.status(500).json({ message: 'Failed to send email OTP' });
  }
});

// ---------- Signup with email + password + OTP ----------
app.post('/api/signup', async (req, res) => {
  const { email, password, otp } = req.body;

  if (!email || !password || !otp) {
    return res
      .status(400)
      .json({ message: 'Email, password and OTP are required' });
  }

  const record = otps[email];
  if (!record || record.otp !== otp || record.expiresAt < Date.now()) {
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  try {
    const existing = await getUserByEmail(email);
    if (existing) {
      return res
        .status(400)
        .json({ message: 'User already exists, please login' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const [user] = await sql`
      insert into users (email, password_hash)
      values (${email}, ${passwordHash})
      returning id, email
    `;

    delete otps[email];

    console.log('New signup:', user);
    res.json({ message: 'Signup successful', email: user.email });
  } catch (err) {
    console.error('Error during signup:', err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

// ---------- Login with email + password ----------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: 'Email and password are required' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res
        .status(404)
        .json({ message: 'User not found, please sign up' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // record login event
    await sql`
      insert into login_events (user_id)
      values (${user.id})
    `;

    res.json({ message: 'Login successful', email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ---------- Forgot password: verify OTP + change password ----------
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res
      .status(400)
      .json({ message: 'Email, OTP and new password are required' });
  }

  const record = otps[email];
  if (!record || record.otp !== otp || record.expiresAt < Date.now()) {
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await sql`
      update users
      set password_hash = ${newHash}
      where id = ${user.id}
    `;

    delete otps[email];
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ message: 'Server error during reset' });
  }
});

// ---------- Profile: fetch existing data ----------
app.get('/api/user', async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Map DB fields to response shape; work_tags is stored as comma-separated text
    const workTagsArray = user.work_tags
      ? user.work_tags.split(',').filter(Boolean)
      : [];

    const safeUser = {
      id: user.id,
      email: user.email,
      name: user.name || '',
      phone: user.phone || '',
      age: user.age || '',
      ageGroup: user.age_group || '',
      dob: user.dob || '',
      country: user.country || '',
      state: user.state || '',
      city: user.city || '',
      pincode: user.pincode || '',
      role: user.role || '',
      workTags: workTagsArray,
    };

    res.json({ user: safeUser });
  } catch (err) {
    console.error('Fetch user error:', err);
    res.status(500).json({ message: 'Server error fetching user' });
  }
});

// ---------- Profile: save details ----------
app.post('/api/profile', async (req, res) => {
  const {
    email,
    name,
    phone,
    age,
    ageGroup,
    dob,
    country,
    state,
    city,
    pincode,
    role,
    workTags,
  } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  // Normalize workTags to an array, then store as comma-separated text
  const tagsArray = Array.isArray(workTags)
    ? workTags
    : workTags
    ? [workTags]
    : [];
  const tagsString = tagsArray.join(','); // e.g. "teaching,tech"

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await sql`
      update users
      set name      = ${name || null},
          phone     = ${phone || null},
          age       = ${age || null},
          age_group = ${ageGroup || null},
          dob       = ${dob || null},
          country   = ${country || null},
          state     = ${state || null},
          city      = ${city || null},
          pincode   = ${pincode || null},
          role      = ${role || null},
          work_tags = ${tagsString || null}
      where id = ${user.id}
    `;

    console.log('Updated profile for:', email, 'tags:', tagsArray);
    res.json({ message: 'Profile saved', email });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: 'Server error saving profile' });
  }
});

// ---------- Stats: for live analytics on homepage ----------
app.get('/api/stats', async (req, res) => {
  try {
    const [total] = await sql`
      select count(*)::int as c from users
    `;
    const [helpers] = await sql`
      select count(*)::int as c from users where role = 'helper'
    `;
    const [hirers] = await sql`
      select count(*)::int as c from users where role = 'hirer'
    `;
    const [ready] = await sql`
      select count(*)::int as c
      from users
      where role is not null
    `;

    res.json({
      totalUsers: total.c,
      helpers: helpers.c,
      hirers: hirers.c,
      readyToServe: ready.c,
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ message: 'Stats error' });
  }
});

app.listen(PORT, () => {
  console.log(`Jugaad test server running at http://localhost:${PORT}`);
});
