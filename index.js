const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');
const path = require('path');

const app = express();
const PORT = 3001;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==================== Home ====================
app.get('/', (req, res) => {
  res.redirect('/login.html');
});


// ==================== Add User ====================
app.post('/user', async (req, res) => {
  try {
    const { name, email, password, phone, user_type } = req.body;

    // 1. Check required fields
    if (
      typeof name !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      typeof phone !== 'string' ||
      typeof user_type !== 'string' ||
      !name.trim() ||
      !email.trim() ||
      !password ||
      !phone.trim() ||
      !user_type.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: 'من فضلك املأ كل البيانات'
      });
    }

    // 2. Clean and normalize data
    const normalizedName = name.trim().replace(/\s+/g, ' ');
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim();
    const normalizedType = user_type.trim().toLowerCase();

    // 3. Name validation
    const namePattern = /^[\p{L}\s]+$/u;

    if (!namePattern.test(normalizedName)) {
      return res.status(400).json({
        success: false,
        message: 'الاسم يجب أن يحتوي على حروف فقط'
      });
    }

    // Maximum 15 characters for each name field
    if (normalizedName.length > 31) {
      return res.status(400).json({
        success: false,
        message: 'الاسم لا يجب أن يزيد عن 15 حرفًا لكل خانة'
      });
    }

    // 4. Email validation
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: 'البريد الإلكتروني غير صحيح'
      });
    }

    // 5. Password validation
    const passwordPattern = /^(?=.*[A-Za-z])(?=.*[0-9]).{8,}$/;

    if (!passwordPattern.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل وتحتوي على حروف وأرقام'
      });
    }

    // 6. Phone validation
    const phonePattern = /^01[0125][0-9]{8}$/;

    if (!phonePattern.test(normalizedPhone)) {
      return res.status(400).json({
        success: false,
        message: 'رقم الهاتف يجب أن يكون 11 رقمًا ويبدأ بـ 010 أو 011 أو 012 أو 015'
      });
    }

    // 7. User type validation
    if (!['student', 'company'].includes(normalizedType)) {
      return res.status(400).json({
        success: false,
        message: 'نوع المستخدم غير صحيح'
      });
    }

    // 8. Check duplicate email
    const [existingUsers] = await db.promise().query(
      'SELECT user_id FROM `user` WHERE email = ?',
      [normalizedEmail]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'البريد الإلكتروني مسجل بالفعل'
      });
    }

    // 9. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 10. Insert user into database
    const [result] = await db.promise().query(
      `INSERT INTO \`user\`
       (NAME, email, password, phone, user_type)
       VALUES (?, ?, ?, ?, ?)`,
      [
        normalizedName,
        normalizedEmail,
        hashedPassword,
        normalizedPhone,
        normalizedType
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'تم إنشاء الحساب بنجاح',
      user_id: result.insertId
    });

  } catch (error) {
    console.error('Signup error:', error);

    return res.status(500).json({
      success: false,
      message: 'حدث خطأ أثناء إنشاء الحساب'
    });
  }
});


// ==================== Get All Users ====================
app.get('/user', async (req, res) => {
  try {
    const [users] = await db.promise().query(
      `SELECT user_id, NAME, email, phone, user_type
       FROM \`user\`
       ORDER BY user_id DESC`
    );

    return res.json(users);

  } catch (error) {
    console.error('Get users error:', error);

    return res.status(500).json({
      success: false,
      message: 'تعذر تحميل المستخدمين'
    });
  }
});


// ==================== Get User By ID ====================
app.get('/user/:id', async (req, res) => {
  try {
    const [users] = await db.promise().query(
      `SELECT user_id, NAME, email, phone, user_type
       FROM \`user\`
       WHERE user_id = ?`,
      [req.params.id]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'المستخدم غير موجود'
      });
    }

    return res.json(users[0]);

  } catch (error) {
    console.error('Get user error:', error);

    return res.status(500).json({
      success: false,
      message: 'حدث خطأ أثناء تحميل المستخدم'
    });
  }
});


// ==================== Login ====================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: 'أدخل البريد الإلكتروني وكلمة المرور'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Search for all accounts with the same email
    const [users] = await db.promise().query(
      `SELECT user_id, NAME, email, password, user_type
       FROM \`user\`
       WHERE email = ?
       ORDER BY user_id DESC`,
      [normalizedEmail]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
      });
    }

    let matchedUser = null;

    // Check password against each matching account
    for (const user of users) {

      const storedPassword = String(user.password);
      const enteredPassword = password;

      let isMatch = false;

      // Check hashed password
      if (/^\$2[aby]\$/.test(storedPassword)) {

        isMatch = await bcrypt.compare(
          enteredPassword,
          storedPassword
        );

      } else {

        // Check old plain text password
        isMatch = enteredPassword === storedPassword;

      }

      if (isMatch) {

        matchedUser = user;

        // Hash old password after successful login
        if (!/^\$2[aby]\$/.test(storedPassword)) {

          const hashedPassword = await bcrypt.hash(
            enteredPassword,
            10
          );

          await db.promise().query(
            `UPDATE \`user\`
             SET password = ?
             WHERE user_id = ?`,
            [hashedPassword, user.user_id]
          );
        }

        break;
      }
    }

    if (!matchedUser) {
      return res.status(401).json({
        success: false,
        message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
      });
    }

    return res.json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      user: {
        user_id: matchedUser.user_id,
        id: matchedUser.user_id,
        name: matchedUser.NAME,
        email: matchedUser.email,
        user_type: matchedUser.user_type
      }
    });

  } catch (error) {
    console.error('Login error:', error);

    return res.status(500).json({
      success: false,
      message: 'حدث خطأ في تسجيل الدخول'
    });
  }
});


// ==================== Add Profile ====================
app.post('/profile', async (req, res) => {
  try {
    const { user_id, ...profileData } = req.body;

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: 'رقم المستخدم مطلوب'
      });
    }

    const columns = Object.keys(profileData);

    if (columns.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'بيانات الملف الشخصي مطلوبة'
      });
    }

    const allowedColumns = [
      'birth_date',
      'gender',
      'address',
      'education',
      'skills',
      'experience',
      'about'
    ];

    const validColumns = columns.filter(column =>
      allowedColumns.includes(column)
    );

    if (validColumns.length !== columns.length) {
      return res.status(400).json({
        success: false,
        message: 'يوجد حقل غير مسموح به في البيانات'
      });
    }

    const insertColumns = ['user_id', ...validColumns];

    const insertValues = [
      user_id,
      ...validColumns.map(column => profileData[column])
    ];

    const placeholders = insertColumns.map(() => '?').join(', ');

    const columnSQL = insertColumns.map(
      column => `\`${column}\``
    ).join(', ');

    const [result] = await db.promise().query(
      `INSERT INTO profile (${columnSQL})
       VALUES (${placeholders})`,
      insertValues
    );

    return res.status(201).json({
      success: true,
      message: 'تم حفظ الملف الشخصي',
      profile_id: result.insertId
    });

  } catch (error) {
    console.error('Profile error:', error);

    return res.status(500).json({
      success: false,
      message: 'حدث خطأ أثناء حفظ الملف الشخصي'
    });
  }
});


// ==================== Get Profiles ====================
app.get('/profile', async (req, res) => {
  try {
    const [profiles] = await db.promise().query(
      'SELECT * FROM profile'
    );

    return res.json(profiles);

  } catch (error) {
    console.error('Get profiles error:', error);

    return res.status(500).json({
      success: false,
      message: 'تعذر تحميل الملفات الشخصية'
    });
  }
});


// ==================== Add Company ====================
app.post('/company', async (req, res) => {
  try {
    const { user_id, company_name, description, website } = req.body;

    if (
      !user_id ||
      typeof company_name !== 'string' ||
      !company_name.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: 'رقم المستخدم واسم الشركة مطلوبان'
      });
    }

    const [result] = await db.promise().query(
      `INSERT INTO company
       (user_id, company_name, description, website)
       VALUES (?, ?, ?, ?)`,
      [
        user_id,
        company_name.trim(),
        description || null,
        website || null
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'تمت إضافة الشركة بنجاح',
      company_id: result.insertId
    });

  } catch (error) {
    console.error('Company error:', error);

    return res.status(500).json({
      success: false,
      message: 'حدث خطأ أثناء إضافة الشركة'
    });
  }
});


// ==================== Get Companies ====================
app.get('/companies', async (req, res) => {
  try {
    const [companies] = await db.promise().query(
      'SELECT * FROM company'
    );

    return res.json(companies);

  } catch (error) {
    console.error('Get companies error:', error);

    return res.status(500).json({
      success: false,
      message: 'تعذر تحميل الشركات'
    });
  }
});


// ==================== Start Server ====================
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});