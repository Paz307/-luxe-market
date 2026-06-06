# Luxe Market — HCI E-Commerce Project (Stage 1)
**Faculty of Computing & Information Sciences | UNILAK | Year 3 Evening**

---

## 📁 Project Structure

```
ecommerce/
├── server.js              ← Main Express app (entry point)
├── package.json
├── data/
│   └── db.json            ← JSON file database (auto-created)
├── models/
│   └── db.js              ← Database connection (lowdb)
├── middleware/
│   └── auth.js            ← Session auth & role protection
├── routes/
│   └── auth.js            ← All routes (register, login, dashboard, etc.)
├── public/
│   ├── css/
│   │   └── style.css      ← All styles (beautiful UI)
│   ├── js/
│   │   └── app.js         ← Password strength + avatar preview
│   └── uploads/           ← Profile pictures stored here
└── views/
    ├── register.html      ← Registration page
    ├── login.html         ← Login page
    ├── reset-password.html← Password expiry reset
    ├── dashboard-admin.html← Admin dashboard
    ├── dashboard-seller.html← Seller dashboard
    ├── dashboard-buyer.html← Buyer dashboard
    └── profile.html       ← User profile page
```

---

## 🚀 Setup & Run

### 1. Install dependencies
```bash
cd ecommerce
npm install
```

### 2. Start the server
```bash
node server.js
```

### 3. Open in browser
```
http://localhost:3000
```

---

## ✅ Requirements Fulfilled

| Requirement | Status | Details |
|---|---|---|
| User Registration | ✅ | Full name, email (unique), password, role, profile picture |
| User Login | ✅ | Email + password authentication |
| Role-Based Redirection | ✅ | Admin → Admin Dashboard, Seller → Seller Dashboard, Buyer → Buyer Dashboard |
| Profile Page | ✅ | Shows picture, name, email, role, dates |
| Password Strength | ✅ | 8+ chars, uppercase, lowercase, number, special char |
| Password Expiry (30 days) | ✅ | Tracks `last_login`; forces reset if >30 days inactive |
| Password Reset Flow | ✅ | Redirect to reset page before accessing dashboard |
| Secure Password Hashing | ✅ | bcryptjs with salt rounds = 12 |
| Frontend Validation | ✅ | Live strength bar + rules checklist |
| Backend Validation | ✅ | express-validator on all routes |
| Profile Picture Upload | ✅ | multer, 2MB limit, images only |
| Session Handling | ✅ | express-session |
| Access Control | ✅ | Middleware guards all protected routes |
| Clean Modular Code | ✅ | Routes, middleware, models separated |

---

## 🔐 Security Features

### Password Policy (enforced on BOTH frontend & backend)
- Minimum **8 characters**
- At least one **uppercase letter** (A–Z)
- At least one **lowercase letter** (a–z)
- At least one **number** (0–9)
- At least one **special character** (`!@#$%&` etc.)

### Password Expiry Rule
- If a user **hasn't logged in for 30+ consecutive days**, their session is blocked
- System redirects them to `/reset-password` before any dashboard access
- Tracked using `last_login` field in the database
- After reset, `password_last_updated` timestamp is updated

### Other Security
- Passwords stored as **bcrypt hashes** (never plain text)
- Session-based authentication with server-side validation
- File upload restricted to images only (MIME + extension check)
- Unique email constraint enforced

---

## 👥 User Roles

| Role | Default Emoji | Dashboard Features |
|---|---|---|
| **Admin** | ⚙️ | View all users, see stats (total, admins, sellers, buyers) |
| **Seller** | 🏪 | Store overview (products/orders in Stage 2) |
| **Buyer** | 🛍️ | Shopping overview (cart/orders in Stage 2) |

---

## 🎨 Design Choices

- **Font**: Fraunces (serif display) + DM Sans (body) — imported from Google Fonts
- **Palette**: Ink black + warm cream + antique gold + sage green
- **Layout**: Split-panel auth pages + sidebar dashboard layout
- **Animations**: CSS `fadeUp` animations on page load
- **Visual Details**: Noise texture overlay, radial gradient accents, role-color pills

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `express` | Web framework |
| `express-session` | Session management |
| `bcryptjs` | Password hashing |
| `multer` | Profile picture upload |
| `connect-flash` | Flash messages |
| `express-validator` | Input validation |
| `lowdb` | JSON file database |
| `uuid` | Unique IDs for users and files |
| `ejs` | Template rendering for HTML views |

---

## 🔮 Scalability for Future Stages

The system is designed to be extended:
- **Database**: Replace lowdb JSON file with PostgreSQL/MySQL by changing only `models/db.js`
- **Products**: Add `products` collection to the database
- **Cart/Orders**: Add `orders` and `cart` collections
- **Payments**: Integrate Stripe/payment gateway in a new route file
- **Email**: Add nodemailer for registration confirmation
- **Auth**: Upgrade sessions to JWT for API-based architecture

---

## 🏃 Quick Test

1. Go to `/register` and create:
   - An **Admin** account
   - A **Seller** account  
   - A **Buyer** account
2. Login with each — notice different dashboards
3. Test password strength (try weak passwords — they'll be rejected)
4. Check profile page at `/profile`
5. To test expiry: change `last_login` in `data/db.json` to 31+ days ago, then login

---

*Built for HCI Module — UNILAK Software Engineering Year 3*
