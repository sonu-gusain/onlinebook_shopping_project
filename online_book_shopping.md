#  Online Book Shopping API (FastAPI)

This project is a backend API for an online book shopping platform. Built using FastAPI and MySQL Connector, it supports user registration, login, role-based access (admin/user), book listing, ordering, and reviews.

---

##  Features

-  Book Listing (Admin can add/update/delete)
-  Order Books (User only)
-  JWT Authentication (Login/Register)
-  Role-based access control (Admin/User)
-  Access + Refresh Tokens
-  Password Hashing (secure)
-  Email Notifications via SMTP 
-  Stripe Payment Integration (User payments)
-  Rate Limiting (SlowAPI)
-  Book Reviews and Ratings

---

##  Technologies Used

- Python 3.13
- FastAPI
- MySQL (via `mysql-connector-python`)
- Pydantic
- JWT (`python-jose`)
- Passlib (for password hashing)

---

##  How to Run

1.  Install dependencies:

pip install fastapi uvicorn python-jose[cryptography] mysql-connector-python passlib[bcrypt]
