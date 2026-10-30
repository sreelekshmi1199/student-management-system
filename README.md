# student-management-system
# Student Management System

A command-line **Student Management System** written in Python with an **SQLite** database. It includes user registration and login, role-based access control (Admin, Staff, Student), full CRUD operations, input validation and exception handling.

---

## Table of Contents

1. [Features](#features)
2. [Technologies Used](#technologies-used)
3. [Project Structure](#project-structure)
4. [How to Run](#how-to-run)
5. [Default Login](#default-login)
6. [Menu Guide](#menu-guide)
7. [User Roles and Permissions](#user-roles-and-permissions)
8. [Database Design](#database-design)
9. [Input Validation](#input-validation)
10. [Exception Handling](#exception-handling)
11. [SQL Operations Used](#sql-operations-used)
12. [Sample Demo Flow](#sample-demo-flow)
13. [Project Requirements Checklist](#project-requirements-checklist)
14. [Known Limitations](#known-limitations)
15. [Author](#author)

---

## Features

- SQLite database that is **created automatically** on first run
- **3 related tables** using primary keys and foreign keys
- User **registration, login and logout**
- Passwords stored as **salted PBKDF2-SHA256 hashes** (never as plain text)
- **Role-based authorization** with three roles: Admin, Staff, Student
- Full **CRUD** for students and courses; user management for admins
- **Menu-driven** interface with a main menu, login menu and role-specific menus
- Validation of every user input
- Exception handling so the program does not crash on bad input or database errors

---

## Technologies Used

| Item | Details |
|------|---------|
| Language | Python 3.8 or newer |
| Database | SQLite (`sqlite3` module) |
| Libraries | Standard library only: `sqlite3`, `hashlib`, `hmac`, `os`, `re`, `functools`, `sys` |
| IDE | PyCharm (works in any terminal as well) |

No extra packages need to be installed.

---

## Project Structure

```
student-management-system/
│
├── student_management_system.py   # Main program (all code)
├── student_management.db          # SQLite database (created automatically on first run)
└── README.md                      # This file
```

---

## How to Run

### In PyCharm

1. Open PyCharm and choose **File → Open**, then select the project folder.
2. Make sure a Python interpreter is set under **File → Settings → Project → Python Interpreter**.
3. Open `student_management_system.py`.
4. Right-click the file and choose **Run 'student_management_system'** (or press `Shift + F10`).
5. Type your inputs in the **Run** window at the bottom.

### In a terminal

```bash
python student_management_system.py
```

On macOS or Linux, use `python3` instead of `python`.

### Resetting the data

Close the program, delete `student_management.db`, and run it again. A fresh database and the default admin account are created automatically.

---

## Default Login

On first run the program creates an administrator account:

| Username | Password |
|----------|----------|
| `admin` | `Admin@123` |

> Change this password after your first login using **Change My Password** (option 9).

> **Note:** Passwords are visible while typing. This is because the standard `getpass` function does not work inside PyCharm's Run window.

---

## Menu Guide

### Main screen (shown first)

```
==============================
  STUDENT MANAGEMENT SYSTEM
==============================
1. Add Student
2. View All Students
3. Search Student
4. Delete Student
5. Exit
```

Choosing options 1–4 when you are not logged in opens the **Login Menu**:

```
1. Login
2. Register
3. Back
```

After a successful login, the same screen stays open with a line showing who is logged in. Admin and Staff users also see extra options:

| Option | Admin | Staff |
|--------|-------|-------|
| 1. Add Student | ✅ | ✅ |
| 2. View All Students | ✅ | ✅ |
| 3. Search Student | ✅ | ✅ |
| 4. Delete Student | ✅ | ⛔ Access denied |
| 5. Exit | ✅ | ✅ |
| 6. Update Student | ✅ | ✅ |
| 7. Manage Courses / View Courses | Manage (full CRUD) | View only |
| 8. Manage Users | ✅ | Not shown |
| 9. Change My Password | ✅ | ✅ |
| 10. Logout | ✅ | ✅ |

**Student** accounts get their own menu:

```
1. View My Record
2. Change My Password
3. Logout
```

---


**Notes**

- Public registration only creates **Student** accounts. Admin and Staff accounts must be created by an admin (Manage Users → Create User).
- A student account is linked to a student record by an admin or staff member when adding or updating the student (enter the account's username when asked).
- Admins cannot delete their own account or change their own role.

---

## Database Design

The database file is `student_management.db`. Foreign key enforcement is turned on with `PRAGMA foreign_keys = ON`.

### Tables

**users**

| Column | Type | Notes |
|--------|------|-------|
| user_id | INTEGER | **Primary key**, auto-increment |
| username | TEXT | Unique, not null, case-insensitive |
| password_hash | TEXT | Salted PBKDF2 hash |
| role | TEXT | Must be `admin`, `staff` or `student` (CHECK constraint) |

**courses**

| Column | Type | Notes |
|--------|------|-------|
| course_id | INTEGER | **Primary key**, auto-increment |
| course_name | TEXT | Unique, not null, case-insensitive |

**students**

| Column | Type | Notes |
|--------|------|-------|
| student_id | INTEGER | **Primary key**, auto-increment |
| name | TEXT | Not null |
| age | INTEGER | Not null, must be between 1 and 120 (CHECK constraint) |
| grade | TEXT | Not null |
| course_id | INTEGER | **Foreign key** → `courses(course_id)`, `ON DELETE RESTRICT` |
| user_id | INTEGER | **Foreign key** → `users(user_id)`, unique, `ON DELETE SET NULL` |

### Relationships

```
courses (1) ───────< students (many)     A course has many students
users   (1) ─────── students (0..1)     A user account may be linked to one student record
```

### Data consistency rules

- A **course cannot be deleted** while students are enrolled in it.
- Deleting a **user** keeps the student record but removes the link (`user_id` becomes empty).
- A student cannot be added unless a valid course exists.

---

## Input Validation

The program checks input before using it and asks again when it is invalid.

| Check | Where it applies |
|-------|------------------|
| Empty input rejected | Names, grades, usernames, course names, search terms |
| Invalid data types rejected | Age, IDs and menu choices must be whole numbers |
| Range checks | Age must be 1–120 |
| Length limits | Name (40), grade (8), username (20), course name (40) |
| Duplicate entries rejected | Usernames and course names |
| Invalid IDs rejected | Student, course and user IDs must exist |
| Invalid menu selection rejected | Every menu |
| Username format | 3–20 letters, digits or underscores |
| Password rules | Minimum 6 characters, entered twice to confirm |
| Confirmation prompts | Deleting a student, course or user asks for `y/n` |

---

## Exception Handling

A custom `@safe` decorator wraps each database-related function in a `try/except` block:

| Error type | What happens |
|------------|--------------|
| `sqlite3.IntegrityError` | Duplicate or linked-record problem: the change is rolled back and a message is shown |
| `sqlite3.Error` | Other database errors: rolled back and a message is shown |
| Any other `Exception` | An "Unexpected error" message is shown |
| `ValueError` (invalid numbers) | Handled in the input functions, which ask again |
| `Ctrl + C` / end of input | The program exits politely |

In all of these cases the program continues running instead of crashing. The database connection is always closed when the program ends.

---

## SQL Operations Used

| Operation | Example use in the project |
|-----------|----------------------------|
| `CREATE TABLE` | Creating the `users`, `courses` and `students` tables |
| `INSERT` | Registering users, adding students and courses |
| `SELECT` | Login, listing and searching records (with `JOIN` and `LEFT JOIN`) |
| `UPDATE` | Editing students, courses, roles and passwords |
| `DELETE` | Removing students, courses and users |

All queries use **parameterized statements** (`?` placeholders) to prevent SQL injection.

---

## Sample Demo Flow

1. Run the program and choose **2. View All Students**. Log in as `admin` / `Admin@123`.
2. Choose **7. Manage Courses → 1. Add Course** and add a course, for example `Computer Science`. Go back.
3. Choose **1. Add Student** and enter a name, age, grade and the course ID.
4. Try **2. View All Students**, **3. Search Student** and **6. Update Student**.
5. Choose **8. Manage Users → 2. Create User** and create a staff account.
6. Choose **10. Logout**, then log in as the staff user and try **4. Delete Student** to see *Access denied*.
7. Log out, then register a student account from the Login Menu and log in to see the student menu.
8. Choose **5. Exit** to close the program.

---

## Project Requirements Checklist

| # | Requirement | Status |
|---|-------------|:------:|
| 1 | SQLite database, created automatically | ✅ |
| 2 | Minimum 2 related tables with primary and foreign keys (3 used) | ✅ |
| 3 | User registration, login and logout | ✅ |
| 4 | Role-based authorization with at least 2 roles (3 used) | ✅ |
| 5 | Full CRUD with permission checks | ✅ |
| 6 | Foreign key relationships keeping data consistent | ✅ |
| 7 | Menu-driven interface (main, login and role-specific menus, exit) | ✅ |
| 8 | Input validation | ✅ |
| 9 | Exception handling | ✅ |
| 10 | SQL operations: CREATE, INSERT, SELECT, UPDATE, DELETE | ✅ |

---

## Known Limitations

- Passwords are visible while typing (a PyCharm console limitation).
- It is a single-user command-line application with no graphical interface.
- There is no "forgot password" feature; an admin would need to recreate the account.
- Student IDs are generated automatically and cannot be chosen by the user.

---

## Author

**Name:** _Your Name_
**Course / Institution:** _Your Course and Institution_
**Date:** _Date of submission_
