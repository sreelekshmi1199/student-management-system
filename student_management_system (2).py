"""
Student Management System
-------------------------
Command-line app using SQLite with:
  - auto-created database, 3 related tables (PK + FK)
  - registration / login / logout (salted PBKDF2 password hashing)
  - role-based authorization (admin, staff, student)
  - full CRUD, input validation, exception handling

Default admin account (created on first run):
    username: admin      password: Admin@123
"""

import functools
import hashlib
import hmac
import os
import re
import sqlite3
import sys

# Make sure emojis/symbols print correctly on Windows consoles (PyCharm)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Database is created in the same folder as this script
DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "student_management.db")
conn = None  # global connection, opened in init_db()

# --------------------------------------------------------------------------
# Role-based permissions
# --------------------------------------------------------------------------
PERMISSIONS = {
    "admin": {
        "student_create", "student_read", "student_update", "student_delete",
        "course_create", "course_read", "course_update", "course_delete",
        "user_manage",
    },
    "staff": {
        "student_create", "student_read", "student_update", "course_read",
    },
    "student": {"own_read"},
}


def authorize(user, permission):
    """Return True if the logged-in user's role has this permission."""
    if permission in PERMISSIONS.get(user["role"], set()):
        return True
    print("⛔ Access denied: your role does not have permission for this action.")
    return False


# --------------------------------------------------------------------------
# Error handling decorator
# --------------------------------------------------------------------------
def safe(func):
    """Catch database and unexpected errors so the program never crashes."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.IntegrityError as e:
            conn.rollback()
            print(f"❌ Data integrity error (duplicate or linked record): {e}")
        except sqlite3.Error as e:
            conn.rollback()
            print(f"❌ Database error: {e}")
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
    return wrapper


# --------------------------------------------------------------------------
# Input helpers (validation)
# --------------------------------------------------------------------------
def ask_text(prompt, max_len=50, pattern=None, pattern_msg=""):
    """Ask until a non-empty (and optionally pattern-matching) text is given."""
    while True:
        value = input(prompt).strip()
        if not value:
            print("❌ Input cannot be empty.")
        elif len(value) > max_len:
            print(f"❌ Input too long (max {max_len} characters).")
        elif pattern and not re.fullmatch(pattern, value):
            print(f"❌ {pattern_msg}")
        else:
            return value


def ask_int(prompt, low, high):
    """Ask until a whole number within [low, high] is given."""
    while True:
        raw = input(prompt).strip()
        if not raw:
            print("❌ Input cannot be empty.")
            continue
        try:
            value = int(raw)
        except ValueError:
            print("❌ Invalid input. Please enter a whole number.")
            continue
        if not low <= value <= high:
            print(f"❌ Value must be between {low} and {high}.")
            continue
        return value


def ask_yes_no(prompt):
    while True:
        answer = input(prompt + " (y/n): ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("❌ Please enter 'y' or 'n'.")


def ask_password(prompt="Password: "):
    # Plain input() is used because getpass does not work inside
    # PyCharm's Run window (especially on Windows). Password is visible.
    return input(prompt)


def ask_new_password():
    while True:
        pw = ask_password("Enter password (min 6 chars): ")
        if len(pw) < 6:
            print("❌ Password must be at least 6 characters.")
            continue
        if pw != ask_password("Confirm password: "):
            print("❌ Passwords do not match.")
            continue
        return pw


USERNAME_RE = r"[A-Za-z0-9_]{3,20}"
USERNAME_MSG = "Username must be 3-20 letters, digits or underscores."


# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------
def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 100_000
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Database setup
# --------------------------------------------------------------------------
def init_db():
    global conn
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL CHECK (role IN ('admin','staff','student'))
        );

        CREATE TABLE IF NOT EXISTS courses (
            course_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            course_name TEXT NOT NULL UNIQUE COLLATE NOCASE
        );

        CREATE TABLE IF NOT EXISTS students (
            student_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            age        INTEGER NOT NULL CHECK (age BETWEEN 1 AND 120),
            grade      TEXT NOT NULL,
            course_id  INTEGER NOT NULL,
            user_id    INTEGER UNIQUE,
            FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE RESTRICT,
            FOREIGN KEY (user_id)   REFERENCES users(user_id)     ON DELETE SET NULL
        );
    """)

    # Seed a default admin on first run
    exists = conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
    if not exists:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            ("admin", hash_password("Admin@123")),
        )
        print("ℹ️  First run: default admin created (username: admin, password: Admin@123)")
    conn.commit()


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
@safe
def register():
    print("\n--- Register (Student Account) ---")
    username = ask_text("Username: ", 20, USERNAME_RE, USERNAME_MSG)
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        print("❌ That username is already taken.")
        return
    password = ask_new_password()
    with conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'student')",
            (username, hash_password(password)),
        )
    print("✅ Registration successful! You can now log in.")
    print("   (Ask an admin/staff member to link your account to your student record.)")


@safe
def login():
    print("\n--- Login ---")
    for attempt in range(3):
        username = ask_text("Username: ", 20)
        password = ask_password()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and verify_password(password, row["password_hash"]):
            print(f"✅ Welcome, {row['username']}! (role: {row['role']})")
            return dict(row)
        print(f"❌ Invalid username or password. ({2 - attempt} attempts left)")
    print("🔒 Too many failed attempts. Returning to main menu.")
    return None


# --------------------------------------------------------------------------
# Course operations
# --------------------------------------------------------------------------
def print_courses():
    rows = conn.execute("SELECT * FROM courses ORDER BY course_id").fetchall()
    if not rows:
        print("No courses found.")
        return False
    print(f"{'ID':<5}{'Course Name':<30}")
    print("-" * 35)
    for r in rows:
        print(f"{r['course_id']:<5}{r['course_name']:<30}")
    return True


def pick_course_id():
    """Ask for a course ID until a valid existing one is entered."""
    while True:
        cid = ask_int("Enter Course ID: ", 1, 10**9)
        if conn.execute("SELECT 1 FROM courses WHERE course_id = ?", (cid,)).fetchone():
            return cid
        print("❌ Invalid Course ID. Please choose from the list above.")


@safe
def add_course(user):
    if not authorize(user, "course_create"):
        return
    print("\n--- Add Course ---")
    name = ask_text("Course name: ", 40)
    with conn:
        conn.execute("INSERT INTO courses (course_name) VALUES (?)", (name,))
    print(f"✅ Course '{name}' added.")


@safe
def view_courses(user):
    if not authorize(user, "course_read"):
        return
    print("\n--- Courses ---")
    print_courses()


@safe
def update_course(user):
    if not authorize(user, "course_update"):
        return
    print("\n--- Update Course ---")
    if not print_courses():
        return
    cid = pick_course_id()
    name = ask_text("New course name: ", 40)
    with conn:
        conn.execute("UPDATE courses SET course_name = ? WHERE course_id = ?", (name, cid))
    print("✅ Course updated.")


@safe
def delete_course(user):
    if not authorize(user, "course_delete"):
        return
    print("\n--- Delete Course ---")
    if not print_courses():
        return
    cid = pick_course_id()
    count = conn.execute(
        "SELECT COUNT(*) FROM students WHERE course_id = ?", (cid,)
    ).fetchone()[0]
    if count:
        print(f"❌ Cannot delete: {count} student(s) are enrolled in this course.")
        return
    if ask_yes_no("Are you sure you want to delete this course?"):
        with conn:
            conn.execute("DELETE FROM courses WHERE course_id = ?", (cid,))
        print("🗑️ Course deleted.")


# --------------------------------------------------------------------------
# Student operations
# --------------------------------------------------------------------------
STUDENT_QUERY = """
    SELECT s.student_id, s.name, s.age, s.grade, c.course_name, u.username
    FROM students s
    JOIN courses c ON c.course_id = s.course_id
    LEFT JOIN users u ON u.user_id = s.user_id
"""


def print_students(rows):
    if not rows:
        print("No student records found.")
        return
    print(f"{'ID':<5}{'Name':<22}{'Age':<5}{'Grade':<8}{'Course':<20}{'Account':<15}")
    print("-" * 75)
    for r in rows:
        print(f"{r['student_id']:<5}{r['name']:<22}{r['age']:<5}{r['grade']:<8}"
              f"{r['course_name']:<20}{(r['username'] or '-'):<15}")


def pick_student_id():
    while True:
        sid = ask_int("Enter Student ID: ", 1, 10**9)
        row = conn.execute(
            "SELECT * FROM students WHERE student_id = ?", (sid,)
        ).fetchone()
        if row:
            return sid, row
        print("❌ No student found with that ID.")
        if not ask_yes_no("Try again?"):
            return None, None


def ask_link_username(current_user_id=None):
    """Optionally link a student record to an existing student-role account."""
    while True:
        username = input("Link to account username (leave blank for none): ").strip()
        if not username:
            return None
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            print("❌ No such user.")
        elif row["role"] != "student":
            print("❌ Only accounts with the 'student' role can be linked.")
        else:
            taken = conn.execute(
                "SELECT 1 FROM students WHERE user_id = ? AND user_id IS NOT ?",
                (row["user_id"], current_user_id),
            ).fetchone()
            if taken:
                print("❌ That account is already linked to another student.")
            else:
                return row["user_id"]


@safe
def add_student(user):
    if not authorize(user, "student_create"):
        return
    print("\n--- Add Student ---")
    if not conn.execute("SELECT 1 FROM courses").fetchone():
        print("❌ No courses exist yet. An admin must add a course first.")
        return
    name = ask_text("Name: ", 40)
    age = ask_int("Age (1-120): ", 1, 120)
    grade = ask_text("Grade (e.g., A, B, 10th): ", 8)
    print_courses()
    course_id = pick_course_id()
    user_id = ask_link_username()
    with conn:
        conn.execute(
            "INSERT INTO students (name, age, grade, course_id, user_id) VALUES (?,?,?,?,?)",
            (name, age, grade, course_id, user_id),
        )
    print(f"✅ Student '{name}' added.")


@safe
def view_students(user):
    if not authorize(user, "student_read"):
        return
    print("\n--- All Students ---")
    print_students(conn.execute(STUDENT_QUERY + " ORDER BY s.student_id").fetchall())


@safe
def search_students(user):
    if not authorize(user, "student_read"):
        return
    print("\n--- Search Students ---")
    term = ask_text("Enter Student ID or part of a name: ", 40)
    if term.isdigit():
        rows = conn.execute(
            STUDENT_QUERY + " WHERE s.student_id = ? OR s.name LIKE ?",
            (int(term), f"%{term}%"),
        ).fetchall()
    else:
        rows = conn.execute(
            STUDENT_QUERY + " WHERE s.name LIKE ?", (f"%{term}%",)
        ).fetchall()
    print_students(rows)


@safe
def update_student(user):
    if not authorize(user, "student_update"):
        return
    print("\n--- Update Student ---")
    sid, row = pick_student_id()
    if not row:
        return
    print("(Press Enter to keep the current value)")

    name = input(f"Name [{row['name']}]: ").strip() or row["name"]
    if len(name) > 40:
        print("❌ Name too long (max 40). Update cancelled.")
        return

    age = row["age"]
    raw_age = input(f"Age [{row['age']}]: ").strip()
    if raw_age:
        if not raw_age.isdigit() or not 1 <= int(raw_age) <= 120:
            print("❌ Age must be a whole number between 1 and 120. Update cancelled.")
            return
        age = int(raw_age)

    grade = input(f"Grade [{row['grade']}]: ").strip() or row["grade"]
    if len(grade) > 8:
        print("❌ Grade too long (max 8). Update cancelled.")
        return

    course_id = row["course_id"]
    if ask_yes_no("Change course?"):
        print_courses()
        course_id = pick_course_id()

    user_id = row["user_id"]
    if ask_yes_no("Change linked account?"):
        user_id = ask_link_username(row["user_id"])

    with conn:
        conn.execute(
            "UPDATE students SET name=?, age=?, grade=?, course_id=?, user_id=? "
            "WHERE student_id=?",
            (name, age, grade, course_id, user_id, sid),
        )
    print("✅ Student updated.")


@safe
def delete_student(user):
    if not authorize(user, "student_delete"):
        return
    print("\n--- Delete Student ---")
    sid, row = pick_student_id()
    if not row:
        return
    if ask_yes_no(f"Delete student '{row['name']}'?"):
        with conn:
            conn.execute("DELETE FROM students WHERE student_id = ?", (sid,))
        print("🗑️ Student deleted.")


@safe
def view_own_record(user):
    if not authorize(user, "own_read"):
        return
    print("\n--- My Record ---")
    rows = conn.execute(
        STUDENT_QUERY + " WHERE s.user_id = ?", (user["user_id"],)
    ).fetchall()
    if not rows:
        print("ℹ️  No student record is linked to your account yet. "
              "Please contact an admin or staff member.")
    else:
        print_students(rows)


# --------------------------------------------------------------------------
# User management (admin only)
# --------------------------------------------------------------------------
def print_users():
    rows = conn.execute("SELECT * FROM users ORDER BY user_id").fetchall()
    print(f"{'ID':<5}{'Username':<22}{'Role':<10}")
    print("-" * 37)
    for r in rows:
        print(f"{r['user_id']:<5}{r['username']:<22}{r['role']:<10}")


def pick_user():
    while True:
        uid = ask_int("Enter User ID: ", 1, 10**9)
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,)).fetchone()
        if row:
            return row
        print("❌ No user found with that ID.")
        if not ask_yes_no("Try again?"):
            return None


@safe
def view_users(user):
    if not authorize(user, "user_manage"):
        return
    print("\n--- All Users ---")
    print_users()


@safe
def create_user(user):
    if not authorize(user, "user_manage"):
        return
    print("\n--- Create User ---")
    username = ask_text("Username: ", 20, USERNAME_RE, USERNAME_MSG)
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        print("❌ That username is already taken.")
        return
    role = ""
    while role not in ("admin", "staff", "student"):
        role = input("Role (admin/staff/student): ").strip().lower()
        if role not in ("admin", "staff", "student"):
            print("❌ Invalid role.")
    password = ask_new_password()
    with conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (username, hash_password(password), role),
        )
    print(f"✅ User '{username}' created as {role}.")


@safe
def change_user_role(user):
    if not authorize(user, "user_manage"):
        return
    print("\n--- Change User Role ---")
    print_users()
    target = pick_user()
    if not target:
        return
    if target["user_id"] == user["user_id"]:
        print("❌ You cannot change your own role.")
        return
    role = ""
    while role not in ("admin", "staff", "student"):
        role = input("New role (admin/staff/student): ").strip().lower()
        if role not in ("admin", "staff", "student"):
            print("❌ Invalid role.")
    if role != "student" and conn.execute(
        "SELECT 1 FROM students WHERE user_id = ?", (target["user_id"],)
    ).fetchone():
        print("❌ This account is linked to a student record. Unlink it first.")
        return
    with conn:
        conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, target["user_id"]))
    print("✅ Role updated.")


@safe
def delete_user(user):
    if not authorize(user, "user_manage"):
        return
    print("\n--- Delete User ---")
    print_users()
    target = pick_user()
    if not target:
        return
    if target["user_id"] == user["user_id"]:
        print("❌ You cannot delete your own account.")
        return
    if ask_yes_no(f"Delete user '{target['username']}'?"):
        with conn:
            conn.execute("DELETE FROM users WHERE user_id = ?", (target["user_id"],))
        print("🗑️ User deleted (any linked student record is kept, but unlinked).")


@safe
def change_own_password(user):
    print("\n--- Change Password ---")
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user["user_id"],)).fetchone()
    if not verify_password(ask_password("Current password: "), row["password_hash"]):
        print("❌ Current password is incorrect.")
        return
    new_pw = ask_new_password()
    with conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE user_id = ?",
            (hash_password(new_pw), user["user_id"]),
        )
    print("✅ Password changed.")


# --------------------------------------------------------------------------
# Menus
# --------------------------------------------------------------------------
def run_submenu(title, options, user):
    """Generic sub-menu with a Back option."""
    back = len(options) + 1
    while True:
        print(f"\n--- {title} ---")
        for i, (label, _) in enumerate(options, 1):
            print(f"{i}. {label}")
        print(f"{back}. Back")
        raw = input(f"Enter your choice (1-{back}): ").strip()
        if not raw.isdigit() or not 1 <= int(raw) <= back:
            print(f"❌ Invalid choice! Please select a number between 1 and {back}.")
            continue
        if int(raw) == back:
            return
        options[int(raw) - 1][1](user)


def course_menu(user):
    run_submenu("Manage Courses", [
        ("Add Course", add_course),
        ("View Courses", view_courses),
        ("Update Course", update_course),
        ("Delete Course", delete_course),
    ], user)


def user_menu(user):
    run_submenu("Manage Users", [
        ("View Users", view_users),
        ("Create User", create_user),
        ("Change User Role", change_user_role),
        ("Delete User", delete_user),
    ], user)


# --------------------------------------------------------------------------
# Main screen layout
# --------------------------------------------------------------------------
# Options 1-4 run these actions (permissions are checked inside each one).
CORE_ACTIONS = {
    1: add_student,
    2: view_students,
    3: search_students,
    4: delete_student,
}
CORE_LABELS = {
    1: "Add Student",
    2: "View All Students",
    3: "Search Student",
    4: "Delete Student",
    5: "Exit",
}

# Extra options that appear after login (staff/admin only).
LOGOUT_CHOICE = 10
EXTRA_OPTIONS = {
    "admin": {
        6: ("Update Student", update_student),
        7: ("Manage Courses", course_menu),
        8: ("Manage Users", user_menu),
        9: ("Change My Password", change_own_password),
    },
    "staff": {
        6: ("Update Student", update_student),
        7: ("View Courses", view_courses),
        9: ("Change My Password", change_own_password),
    },
}

STUDENT_OPTIONS = {
    1: ("View My Record", view_own_record),
    2: ("Change My Password", change_own_password),
}


def login_menu():
    """Login Menu. Returns the logged-in user (dict) or None if user goes back."""
    while True:
        print("\n------------------------------")
        print("          LOGIN MENU          ")
        print("------------------------------")
        print("1. Login")
        print("2. Register")
        print("3. Back")
        choice = input("Enter your choice (1-3): ").strip()
        if choice == "1":
            user = login()
            if user:
                return user
        elif choice == "2":
            register()
        elif choice == "3":
            return None
        else:
            print("❌ Invalid choice! Please select 1, 2 or 3.")


def student_menu(user):
    """Student role menu. Returns when the student logs out."""
    logout_choice = len(STUDENT_OPTIONS) + 1
    while True:
        print("\n==============================")
        print(f"  STUDENT MENU  (user: {user['username']})")
        print("==============================")
        for num, (label, _) in STUDENT_OPTIONS.items():
            print(f"{num}. {label}")
        print(f"{logout_choice}. Logout")
        raw = input(f"Enter your choice (1-{logout_choice}): ").strip()
        if not raw.isdigit() or not 1 <= int(raw) <= logout_choice:
            print(f"❌ Invalid choice! Please select a number between 1 and {logout_choice}.")
        elif int(raw) == logout_choice:
            print(f"👋 Logged out. Goodbye, {user['username']}!")
            return
        else:
            STUDENT_OPTIONS[int(raw)][1](user)


def main_menu():
    user = None  # None means nobody is logged in
    while True:
        # Students get their own role-specific menu
        if user and user["role"] == "student":
            student_menu(user)
            user = None
            continue

        extras = EXTRA_OPTIONS[user["role"]] if user else {}

        print("\n==============================")
        print("  STUDENT MANAGEMENT SYSTEM   ")
        print("==============================")
        if user:
            print(f"(Logged in as: {user['username']} - {user['role']})")
        for num in range(1, 6):
            print(f"{num}. {CORE_LABELS[num]}")
        if user:
            for num, (label, _) in extras.items():
                print(f"{num}. {label}")
            print(f"{LOGOUT_CHOICE}. Logout")

        valid = list(range(1, 6)) + (list(extras) + [LOGOUT_CHOICE] if user else [])
        high = max(valid)
        raw = input(f"Enter your choice (1-{high}): ").strip()
        if not raw.isdigit() or int(raw) not in valid:
            print("❌ Invalid choice! Please select a valid option from the menu.")
            continue
        choice = int(raw)

        if choice == 5:
            print("\nThank you for using the Student Management System. Goodbye!")
            return

        if choice == LOGOUT_CHOICE:
            print(f"👋 Logged out. Goodbye, {user['username']}!")
            user = None
            continue

        # Options 1-4 need a login first
        if not user:
            print("\n🔐 Please log in to continue.")
            user = login_menu()
            if not user:
                continue
            if user["role"] == "student":
                continue  # goes to the student menu at the top of the loop

        if choice in CORE_ACTIONS:
            CORE_ACTIONS[choice](user)
        else:
            extras[choice][1](user)


def main():
    try:
        init_db()
    except sqlite3.Error as e:
        print(f"❌ Could not initialise the database: {e}")
        sys.exit(1)

    try:
        main_menu()
    except (EOFError, KeyboardInterrupt):
        print("\n\nProgram interrupted. Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    main()
