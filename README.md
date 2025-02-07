# MindPlan

**MindPlan** is a project built with Python (Django). This README will detail key information about the project alongside setup instructions for developers and users.

---

## 🚀 Feature Apps

- [ ] **User**: Handles user registration, authentication, and profile management.
- [ ] **MindPlan manager**: Facilitates planning, organization, and management of tasks or ideas with advanced features.

---

## 🛠️ Requirements

Before starting, make sure you have the following installed:

- Python 3.13
- Django (installed via `pip`)
- Development environment (e.g., PyCharm)

---

## 📦 Installation

To set up and run the project locally:

1. Clone the repository:
   ```bash
   git clone <REPO_URL>
   cd MindPlan
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv .venv
   source .venv/Scripts/activate # Windows
   source .venv/bin/activate     # macOS/Linux
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Apply database migrations:
   ```bash
   python manage.py migrate
   ```

5. Run the development server:
   ```bash
   python manage.py runserver
   ```

---

## 📂 Project Structure