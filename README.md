Custom Auth & Authorization Backend (Django)
About:
- Backend application with a custom authentication and authorization system, implemented without using Django permissions out of the box.
- The project demonstrates how user access to resources can be managed using role-based access control (RBAC).


Key Features:
- User registration, login and logout
- Session-based authentication
- Soft delete users (is_active = false)
- Role-based access control (RBAC)
- Correct handling of 401 Unauthorized and 403 Forbidden
- Admin API for managing roles and permissions
- Mock business resources to demonstrate access control
- Minimal browser-based UI for testing (no frontend framework)

Access Control Concept:
- Access is defined by the following chain:
- User → Role → Permission → Resource + Action
- A user can have multiple roles
- A role contains permissions
- A permission defines what action can be performed on a resource
- This approach allows flexible and scalable access management.

API Behavior:
- Not authenticated → 401 Unauthorized
- Authenticated but no permission → 403 Forbidden
- Authorized → requested resource is returned

Mock Business Endpoints:
- /api/mock/projects
- /api/mock/reports
- These endpoints are used only to demonstrate authorization logic.
- No real business tables are created.

Minimal UI (optional):
- A simple HTML UI is included for testing without Postman:
- /ui/register
- /ui/login
- /ui/me
- The UI exists only to demonstrate backend functionality.

Technologies:
- Python
- Django
- Django REST Framework
- SQLite
- HTML + Fetch API

Running the Project:
python manage.py migrate
python manage.py runserver


Open in browser:
http://127.0.0.1:8000/ui/
