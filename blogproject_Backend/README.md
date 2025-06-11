# Blog Application Backend

This is the backend API for the Blog Application built using Django and MySQL.

## Setup Instructions

1. Clone the repository.

2. Create a virtual environment and activate it:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure MySQL database:

- Create a MySQL database named `blog_db`.
- Update the database credentials in `blog_project/settings.py`:



5. Run migrations:

```bash
python manage.py migrate
```

6. Create a superuser (optional, for admin access):

```bash
python manage.py createsuperuser
```

7. Run the development server:

```bash
python manage.py runserver
```

## API Endpoints

- `POST /api/register/` - Register a new user.
- `POST /api/login/` - Login user.
- `POST /api/logout/` - Logout user.
- `GET /api/blogs/` - List all blogs (public, paginated).
- `POST /api/blogs/` - Create a new blog (authenticated users only).
- `GET /api/blogs/{id}/` - Get blog details.
- `PUT /api/blogs/{id}/` - Update a blog (author only).
- `DELETE /api/blogs/{id}/` - Delete a blog (author only).

## Notes

- Authentication uses session and basic authentication.
- Pagination is set to 10 blogs per page.
- Only blog authors can edit or delete their blogs.

## Testing

You can use tools like Postman or Curl to test the API endpoints.
