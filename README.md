# Chirpy

I built this Twitter-like social media API with Go. It lets users post short messages, manage accounts, and upgrade to premium membership.

It is a production-ready REST API with:
- JWT-based authentication with refresh tokens
- PostgreSQL database with proper schema management
- Password hashing using Argon2
- Profanity filtering
- Premium membership webhooks
- Clean separation of concerns

It was perfect for learning Go web development or as a foundation for social media applications.

## Features

- User registration and authentication (JWT + refresh tokens)
- Create, read, and delete chirps (140 character limit)
- Filter chirps by author
- Sort chirps by date (ascending/descending)
- Premium membership upgrades via webhooks
- Profanity filtering
- Password hashing with Argon2

## Installation

### Prerequisites

- Go 1.25.1 or higher
- PostgreSQL database

### Setup

1. Clone the repository:
```bash
git clone https://github.com/dddaglar/http_server_mockup.git
cd chirpy
```

2. Install dependencies:
```bash
go mod download
```

3. Set up your environment variables in a `.env` file:
```env
DB_URL=postgres://username:password@localhost:5432/chirpy?sslmode=disable
SECRET_KEY=your-jwt-secret-key
POLKA_KEY=your-polka-api-key
PLATFORM=dev
```

4. Run database migrations:
```bash
# Apply the SQL schema files in sql/schema/ to your database
psql -U username -d chirpy -f sql/schema/001_users.sql
psql -U username -d chirpy -f sql/schema/002_chirps.sql
psql -U username -d chirpy -f sql/schema/003_password.sql
psql -U username -d chirpy -f sql/schema/004_refresh_tokens.sql
psql -U username -d chirpy -f sql/schema/005_red.sql
```

5. Run the server:
```bash
go run .
```

The server will start on `http://localhost:8080`

## API Endpoints

### Health Check
- `GET /api/healthz` - Check if the server is running

### Users
- `POST /api/users` - Register a new user
- `PUT /api/users` - Update user email/password (requires JWT)
- `POST /api/login` - Login and receive JWT + refresh token

### Chirps
- `POST /api/chirps` - Create a new chirp (requires JWT)
- `GET /api/chirps` - Get all chirps (supports `?author_id=uuid` and `?sort=asc|desc`)
- `GET /api/chirps/{chirpID}` - Get a single chirp
- `DELETE /api/chirps/{chirpID}` - Delete a chirp (requires JWT, must be owner)

### Authentication
- `POST /api/refresh` - Refresh JWT using refresh token
- `POST /api/revoke` - Revoke a refresh token

### Webhooks
- `POST /api/polka/webhooks` - Upgrade user to Chirpy Red (requires API key)

### Admin (dev only)
- `GET /admin/metrics` - View server metrics
- `POST /admin/reset` - Reset database (only in dev environment)

## License

MIT
